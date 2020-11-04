/*
 * tlsTask.c
 *
 *  Created on: 2020/11/4
 *      Author: shengtuo
 */

#include "tlsTask.h"
#include "config.h"

#if ST_TLS_APP

#include "Cpu.h"

#if defined(USING_OS_FREERTOS)
/* FreeRTOS kernel includes. */
#include "FreeRTOS.h"
#include "task.h"
#endif /* defined(USING_OS_FREERTOS) */

#include "osif.h"

/* lwIP core includes */
#include "lwip/opt.h"

#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/init.h"
#include "lwip/tcpip.h"
#include "lwip/netif.h"
#include "lwip/api.h"
#include "lwip/arch.h"

#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/dns.h"
#include "lwip/dhcp.h"
#include "lwip/autoip.h"

/* lwIP netif includes */
#include "lwip/etharp.h"
#include "netif/ethernet.h"
#include "netifcfg.h"

/* include the port-dependent configuration */
#include "lwipcfg.h"

#ifndef LWIP_INIT_COMPLETE_CALLBACK
#define LWIP_INIT_COMPLETE_CALLBACK 0
#endif /* LWIP_INIT_COMPLETE_CALLBACK */

/* network interfaces global variables */
struct netif networkInterfaces[ETHIF_NUMBER];

#include "tlsServer.h"

/* This function initializes all network interfaces
 * Implements enetif_init_Activity
 */
static void interface_init(void) {
	for (int i = 0; i < ETHIF_NUMBER; i++) {
#if LWIP_IPV4
		ip4_addr_t ipaddr, netmask, gw;
#endif /* LWIP_IPV4 */
#if LWIP_DHCP || LWIP_AUTOIP
		err_t err;
#endif /* LWIP_AUTOIP || LWIP_DHCP */

#if LWIP_IPV4
		ip4_addr_set_zero(&gw);
		ip4_addr_set_zero(&ipaddr);
		ip4_addr_set_zero(&netmask);
		/* networkInterfaces[i] takes the IPV4 addresses from the respective configuration */
		if ((!netif_cfg[i]->has_dhcp) && (!netif_cfg[i]->has_auto_ip)) {
			IP4_ADDR((&gw), netif_cfg[i]->gw[0], netif_cfg[i]->gw[1],
					netif_cfg[i]->gw[2], netif_cfg[i]->gw[3]);
			IP4_ADDR((&ipaddr), netif_cfg[i]->ip_addr[0],
					netif_cfg[i]->ip_addr[1], netif_cfg[i]->ip_addr[2],
					netif_cfg[i]->ip_addr[3]);
			IP4_ADDR((&netmask), netif_cfg[i]->netmask[0],
					netif_cfg[i]->netmask[1], netif_cfg[i]->netmask[2],
					netif_cfg[i]->netmask[3]);
		}
#endif /* LWIP_IPV4 */

#if NO_SYS
		netif_set_default(netif_add(&networkInterfaces[i], &ipaddr, &netmask, &gw, NULL, ETHIF_INIT, netif_input));
#else /* NO_SYS */
		netif_set_default(
				netif_add(&networkInterfaces[i], &ipaddr, &netmask, &gw, NULL,
				ETHIF_INIT, tcpip_input));
#endif /* NO_SYS */

#if LWIP_IPV6
		if (netif_cfg[i]->has_IPv6) {
			netif_create_ip6_linklocal_address(&networkInterfaces[i], 1);

#if PRINTF_SUPPORT
			printf("ip6 linklocal address: ");
#endif
			ip6_addr_debug_print(0xFFFFFFFFU & ~LWIP_DBG_HALT, netif_ip6_addr(&networkInterfaces[i], 0));
		}
#endif /* LWIP_IPV6 */

#if LWIP_NETIF_STATUS_CALLBACK
		netif_set_status_callback(&networkInterfaces[i], status_callback);
#endif /* LWIP_NETIF_STATUS_CALLBACK */

#if LWIP_NETIF_LINK_CALLBACK
		netif_set_link_callback(&networkInterfaces[i], link_callback);
#endif /* LWIP_NETIF_LINK_CALLBACK */

#if LWIP_AUTOIP
		if (netif_cfg[i]->has_auto_ip)
		{
			autoip_set_struct(&networkInterfaces[i], &netif_autoip);
		}
#endif /* LWIP_AUTOIP */

#if LWIP_DHCP
		if (netif_cfg[i]->has_dhcp)
		{
			dhcp_set_struct(&networkInterfaces[i], &netif_dhcp);
		}
#endif /* LWIP_DHCP */
		netif_set_up(&networkInterfaces[i]);
#if LWIP_DHCP
		if (netif_cfg[i]->has_dhcp)
		{
			err = dhcp_start((struct netif *)&networkInterfaces[i]);
			LWIP_ASSERT("dhcp_start failed", err == (err_t)ERR_OK);
		}
#endif /* LWIP_DHCP */

#if LWIP_AUTOIP
		else if (netif_cfg[i]->has_auto_ip)
		{
			err = autoip_start(&networkInterfaces[i]);
			LWIP_ASSERT("autoip_start failed", err == (err_t)ERR_OK);
		}
#endif /* LWIP_AUTOIP */
	}
}

/* This function initializes this lwIP test. When NO_SYS=1, this is done in
 * the main_loop context (there is no other one), when NO_SYS=0, this is done
 * in the tcpip_thread context */
static void appInit(void* arg) {
	sys_sem_t* init_sem = (sys_sem_t*) arg;
	LWIP_ASSERT("init_sem != NULL", init_sem != NULL);

	/* init network interfaces */
	interface_init();

	/* init apps */
	tlsInit();

	sys_sem_signal(init_sem);
}

/* main loop */
void tlsMainLoopTask(void* pvParameters) {
	(void) pvParameters;

	/* initialize lwIP stack and network interfaces -- by h1994st */
	err_t err;
	sys_sem_t initSem;

	err = sys_sem_new(&initSem, 0);
	LWIP_ASSERT("failed to create init_sem", err == (err_t )ERR_OK);
	LWIP_UNUSED_ARG(err);
	tcpip_init(appInit, (void*) &initSem);
	/* we have to wait for initialization to finish before
	 * calling update_adapter()! */
	(void) sys_sem_wait(&initSem);
	sys_sem_free(&initSem);
#if (LWIP_SOCKET || LWIP_NETCONN) && LWIP_NETCONN_SEM_PER_THREAD
	netconn_thread_init();
#endif

	/* MAIN LOOP for driver update (and timers if NO_SYS) */
	while (1) {
		sys_msleep(5000);
	}

#if (LWIP_SOCKET || LWIP_NETCONN) && LWIP_NETCONN_SEM_PER_THREAD
	netconn_thread_cleanup();
#endif
	/* release the network interfaces... */
	for (int i = 0; i < ETHIF_NUMBER; i++) {
		ETHIF_SHUTDOWN(&networkInterfaces[i]);
	}
}

#endif /* ST_TLS_APP */
