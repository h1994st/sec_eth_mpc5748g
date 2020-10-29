/*
 * Copyright 2016-2019 NXP
 * All rights reserved.
 *
 * THIS SOFTWARE IS PROVIDED BY NXP "AS IS" AND ANY EXPRESSED OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL NXP OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

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

#include "tlsServer.h"

#ifndef LWIP_INIT_COMPLETE_CALLBACK
#define LWIP_INIT_COMPLETE_CALLBACK 0
#endif /* LWIP_INIT_COMPLETE_CALLBACK */

/* network interfaces global variables */
struct netif networkInterfaces[ETHIF_NUMBER];

volatile int exit_code = 0;

/* custom random seed function -- by h1994st */
int customRandSeed(uint8_t* output, uint32_t sz) {
	uint32_t i;
	srand(OSIF_GetMilliseconds());
	for (i = 0; i < sz; i++) {
		output[i] = rand() % 256;
	}
	return 0;
}

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
static void mainLoopTask(void* pvParameters) {
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

int main(void) {

	/*** Processor Expert internal initialization. DON'T REMOVE THIS CODE!!! ***/
#ifdef PEX_RTOS_INIT
	PEX_RTOS_INIT(); /* Initialization of the selected RTOS. Macro is defined by the RTOS component. */
#endif
	/*** End of Processor Expert internal initialization.                    ***/

	/* Write your code here */
	status_t ret = STATUS_ERROR;

	/* Initialize and configure clocks */
	ret = CLOCK_SYS_Init(g_clockManConfigsArr,
			(uint8_t) CLOCK_MANAGER_CONFIG_CNT, g_clockManCallbacksArr,
			(uint8_t) CLOCK_MANAGER_CALLBACK_CNT);
	DEV_ASSERT(STATUS_SUCCESS == ret);
	ret = CLOCK_SYS_UpdateConfiguration(0U, CLOCK_MANAGER_POLICY_AGREEMENT);
	DEV_ASSERT(STATUS_SUCCESS == ret);

	/* Initialize pins */
	ret = PINS_DRV_Init(NUM_OF_CONFIGURED_PINS, g_pin_mux_InitConfigArr);
	DEV_ASSERT(STATUS_SUCCESS == ret);

	/* Initialize FreeRTOS */
	BaseType_t taskRet = xTaskCreate(mainLoopTask, "mainloop", 256U, NULL, 1,
	NULL);
	/* Start the tasks and timer running. */
	DEV_ASSERT(taskRet == pdPASS);
	vTaskStartScheduler();

	/* If all is well, the scheduler will now be running, and the following
	 line will never be reached.  If the following line does execute, then
	 there was insufficient FreeRTOS heap memory available for the idle and/or
	 timer tasks to be created.  See the memory management section on the
	 FreeRTOS web site for more details. */
	for (;;) {
	}

	/*** Don't write any code pass this line, or it will be deleted during code generation. ***/
	/*** RTOS startup code. Macro PEX_RTOS_START is defined by the RTOS component. DON'T MODIFY THIS CODE!!! ***/
#ifdef PEX_RTOS_START
	PEX_RTOS_START(); /* Startup of the selected RTOS. Macro is defined by the RTOS component. */
#endif
	/*** End of RTOS startup code.  ***/
	/*** Processor Expert end of main routine. DON'T MODIFY THIS CODE!!! ***/
	for (;;) {
		if (exit_code != 0) {
			break;
		}
	}
	return exit_code;
	/*** Processor Expert end of main routine. DON'T WRITE CODE BELOW!!! ***/
} /*** End of main routine. DO NOT MODIFY THIS TEXT!!! ***/

/* END main */
/*!
 ** @}
 */
/*
 ** ###################################################################
 **
 **     This file was created by Processor Expert 10.1 [05.21]
 **     for the NXP C55 series of microcontrollers.
 **
 ** ###################################################################
 */
