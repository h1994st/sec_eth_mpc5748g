/*
 * tlsClient.c
 *
 *  Created on: 2020/11/8
 *      Author: shengtuo
 */
#include "config.h"
#if ST_TLS_APP && (ST_TLS_TYPE == 0)

#include "utils.h"
#include "tlsTask.h"
#include "tlsClient.h"

#include "lwip/opt.h"
#include "lwip/sys.h"
#include "lwip/sockets.h"
#include "lwip/mem.h"

#if LWIP_SOCKET

#if LWIP_DHCP
#include "lwip/dhcp.h"
#endif /* LWIP_DHCP */
#if LWIP_AUTOIP || LWIP_DHCP_AUTOIP_COOP
#include "lwip/autoip.h"
#endif /* LWIP_AUTOIP || LWIP_DHCP_AUTOIP_COOP */

#if LWIP_DHCP
#if LWIP_DHCP_AUTOIP_COOP
#define HAVE_IP(n)      (dhcp_supplied_address(n) || autoip_supplied_address(n))
#else
#define HAVE_IP(n)      dhcp_supplied_address(n)
#endif /* LWIP_DHCP_AUTOIP_COOP */
#elif LWIP_AUTOIP
#define HAVE_IP(n)      autoip_supplied_address(n)
#else
#define HAVE_IP(n)      1
#endif /* LWIP_DHCP */

#include "ssl.h"

#include <string.h>

#include "osif.h"

#include <wolfssl/wolfcrypt/error-crypt.h>

#define MAX_SERV                 5         /* Maximum number of services. Don't need too many */

#define socket_client_thread_STACKSIZE configMINIMAL_STACK_SIZE

#define PORT   11111

#define BUFFER_SIZE 80
char buf[BUFFER_SIZE];

#define MSG_HI "Connecting ...\r\n"
#define MSG_TOSERVER "Hello, server!"

struct servercb {
	int socket;
	WOLFSSL* ssl;
	struct sockaddr_storage srvaddr;
	socklen_t srvlen;
};
static struct servercb srvcb;

/**************************************************************
 * void close_socket(struct servercb *p_servercb)
 *
 * Close the socket and free this servercb.
 **************************************************************/
static void close_socket() {
	/* Either an error or tcp connection closed on other
	 * end. Close here */
	wolfSSL_free(srvcb.ssl);
	close(srvcb.socket);
	memset(&srvcb, 0, sizeof(srvcb));
}

/* This is a helper function that blocks until the IP configuration is complete */
static inline void wait_for_ip(void) {
#if LWIP_IPV4
	while (!(HAVE_IP(netif_default))) {
		/* wait for dhcp / auto initialization to finish before using IP */
		sys_msleep(100);
	}
#endif /* LWIP_IPV4 */
}

/**************************************************************
 * void socket_client_thread(void *arg)
 *
 * secure socket task. This client will send user's input to a
 * server.
 **************************************************************/
static void socket_client_thread(void *arg) {
#if LWIP_IPV6
	struct sockaddr_in6 socket_saddr;
#else /* LWIP_IPV6 */
	struct sockaddr_in socket_saddr;
#endif /* LWIP_IPV6 */
	int ret;
	WOLFSSL_CTX* ctx;
	LWIP_UNUSED_ARG(arg);

	wait_for_ip();

	/* Initialize WOLFSSL */
	ret = wolfSSL_Init();
	LWIP_ASSERT("wolfSSL_Init() failed", ret == SSL_SUCCESS);

	/* Create and initialize CTX */
	WOLFSSL_METHOD* method_instance = wolfSSLv23_client_method();
	ctx = wolfSSL_CTX_new(method_instance);
	LWIP_ASSERT("wolfSSL_CTX_new() failed", ctx != NULL);

	/* Limit to AES128 - hardware-accelerated */
	wolfSSL_CTX_set_cipher_list(ctx, "AES128-SHA");
	// -- by h1994st: use CHACHA20-POLY1305 for TLS 1.3
//  ret = wolfSSL_CTX_set_cipher_list(ctx, "TLS13-CHACHA20-POLY1305-SHA256");
	// -- by h1994st: use CHACHA-POLY for TLS 1.2 & DTLS
//	ret = wolfSSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-CHACHA20-POLY1305");
	LWIP_ASSERT("wolfSSL_CTX_set_cipher_list() failed", ret == SSL_SUCCESS);

	// -- by h1994st: fewer packet
	ret = wolfSSL_CTX_set_group_messages(ctx);
	LWIP_ASSERT("wolfSSL_CTX_set_group_messages() failed", ret == SSL_SUCCESS);

	// -- by h1994st: set key size
#ifdef WOLFSSL_TLS13
#ifndef NO_DH
	ret = wolfSSL_CTX_SetMinDhKey_Sz(ctx, 1024);
	LWIP_ASSERT("wolfSSL_CTX_SetMinDhKey_Sz() failed", ret == SSL_SUCCESS);
#endif
#ifndef NO_RSA
	ret = wolfSSL_CTX_SetMinRsaKey_Sz(ctx, 1024);
	LWIP_ASSERT("wolfSSL_CTX_SetMinRsaKey_Sz() failed", ret == SSL_SUCCESS);
#endif
#ifdef HAVE_ECC
	ret = wolfSSL_CTX_SetMinEccKey_Sz(ctx, 256); // use 256 bits, instead of 224 bits (default)
	LWIP_ASSERT("wolfSSL_CTX_SetMinEccKey_Sz() failed", ret == SSL_SUCCESS);
#endif
#endif /* WOLFSSL_TLS13 */

	/* Load CA certificates */
	ret = wolfSSL_CTX_load_verify_buffer(ctx, CA_CERT, CA_CERT_SIZE,
			SSL_FILETYPE_ASN1);
	LWIP_ASSERT("wolfSSL_CTX_load_verify_locations() failed",
			ret == SSL_SUCCESS);

	/* Load client certificate */
	ret = wolfSSL_CTX_use_certificate_buffer(ctx, CLIENT_CERT, CLIENT_CERT_SIZE,
			SSL_FILETYPE_ASN1);
	LWIP_ASSERT("wolfSSL_CTX_use_certificate_buffer() failed",
			ret == SSL_SUCCESS);

	/* Load keys */
	ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, CLIENT_KEY, CLIENT_KEY_SIZE,
			SSL_FILETYPE_ASN1);
	LWIP_ASSERT("wolfSSL_CTX_use_PrivateKey_buffer() failed",
			ret == SSL_SUCCESS);

	while (1) {
		/* Connecting */
		vTaskDelay(1000); // wait 1 second
		printData(MSG_HI, strlen(MSG_HI));

		memset(&socket_saddr, 0, sizeof(socket_saddr));
		/* First acquire our socket for the connection */
		srvcb.socket = socket(AF_INET, SOCK_STREAM, 0);
		socket_saddr.sin_family = AF_INET;
		socket_saddr.sin_addr.s_addr = PP_HTONL(LWIP_MAKEU32(192, 168, 1, 200));
		socket_saddr.sin_port = lwip_htons(PORT); /* echo server port */
		LWIP_ASSERT("socket_client_thread(): Socket create failed.",
				srvcb.socket >= 0);

		/* Put socket into connecting mode */
		printString("Before connect(): ");
		printTimestamp();
		printString("\r\n");
		if (connect(srvcb.socket, (struct sockaddr * ) &socket_saddr,
				sizeof(socket_saddr)) == -1) {
//			LWIP_ASSERT("socket_client_thread(): Connect failed.", 0);
			printData("Connection failed\r\n", 19);
			close(srvcb.socket);
			continue;
		}
		printString("TCP connected: ");
		printTimestamp();
		printString("\r\n");
		srvcb.ssl = wolfSSL_new(ctx);
		LWIP_ASSERT("wolfSSL_new() failed.", srvcb.ssl != NULL);
		wolfSSL_set_fd(srvcb.ssl, srvcb.socket);

		int err;
		/* TLS connect */
		err = 0;
		printString("Before wolfSSL_connect(): ");
		printTimestamp();
		printString("\r\n");
		ret = wolfSSL_connect(srvcb.ssl);
		if (ret != SSL_SUCCESS) {
			printString("wolfSSL_connect failed\r\n");
			err = wolfSSL_get_error(srvcb.ssl, 0);
			close_socket();
			continue;
		}
		printString("TLS connected: ");
		printTimestamp();
		printString("\r\n");

		/* Send data */
		do {
			err = 0;
			printString("Before sending: ");
			printTimestamp();
			printString("\r\n");
			ret = wolfSSL_write(srvcb.ssl, MSG_TOSERVER, strlen(MSG_TOSERVER));
			if (ret <= 0) {
				err = wolfSSL_get_error(srvcb.ssl, 0);
			}
		} while (err == WC_PENDING_E);
		LWIP_ASSERT("wolfSSL_write() failed.", ret == strlen(MSG_TOSERVER));

		/* Wait for data from the server*/
		do {
			err = 0;
			ret = wolfSSL_read(srvcb.ssl, buf, BUFFER_SIZE - 1);
			if (ret <= 0) {
				err = wolfSSL_get_error(srvcb.ssl, 0);
			}
			printString("After reading: ");
			printTimestamp();
			printString("\r\n");
		} while (err == WC_PENDING_E || err == SSL_ERROR_WANT_READ);
		if (ret > 0) {
			printString("From server: ");
			printData(buf, ret);
			printData("\r\n", 2);
		}

		close_socket();
	}

	wolfSSL_CTX_free(ctx);
	wolfSSL_Cleanup();
}

void tlsClientInit(void) {
	sys_thread_t thread;
	thread = sys_thread_new("tls_client", socket_client_thread, 0, 6 * 1024,
	DEFAULT_THREAD_PRIO);
	LWIP_ASSERT("secure_socket_init() failed", thread != NULL);
}

#endif /* LWIP_SOCKET */

#endif /* ST_TLS_APP && (ST_TLS_TYPE == 0) */
