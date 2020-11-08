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

#define MAX_SERV                 5         /* Maximum number of services. Don't need too many */

#define socket_client_thread_STACKSIZE configMINIMAL_STACK_SIZE

#define PORT   11111

char buf[80];

struct servercb {
	int socket;
	WOLFSSL* ssl;
	struct sockaddr_storage srvaddr;
	socklen_t srvlen;
};

/**************************************************************
 * void close_socket(struct servercb *p_servercb)
 *
 * Close the socket and free this servercb.
 **************************************************************/
static void close_socket(struct servercb *p_servercb) {
	/* Either an error or tcp connection closed on other
	 * end. Close here */
	wolfSSL_free(p_servercb->ssl);
	close(p_servercb->socket);
	mem_free(p_servercb);
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
	int connectfd;
#if LWIP_IPV6
	struct sockaddr_in6 socket_saddr;
#else /* LWIP_IPV6 */
	struct sockaddr_in socket_saddr;
#endif /* LWIP_IPV6 */
	fd_set readset;
	int i, maxfdp1;
	int ret;
	WOLFSSL_CTX* ctx;
	struct servercb *p_servercb;
	LWIP_UNUSED_ARG(arg);

	wait_for_ip();

	/* Initialize WOLFSSL */
	ret = wolfSSL_Init();
	LWIP_ASSERT("wolfSSL_Init() failed", ret == SSL_SUCCESS);

	memset(&socket_saddr, 0, sizeof(socket_saddr));
#if LWIP_IPV6
	/* First acquire our socket for the connection */
	connectfd = socket(AF_INET6, SOCK_STREAM, 0);
	socket_saddr.sin6_family = AF_INET6;
	socket_saddr.sin6_addr = in6addr_any;
	socket_saddr.sin6_port = lwip_htons(PORT); /* echo server port */
#else /* LWIP_IPV6 */
	/* First acquire our socket for the connection */
	connectfd = socket(AF_INET, SOCK_STREAM, 0);
	socket_saddr.sin_family = AF_INET;
	socket_saddr.sin_addr.s_addr = PP_HTONL(INADDR_ANY);
	socket_saddr.sin_port = lwip_htons(PORT); /* echo server port */
#endif /* LWIP_IPV6 */

	LWIP_ASSERT("socket_client_thread(): Socket create failed.", listenfd >= 0);

	/* Create and initialize CTX */
	WOLFSSL_METHOD* method_instance = wolfSSLv23_server_method();
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
	ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, SERVER_KEY, SERVER_KEY_SIZE,
			SSL_FILETYPE_ASN1);
	LWIP_ASSERT("wolfSSL_CTX_use_PrivateKey_buffer() failed",
			ret == SSL_SUCCESS);

	if (bind(listenfd, (struct sockaddr * ) &socket_saddr, sizeof(socket_saddr))
			== -1) {
		LWIP_ASSERT("socket_client_thread(): Socket bind failed.", 0);
	}

	/* Put socket into listening mode */
	if (listen(listenfd, MAX_SERV) == -1) {
		LWIP_ASSERT("socket_client_thread(): Listen failed.", 0);
	}

	/* Wait forever for network input: This could be connections or data */
	for (;;) {
		maxfdp1 = listenfd + 1;

		/* Determine what sockets need to be in readset */
		FD_ZERO(&readset);
		FD_SET(listenfd, &readset);
		for (p_clientcb = clientcb_list; p_clientcb;
				p_clientcb = p_clientcb->next) {
			if (maxfdp1 < p_clientcb->socket + 1) {
				maxfdp1 = p_clientcb->socket + 1;
			}
			FD_SET(p_clientcb->socket, &readset);
		}

		/* Wait for data or a new connection */
		i = select(maxfdp1, &readset, 0, 0, 0);

		if (i == 0) {
			continue;
		}
		/* At least one descriptor is ready */
		if (FD_ISSET(listenfd, &readset)) {
			/* We have a new connection request!!! */
			/* Lets create a new control block */
			p_clientcb = (struct clientcb *) mem_malloc(
					sizeof(struct clientcb));
			if (p_clientcb) {
				p_clientcb->socket = accept(listenfd,
						(struct sockaddr * ) &p_clientcb->cliaddr,
						&p_clientcb->clilen);
				if (p_clientcb->socket < 0) {
					mem_free(p_clientcb);
				} else {
					/* Keep this tecb in our list */
					p_clientcb->ssl = wolfSSL_new(ctx);
					LWIP_ASSERT("wolfSSL_new() failed.",
							p_clientcb->ssl != NULL);
					wolfSSL_set_fd(p_clientcb->ssl, p_clientcb->socket);
					p_clientcb->next = clientcb_list;
					clientcb_list = p_clientcb;
				}
			} else {
				/* No memory to accept connection. Just accept and then close */
				int sock;
				struct sockaddr cliaddr;
				socklen_t clilen;

				sock = accept(listenfd, &cliaddr, &clilen);
				if (sock >= 0) {
					close(sock);
				}
			}
		}
		/* Go through list of connected clients and process data */
		for (p_clientcb = clientcb_list; p_clientcb;
				p_clientcb = p_clientcb->next) {
			if (FD_ISSET(p_clientcb->socket, &readset)) {
				/* This socket is ready for reading. This could be because someone typed
				 * some characters or it could be because the socket is now closed. Try reading
				 * some data to see. */
				int readcount;
				readcount = wolfSSL_read(p_clientcb->ssl, &buf,
						sizeof(buf) - 1);
				if (readcount <= 0) {
					close_socket(p_clientcb);
					break;
				}
				buf[readcount] = 0;
				if (wolfSSL_write(p_clientcb->ssl, buf, strlen(buf)) < 0) {
					close_socket(p_clientcb);
					break;
				}
			}
		}
	}

	wolfSSL_CTX_free(ctx);
	wolfSSL_Cleanup();
	close(listenfd);
}

void tlsClientInit(void) {
	sys_thread_t thread;
	thread = sys_thread_new("tls_client", socket_client_thread, 0, 6 * 1024,
	DEFAULT_THREAD_PRIO);
	LWIP_ASSERT("secure_socket_init() failed", thread != NULL);
}

#endif /* LWIP_SOCKET */

#endif /* ST_TLS_APP && (ST_TLS_TYPE == 0) */
