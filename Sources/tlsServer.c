/*
 * tlsServer.c
 *
 *  Created on: 2020/10/28
 *      Author: shengtuo
 */

#include "tlsServer.h"

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

#ifdef CERT_256  // -- by h1994st: use 256-bit ecc key
#define USE_CERT_BUFFERS_256
#include <certs_test.h>
#define CA_CERT				cliecc_cert_der_256
#define CA_CERT_SIZE		sizeof_cliecc_cert_der_256
#define SERVER_CERT			serv_ecc_der_256
#define SERVER_CERT_SIZE	sizeof_serv_ecc_der_256
#define CLIENT_CERT			cliecc_cert_der_256
#define CLIENT_CERT_SIZE	sizeof_cliecc_cert_der_256
#define SERVER_KEY			ecc_key_der_256
#define SERVER_KEY_SIZE		sizeof_ecc_key_der_256
#else /* CERT_256 */

#ifdef CERT_1024

#define USE_CERT_BUFFERS_1024
#include <certs_test.h>

#define CA_CERT				ca_cert_der_1024
#define CA_CERT_SIZE		sizeof_ca_cert_der_1024
#define SERVER_CERT			server_cert_der_1024
#define SERVER_CERT_SIZE	sizeof_server_cert_der_1024
#define CLIENT_CERT			client_cert_der_1024
#define CLIENT_CERT_SIZE	sizeof_client_cert_der_1024
#define SERVER_KEY			server_key_der_1024
#define SERVER_KEY_SIZE		sizeof_server_key_der_1024

#else /* CERT_1024 */

#define USE_CERT_BUFFERS_2048
#include <certs_test.h>

#define CA_CERT				ca_cert_der_2048
#define CA_CERT_SIZE		sizeof_ca_cert_der_2048
#define SERVER_CERT			server_cert_der_2048
#define SERVER_CERT_SIZE	sizeof_server_cert_der_2048
#define CLIENT_CERT			client_cert_der_2048
#define CLIENT_CERT_SIZE	sizeof_client_cert_der_2048
#define SERVER_KEY			server_key_der_2048
#define SERVER_KEY_SIZE		sizeof_server_key_der_2048

#endif /* CERT_1024 */

#endif /* CERT_256 */

#define MAX_SERV                 5         /* Maximum number of services. Don't need too many */

#define socket_server_thread_STACKSIZE configMINIMAL_STACK_SIZE

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/poly1305.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/ecc.h>   /* wc_ecc_fp_free */

#include <wolfssl/internal.h>

/* how many kB to test (en/de)cryption */
#define NUM_BLOCKS 4096
#define BLOCK_SIZE 1024
#define SPEED(start, end)   (int)(((end) - (start)) > 0.0 ? ((double)NUM_BLOCKS / ((end) - (start))) : 0)

// -- by h1994st
#define GEN_TIMES 10
#define OPS_PER_SEC(start, end)   (double)(((end) - (start)) > 0.0 ? ((double)GEN_TIMES / ((end) - (start))) : 0)

static XGEN_ALIGN byte bench_key[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
		0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x89, 0xab, 0xcd,
		0xef, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
		0xef };
static XGEN_ALIGN byte bench_iv[] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd,
		0xef, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x11, 0x21, 0x31,
		0x41, 0x51, 0x61, 0x71, 0x81 };

Aes* enc = NULL;
byte* bench_plain = NULL;
byte* bench_cipher = NULL;

double current_time(void);
char* bench_aescbc(word32 keySz);

char* bench_chacha20_poly1305_aead(void);
char* bench_aesccm(word32 keySz);
char* bench_aesgcm(word32 keySz);
char* bench_ecc_key_gen();
char* bench_ecdsa(word32 keySz);
char* bench_ecdhe();
char* bench_rsa();
char* bench_ecc_encrypt();

uint32_t current_time_ms(void);

static WC_RNG rng;

#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
#define AES_AUTH_ADD_SZ 13
#define AES_AUTH_TAG_SZ 16
#define BENCH_CIPHER_ADD AES_AUTH_TAG_SZ
#endif

char* bench_chacha20_poly1305_aead(void) {
	static char result[32] = "Enc:      KB/s Dec:      KB/s\n";
	char *p;
	double start_time, done_time;
	int i = 0;
	int ret = 0;
	byte authTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

	memset(authTag, 0, CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);

	memset(bench_plain, 0, BLOCK_SIZE);
	memset(bench_cipher, 0, BLOCK_SIZE);
	memset(enc, 0, sizeof(*enc));

//int wc_ChaCha20Poly1305_Encrypt(
//				const byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
//				const byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
//				const byte* inAAD, const word32 inAADLen,
//				const byte* inPlaintext, const word32 inPlaintextLen,
//				byte* outCiphertext,
//				byte outAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE]);
	start_time = current_time();
	for (i = 0; i < NUM_BLOCKS; i++) {
		ret = wc_ChaCha20Poly1305_Encrypt(bench_key, (byte*) bench_iv, NULL, 0,
				bench_plain, BLOCK_SIZE, bench_cipher, authTag);
		LWIP_ASSERT("wc_ChaCha20Poly1305_Encrypt() failed", ret == 0);
	}
	done_time = current_time();
	p = &result[4];
	lwip_itoa(p, 5, SPEED(start_time, done_time));
	while (*p)
		p++;
	while (!(*p))
		*(p++) = ' ';

//int wc_ChaCha20Poly1305_Decrypt(
//				const byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
//				const byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
//				const byte* inAAD, const word32 inAADLen,
//				const byte* inCiphertext, const word32 inCiphertextLen,
//				const byte inAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE],
//				byte* outPlaintext);
	start_time = current_time();
	for (i = 0; i < NUM_BLOCKS; i++) {
		ret = wc_ChaCha20Poly1305_Decrypt(bench_key, (byte*) bench_iv, NULL, 0,
				bench_cipher, BLOCK_SIZE, authTag, bench_plain);
		LWIP_ASSERT("wc_ChaCha20Poly1305_Decrypt() failed", ret == 0);
	}
	done_time = current_time();
	p = &result[19];
	lwip_itoa(p, 5, SPEED(start_time, done_time));
	while (*p)
		p++;
	while (!(*p))
		*(p++) = ' ';

	return result;
}

#if defined(HAVE_AESCCM)
char* bench_aesccm(word32 keySz) {
	static char result[32] = "Enc:      KB/s Dec:      KB/s\n";
	char *p;
	double start_time, done_time;
	int i = 0;
	int ret = 0;
	byte bench_tag[AES_AUTH_TAG_SZ];
	byte bench_additional[AES_AUTH_ADD_SZ];

	memset(bench_plain, 0, BLOCK_SIZE);
	memset(bench_cipher, 0, BLOCK_SIZE);
	memset(enc, 0, sizeof(*enc));

	/* init keys */
	ret = wc_AesInit(enc, NULL, INVALID_DEVID);
	LWIP_ASSERT("ws_AesInit() failed", ret == 0);
	ret = wc_AesCcmSetKey(enc, (byte*) bench_key, keySz);
	LWIP_ASSERT("wc_AesCcmSetKey() failed", ret == 0);

//int wc_AesCcmEncrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
//				   const byte* nonce, word32 nonceSz,
//				   byte* authTag, word32 authTagSz,
//				   const byte* authIn, word32 authInSz)
	start_time = current_time();
	for (i = 0; i < NUM_BLOCKS; i++) {
		ret = wc_AesCcmEncrypt(enc, bench_cipher, bench_plain, BLOCK_SIZE,
				bench_iv, 12, bench_tag, AES_AUTH_TAG_SZ, bench_additional,
				AES_AUTH_ADD_SZ);
		LWIP_ASSERT("wc_AesCcmEncrypt() failed", ret == 0);
	}
	done_time = current_time();
	p = &result[4];
	lwip_itoa(p, 5, SPEED(start_time, done_time));
	while (*p)
		p++;
	while (!(*p))
		*(p++) = ' ';

//int  wc_AesCcmDecrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
//				   const byte* nonce, word32 nonceSz,
//				   const byte* authTag, word32 authTagSz,
//				   const byte* authIn, word32 authInSz)
	start_time = current_time();
	for (i = 0; i < NUM_BLOCKS; i++) {
		ret = wc_AesCcmDecrypt(enc, bench_plain, bench_cipher, BLOCK_SIZE,
				bench_iv, 12, bench_tag, AES_AUTH_TAG_SZ, bench_additional,
				AES_AUTH_ADD_SZ);
		LWIP_ASSERT("wc_AesCcmDecrypt() failed", ret == 0);
	}
	done_time = current_time();
	p = &result[19];
	lwip_itoa(p, 5, SPEED(start_time, done_time));
	while (*p)
		p++;
	while (!(*p))
		*(p++) = ' ';

	wc_AesFree(enc);

	return result;
}
#endif

#if defined(HAVE_AESGCM)
char* bench_aesgcm(word32 keySz) {
	static char result[32] = "Enc:      KB/s Dec:      KB/s\n";
	char *p;
	double start_time, done_time;
	int i = 0;
	int ret = 0;
	byte bench_tag[AES_AUTH_TAG_SZ];
	byte bench_additional[AES_AUTH_ADD_SZ];

	memset(bench_plain, 0, BLOCK_SIZE);
	memset(bench_cipher, 0, BLOCK_SIZE);
	memset(enc, 0, sizeof(*enc));

	/* init keys */
	ret = wc_AesInit(enc, NULL, INVALID_DEVID);
	LWIP_ASSERT("ws_AesInit() failed", ret == 0);
	ret = wc_AesGcmSetKey(enc, (byte*) bench_key, keySz);
	LWIP_ASSERT("wc_AesGcmSetKey() failed", ret == 0);

//int wc_AesGcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
//				   const byte* iv, word32 ivSz,
//				   byte* authTag, word32 authTagSz,
//				   const byte* authIn, word32 authInSz)
	start_time = current_time();
	for (i = 0; i < NUM_BLOCKS; i++) {
		ret = wc_AesGcmEncrypt(enc, bench_cipher, bench_plain, BLOCK_SIZE,
				bench_iv, 12, bench_tag, AES_AUTH_TAG_SZ, bench_additional,
				AES_AUTH_ADD_SZ);
		LWIP_ASSERT("wc_AesGcmEncrypt() failed", ret == 0);
	}
	done_time = current_time();
	p = &result[4];
	lwip_itoa(p, 5, SPEED(start_time, done_time));
	while (*p)
		p++;
	while (!(*p))
		*(p++) = ' ';

//int  wc_AesGcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
//				   const byte* iv, word32 ivSz,
//				   const byte* authTag, word32 authTagSz,
//				   const byte* authIn, word32 authInSz)
	start_time = current_time();
	for (i = 0; i < NUM_BLOCKS; i++) {
		ret = wc_AesGcmDecrypt(enc, bench_plain, bench_cipher, BLOCK_SIZE,
				bench_iv, 12, bench_tag, AES_AUTH_TAG_SZ, bench_additional,
				AES_AUTH_ADD_SZ);
		LWIP_ASSERT("wc_AesGcmDecrypt() failed", ret == 0);
	}
	done_time = current_time();
	p = &result[19];
	lwip_itoa(p, 5, SPEED(start_time, done_time));
	while (*p)
		p++;
	while (!(*p))
		*(p++) = ' ';

	wc_AesFree(enc);

	return result;
}
#endif

#if defined(HAVE_AES_CBC)
char* bench_aescbc(word32 keySz) {
	static char result[32] = "Enc:      KB/s Dec:      KB/s\n";
	char *p;
	double start_time, done_time;
	int i = 0;
	int ret = 0;

	memset(bench_plain, 0, BLOCK_SIZE);
	memset(bench_cipher, 0, BLOCK_SIZE);
	memset(enc, 0, sizeof(*enc));

	/* init keys */
	ret = wc_AesInit(enc, NULL, INVALID_DEVID);
	LWIP_ASSERT("ws_AesInit() failed", ret == 0);
	ret = wc_AesSetKey(enc, (byte*) bench_key, keySz, (byte*) bench_iv,
			AES_ENCRYPTION);
	LWIP_ASSERT("ws_AesSetKey() failed", ret == 0);

	start_time = current_time();
	for (i = 0; i < NUM_BLOCKS; i++) {
		ret = wc_AesCbcEncrypt(enc, bench_cipher, bench_plain, BLOCK_SIZE);
		LWIP_ASSERT("ws_AesCbcEncrypt() failed", ret == 0);
	}
	done_time = current_time();
	p = &result[4];
	lwip_itoa(p, 5, SPEED(start_time, done_time));
	while (*p)
		p++;
	while (!(*p))
		*(p++) = ' ';

	/* init keys */
	ret = wc_AesSetKey(enc, (byte*) bench_key, keySz, (byte*) bench_iv,
			AES_DECRYPTION);
	LWIP_ASSERT("ws_AesSetKey() failed", ret == 0);
	start_time = current_time();
	for (i = 0; i < NUM_BLOCKS; i++) {
		ret = wc_AesCbcDecrypt(enc, bench_plain, bench_cipher, BLOCK_SIZE);
		LWIP_ASSERT("ws_AesCbcDecrypt() failed", ret == 0);
	}
	done_time = current_time();
	p = &result[19];
	lwip_itoa(p, 5, SPEED(start_time, done_time));
	while (*p)
		p++;
	while (!(*p))
		*(p++) = ' ';

	wc_AesFree(enc);

	return result;
}
#endif

char* bench_ecc_key_gen(word32 keySz) {
	static char result[45] = "ECC     bit Key Gen:          ms(   3 ops)\n";
	char* p;
	uint32_t start_time_ms, done_time_ms;
	int i = 0;
	int ret = 0;
	ecc_key key;

	memset(&key, 0, sizeof(ecc_key));

	p = &result[4];
	lwip_itoa(p, 4, keySz * 8);
	while (*p)
		p++;
	while (!(*p))
		*(p++) = ' ';

	start_time_ms = current_time_ms();
	for (i = 0; i < GEN_TIMES; ++i) {
		wc_ecc_free(&key);
		ret = wc_ecc_init(&key);
		LWIP_ASSERT("wc_ecc_init() failed", ret == 0);

		ret = wc_ecc_make_key(&rng, keySz, &key);
		LWIP_ASSERT("wc_ecc_make_key() failed", ret == 0);
	}
	done_time_ms = current_time_ms();
	p = &result[21];
	lwip_itoa(p, 9, (done_time_ms - start_time_ms));
	while (*p)
		p++;
	while (!(*p))
		*(p++) = ' ';

	return result;
}

char* bench_ecdsa(word32 keySz) {
	static char result[55] =
			"ECDSA     bit, sign:      ms, verify:      ms (3 ops)\n";
	char* p;
	uint32_t start_time_ms, done_time_ms;
	int i = 0;
	int ret = 0;
	ecc_key key;

	word32 x;
	byte *digest = bench_plain; // size: keySz
	byte *sig = bench_cipher; // size: keySz
	int verify;

	memset(&key, 0, sizeof(ecc_key));
	memset(bench_plain, 0, BLOCK_SIZE);
	memset(bench_cipher, 0, BLOCK_SIZE);

	p = &result[6];
	lwip_itoa(p, 4, keySz * 8);
	while (*p)
		p++;
	while (!(*p))
		*(p++) = ' ';

	// initialize the key
	wc_ecc_free(&key);
	ret = wc_ecc_init(&key);
	LWIP_ASSERT("wc_ecc_init() failed", ret == 0);

	ret = wc_ecc_make_key(&rng, keySz, &key);
	LWIP_ASSERT("wc_ecc_make_key() failed", ret == 0);

//	int wc_ecc_sign_hash(const byte* in, word32 inlen, byte* out, word32 *outlen,
//	                     WC_RNG* rng, ecc_key* key)
	start_time_ms = current_time_ms();
	for (i = 0; i < GEN_TIMES; ++i) {
		x = ECC_MAX_SIG_SIZE;
		key.state = 0;
		ret = wc_ecc_sign_hash(digest, keySz, sig, &x, &rng, &key);
		LWIP_ASSERT("wc_ecc_sign_hash() failed", ret == MP_OKAY);
	}
	done_time_ms = current_time_ms();
	p = &result[21];
	lwip_itoa(p, 5, (done_time_ms - start_time_ms));
	while (*p)
		p++;
	while (!(*p))
		*(p++) = ' ';

//	int wc_ecc_verify_hash(const byte* sig, word32 siglen, const byte* hash,
//	                       word32 hashlen, int* res, ecc_key* key)
	start_time_ms = current_time_ms();
	for (i = 0; i < GEN_TIMES; ++i) {
		key.state = 0;
		ret = wc_ecc_verify_hash(sig, x, digest, keySz, &verify, &key);
		LWIP_ASSERT("wc_ecc_verify_hash() failed",
				ret == MP_OKAY && verify == 1);
	}
	done_time_ms = current_time_ms();
	p = &result[38];
	lwip_itoa(p, 5, (done_time_ms - start_time_ms));
	while (*p)
		p++;
	while (!(*p))
		*(p++) = ' ';

	return result;
}

char* bench_ecdhe() {
	return "";
}

char* bench_rsa() {
	return "";
}

char* bench_ecc_encrypt() {
	return "";
}

double current_time(void) {
	uint32_t msecs = OSIF_GetMilliseconds();
	return (double) msecs / (double) 1000;
}

uint32_t current_time_ms(void) {
	return OSIF_GetMilliseconds();
}

#define PORT   11111

char buf[80];

struct clientcb {
	struct clientcb *next;
	int socket;
	WOLFSSL* ssl;
	struct sockaddr_storage cliaddr;
	socklen_t clilen;
};

static struct clientcb *clientcb_list = 0;

/**************************************************************
 * void close_socket(struct clientcb *p_clientcb)
 *
 * Close the socket and remove this clientcb from the list.
 **************************************************************/
static void close_socket(struct clientcb *p_clientcb) {
	struct clientcb *p_search_clientcb;

	/* Either an error or tcp connection closed on other
	 * end. Close here */
	wolfSSL_free(p_clientcb->ssl);
	close(p_clientcb->socket);
	/* Free clientcb */
	if (clientcb_list == p_clientcb) {
		clientcb_list = p_clientcb->next;
	} else {
		for (p_search_clientcb = clientcb_list; p_search_clientcb;
				p_search_clientcb = p_search_clientcb->next) {
			if (p_search_clientcb->next == p_clientcb) {
				p_search_clientcb->next = p_clientcb->next;
				break;
			}
		}
	}
	mem_free(p_clientcb);
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
 * void sock_server_thread(void *arg)
 *
 * secure socket task. This server will wait for connections on
 * TCP port number: PORT. For every connection, the server will
 *echo back any message received.
 **************************************************************/
static void socket_server_thread(void *arg) {
	int listenfd;
#if LWIP_IPV6
	struct sockaddr_in6 socket_saddr;
#else /* LWIP_IPV6 */
	struct sockaddr_in socket_saddr;
#endif /* LWIP_IPV6 */
	fd_set readset;
	int i, maxfdp1;
	int ret;
	WOLFSSL_CTX* ctx;
	struct clientcb *p_clientcb;
	LWIP_UNUSED_ARG(arg);

	wait_for_ip();

	/* Initialize WOLFSSL */
	ret = wolfSSL_Init();
	LWIP_ASSERT("wolfSSL_Init() failed", ret == SSL_SUCCESS);

	memset(&socket_saddr, 0, sizeof(socket_saddr));
#if LWIP_IPV6
	/* First acquire our socket for listening for connections */
	listenfd = socket(AF_INET6, SOCK_STREAM, 0);
	socket_saddr.sin6_family = AF_INET6;
	socket_saddr.sin6_addr = in6addr_any;
	socket_saddr.sin6_port = lwip_htons(PORT); /* echo server port */
#else /* LWIP_IPV6 */
	/* First acquire our socket for listening for connections */
	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	socket_saddr.sin_family = AF_INET;
	socket_saddr.sin_addr.s_addr = PP_HTONL(INADDR_ANY);
	socket_saddr.sin_port = lwip_htons(PORT); /* echo server port */
#endif /* LWIP_IPV6 */

	LWIP_ASSERT("socket_server_thread(): Socket create failed.", listenfd >= 0);

	/* Create and initialize CTX */
	WOLFSSL_METHOD* method_instance = wolfSSLv23_server_method();
	// -- by h1994st: TLS 1.3 methods
//  WOLFSSL_METHOD* method_instance = wolfTLSv1_3_server_method_ex(NULL);
//  method_instance->downgrade = 1;
	// -- by h1994st: TLS 1.2 methods
//	WOLFSSL_METHOD* method_instance = wolfTLSv1_2_server_method_ex(NULL);
	ctx = wolfSSL_CTX_new(method_instance);
	LWIP_ASSERT("wolfSSL_CTX_new() failed", ctx != NULL);

	/* Limit to AES128 - hardware-accelerated */
//	wolfSSL_CTX_set_cipher_list(ctx, "AES128-SHA");
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

	/* Load server certificate */
	ret = wolfSSL_CTX_use_certificate_buffer(ctx, SERVER_CERT, SERVER_CERT_SIZE,
			SSL_FILETYPE_ASN1);
	LWIP_ASSERT("wolfSSL_CTX_use_certificate_buffer() failed",
			ret == SSL_SUCCESS);

	/* Load keys */
	ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, SERVER_KEY, SERVER_KEY_SIZE,
			SSL_FILETYPE_ASN1);
	LWIP_ASSERT("wolfSSL_CTX_use_PrivateKey_buffer() failed",
			ret == SSL_SUCCESS);

	// -- by h1994st: set client verification
//	wolfSSL_CTX_set_verify(ctx,
//			SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

	if (bind(listenfd, (struct sockaddr * ) &socket_saddr, sizeof(socket_saddr))
			== -1) {
		LWIP_ASSERT("socket_server_thread(): Socket bind failed.", 0);
	}

	/* Put socket into listening mode */
	if (listen(listenfd, MAX_SERV) == -1) {
		LWIP_ASSERT("socket_server_thread(): Listen failed.", 0);
	}

	enc = (Aes*) mem_malloc(sizeof(Aes));
	bench_plain = (byte*) mem_malloc(BLOCK_SIZE);
	bench_cipher = (byte*) mem_malloc(BLOCK_SIZE);

	// -- by h1994st: initialize RNG
	ret = wc_InitRng(&rng);
	LWIP_ASSERT("wc_InitRng() failed", ret == 0);

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
				if (!strncmp(buf, "benchmark_chacha_poly", 21)) {
					strncpy(buf, bench_chacha20_poly1305_aead(), 40);
#if defined(HAVE_AESGCM)
				} else if (!strncmp(buf, "benchmark_aesgcm_128", 20)) {
					strncpy(buf, bench_aesgcm(128 / 8), 40);
				} else if (!strncmp(buf, "benchmark_aesgcm_192", 20)) {
					strncpy(buf, bench_aesgcm(192 / 8), 40);
				} else if (!strncmp(buf, "benchmark_aesgcm_256", 20)) {
					strncpy(buf, bench_aesgcm(256 / 8), 40);
#endif
#if defined(HAVE_AESCCM)
				} else if (!strncmp(buf, "benchmark_aesccm_128", 20)) {
					strncpy(buf, bench_aesccm(128 / 8), 40);
				} else if (!strncmp(buf, "benchmark_aesccm_192", 20)) {
					strncpy(buf, bench_aesccm(192 / 8), 40);
				} else if (!strncmp(buf, "benchmark_aesccm_256", 20)) {
					strncpy(buf, bench_aesccm(256 / 8), 40);
#endif
#if defined(HAVE_AES_CBC)
				} else if (!strncmp(buf, "benchmark_aescbc_128", 20)) {
					strncpy(buf, bench_aescbc(128 / 8), 40);
				} else if (!strncmp(buf, "benchmark_aescbc_192", 20)) {
					strncpy(buf, bench_aescbc(192 / 8), 40);
				} else if (!strncmp(buf, "benchmark_aescbc_256", 20)) {
					strncpy(buf, bench_aescbc(256 / 8), 40);
#endif
				} else if (!strncmp(buf, "benchmark_ecc_key_gen_256", 25)) {
					strncpy(buf, bench_ecc_key_gen(256 / 8), 45);
				} else if (!strncmp(buf, "benchmark_ecdsa_256", 19)) { // sign, verify
					strncpy(buf, bench_ecdsa(256 / 8), 55);
				} else if (!strncmp(buf, "benchmark_ecdhe", 15)) { // agree
					bench_ecdhe();
				} else if (!strncmp(buf, "benchmark_rsa", 13)) { // sign, verify
					bench_rsa();
				} else if (!strncmp(buf, "benchmark_ecc_encrypt", 21)) { // encrypt, decrypt
					bench_ecc_encrypt();
				}
				if (wolfSSL_write(p_clientcb->ssl, buf, strlen(buf)) < 0) {
					close_socket(p_clientcb);
					break;
				}
			}
		}
	}
	mem_free(bench_plain);
	mem_free(bench_cipher);
	mem_free(enc);

	wolfSSL_CTX_free(ctx);
	wolfSSL_Cleanup();
	close(listenfd);
}

void tlsInit(void) {
	sys_thread_t thread;
	thread = sys_thread_new("tls", socket_server_thread, 0, 6 * 1024,
	DEFAULT_THREAD_PRIO);
	LWIP_ASSERT("secure_socket_init() failed", thread != NULL);
}

#endif
