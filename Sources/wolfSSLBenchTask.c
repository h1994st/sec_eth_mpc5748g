/*
 * wolfSSLBenchTask.c
 *
 *  Created on: 2020/11/4
 *      Author: shengtuo
 */

#include "wolfSSLBenchTask.h"
#include "utils.h"

#if ST_BENCH_WOLFSSL

#include "Cpu.h"

#if defined(USING_OS_FREERTOS)
/* FreeRTOS kernel includes. */
#include "FreeRTOS.h"
#include "task.h"
#endif /* defined(USING_OS_FREERTOS) */

#include "lwip/opt.h"
#include "lwip/sys.h"
#include "lwip/sockets.h"
#include "lwip/mem.h"

#include <string.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>

/* FreeRTOS defines: */
#define TASK_DELAY         ((TickType_t)100 / portTICK_PERIOD_MS)
#define TASK0_PRIORITY      (tskIDLE_PRIORITY + 1)
#define MESSAGE_LENGTH      16

#define BLOCK_SIZE          1024
#define NUM_BLOCKS          4096
#define SPEED(start, end)   (int)(((end) - (start)) > 0.0 ? ((double)NUM_BLOCKS / ((end) - (start))) : 0)
#define AES_AUTH_ADD_SZ     13
#define AES_AUTH_TAG_SZ     16
#define BENCH_CIPHER_ADD    AES_AUTH_TAG_SZ
#define SHA256_SIZE         32

/* Application defines: */
#define TIMEOUT_ENCRYPTION    (1000U)
#define PLAINTEXT    "AccessCode:01234"
#define MSG_HELLO    "hello \r\n"

/* Enums: */
typedef enum{
    TASK_NONE = 0,
#ifdef HAVE_AES_CBC
    ENCRYPT_CBC,
#endif
#ifdef HAVE_AESCCM
    ENCRYPT_CCM,
#endif
#ifdef HAVE_AESGCM
    ENCRYPT_GCM,
#endif
    HASH_SHA256,
    HASH_HMAC256,
    RSA_ENCRYPT,
    RSA_VERIFY,
} TaskType_e;

/* Structures: */
typedef struct{
    uint8_t ucInitVector[MESSAGE_LENGTH];
    uint8_t ucEncMsg[MESSAGE_LENGTH];
} Data_t;

/* Global variables: */

/* Functions: */

/* Benchmark Tasks */
static Aes* enc = NULL;
static uint8_t ucMsg[BLOCK_SIZE] = { 0 };
static uint8_t ucEncMsg[BLOCK_SIZE] = { 0 };
static uint8_t ucDecMsg[BLOCK_SIZE] = { 0 };
static uint32_t start_time, done_time;
static uint8_t ucInitVector[MESSAGE_LENGTH] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static uint8_t ucTag[AES_AUTH_TAG_SZ] = { 0 };
static uint8_t ucAdd[AES_AUTH_TAG_SZ] = { 0 };
static const uint8_t ucPlainKey[MESSAGE_LENGTH] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
};
static uint8_t ucHash[SHA256_SIZE] = { 0 };
static Sha256 wcHash;
static Hmac wcHmac;
static char result[38] = "Enc:           ms Dec:           ms\r\n";
static char result2[] = "Duration:           ms\r\n";
static char *p = NULL;

static void benchNone()
{
	// Print hello message
	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1,
			(uint8_t *)MSG_HELLO, strlen(MSG_HELLO), TIMEOUT_ENCRYPTION);
}

#ifdef HAVE_AES_CBC
static void benchAesCbc()
{
	int i;
	int ret = 0;

	memset(ucMsg, 0, BLOCK_SIZE);
	memset(ucEncMsg, 0, BLOCK_SIZE);
	memset(ucDecMsg, 0, BLOCK_SIZE);
	memset(enc, 0, sizeof(Aes));
	ret = wc_AesInit(enc, NULL, INVALID_DEVID);
	LWIP_ASSERT("ws_AesInit() failed", ret == 0);

	/* init keys */
	ret = wc_AesSetKey(enc, (byte*) ucPlainKey, sizeof(ucPlainKey),
			(byte*) ucInitVector, AES_ENCRYPTION);
	LWIP_ASSERT("ws_AesSetKey() failed", ret == 0);

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1,
			(uint8_t *)"AES-CBC:\r\n", 10, TIMEOUT_ENCRYPTION);

	// Encrypt
	start_time = current_time_ms();
	for (i = 0; i < NUM_BLOCKS; ++i)
	{
		ret = wc_AesCbcEncrypt(enc, ucEncMsg, ucMsg, BLOCK_SIZE);
		LWIP_ASSERT("ws_AesCbcEncrypt() failed", ret == 0);
	}
	done_time = current_time_ms();
	p = &result[4];
	memset(p, ' ', 10);
	custom_itoa(p, 5, (done_time - start_time));
	while (*p) p++;
	while (!(*p)) *(p++) = ' ';

	/* init keys */
	ret = wc_AesSetKey(enc, (byte*) ucPlainKey, sizeof(ucPlainKey),
			(byte*) ucInitVector, AES_ENCRYPTION);
	LWIP_ASSERT("ws_AesSetKey() failed", ret == 0);

	// Decrypt
	start_time = current_time_ms();
	for (i = 0; i < NUM_BLOCKS; ++i)
	{
		ret = wc_AesCbcDecrypt(enc, ucDecMsg, ucEncMsg, BLOCK_SIZE);
		LWIP_ASSERT("ws_AesCbcDecrypt() failed", ret == 0);
//		DEV_ASSERT(bufferCompare(ucDecMsg, ucMsg, BLOCK_SIZE));
	}
	done_time = current_time_ms();
	p = &result[22];
	memset(p, ' ', 10);
	custom_itoa(p, 5, (done_time - start_time));
	while (*p) p++;
	while (!(*p)) *(p++) = ' ';

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1,
			(uint8_t *)result, strlen(result), TIMEOUT_ENCRYPTION);

	wc_AesFree(enc);
}
#endif

#ifdef HAVE_AESCCM
static void benchAesCcm()
{
	int i;
	int ret = 0;

	memset(ucMsg, 0, BLOCK_SIZE);
	memset(ucEncMsg, 0, BLOCK_SIZE);
	memset(ucDecMsg, 0, BLOCK_SIZE);
	memset(enc, 0, sizeof(Aes));
	ret = wc_AesInit(enc, NULL, INVALID_DEVID);
	LWIP_ASSERT("ws_AesInit() failed", ret == 0);

	/* init keys */
	ret = wc_AesSetKey(enc, (byte*) ucPlainKey, sizeof(ucPlainKey),
			(byte*) ucInitVector, AES_ENCRYPTION);
	LWIP_ASSERT("ws_AesSetKey() failed", ret == 0);

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1,
			(uint8_t *)"AES-CCM:\r\n", 10, TIMEOUT_ENCRYPTION);

	// Encrypt
	start_time = current_time_ms();
	for (i = 0; i < NUM_BLOCKS; ++i)
	{
		ret = wc_AesCcmEncrypt(enc, ucEncMsg, ucMsg, BLOCK_SIZE,
				ucInitVector, 12, ucTag, AES_AUTH_TAG_SZ, ucAdd,
				AES_AUTH_ADD_SZ);
		LWIP_ASSERT("ws_AesCbcEncrypt() failed", ret == 0);
	}
	done_time = current_time_ms();
	p = &result[4];
	memset(p, ' ', 10);
	custom_itoa(p, 7, (done_time - start_time));
	while (*p) p++;
	while (!(*p)) *(p++) = ' ';

	/* init keys */
	ret = wc_AesSetKey(enc, (byte*) ucPlainKey, sizeof(ucPlainKey),
			(byte*) ucInitVector, AES_ENCRYPTION);
	LWIP_ASSERT("ws_AesSetKey() failed", ret == 0);

	// Decrypt
	start_time = current_time_ms();
	for (i = 0; i < NUM_BLOCKS; ++i)
	{
		ret = wc_AesCcmDecrypt(enc, ucDecMsg, ucEncMsg, BLOCK_SIZE,
				ucInitVector, 12, ucTag, AES_AUTH_TAG_SZ, ucAdd,
				AES_AUTH_ADD_SZ);
		LWIP_ASSERT("ws_AesCbcDecrypt() failed", ret == 0);
//		DEV_ASSERT(bufferCompare(ucDecMsg, ucMsg, BLOCK_SIZE));
	}
	done_time = current_time_ms();
	p = &result[22];
	memset(p, ' ', 10);
	custom_itoa(p, 7, (done_time - start_time));
	while (*p) p++;
	while (!(*p)) *(p++) = ' ';

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1,
			(uint8_t *)result, strlen(result), TIMEOUT_ENCRYPTION);

	wc_AesFree(enc);
}
#endif

#ifdef HAVE_AESGCM
static void benchAesGcm()
{
	int i;
	int ret = 0;

	memset(ucMsg, 0, BLOCK_SIZE);
	memset(ucEncMsg, 0, BLOCK_SIZE);
	memset(ucDecMsg, 0, BLOCK_SIZE);
	memset(enc, 0, sizeof(Aes));
	ret = wc_AesInit(enc, NULL, INVALID_DEVID);
	LWIP_ASSERT("ws_AesInit() failed", ret == 0);

	/* init keys */
	ret = wc_AesSetKey(enc, (byte*) ucPlainKey, sizeof(ucPlainKey),
			(byte*) ucInitVector, AES_ENCRYPTION);
	LWIP_ASSERT("ws_AesSetKey() failed", ret == 0);

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1,
			(uint8_t *)"AES-GCM:\r\n", 10, TIMEOUT_ENCRYPTION);

	// Encrypt
	start_time = current_time_ms();
	for (i = 0; i < NUM_BLOCKS; ++i)
	{
		ret = wc_AesGcmEncrypt(enc, ucEncMsg, ucMsg, BLOCK_SIZE,
				ucInitVector, 12, ucTag, AES_AUTH_TAG_SZ, ucAdd,
				AES_AUTH_ADD_SZ);
		LWIP_ASSERT("ws_AesCbcEncrypt() failed", ret == 0);
	}
	done_time = current_time_ms();
	p = &result[4];
	memset(p, ' ', 10);
	custom_itoa(p, 5, (done_time - start_time));
	while (*p) p++;
	while (!(*p)) *(p++) = ' ';

	/* init keys */
	ret = wc_AesSetKey(enc, (byte*) ucPlainKey, sizeof(ucPlainKey),
			(byte*) ucInitVector, AES_ENCRYPTION);
	LWIP_ASSERT("ws_AesSetKey() failed", ret == 0);

	// Decrypt
	start_time = current_time_ms();
	for (i = 0; i < NUM_BLOCKS; ++i)
	{
		ret = wc_AesGcmDecrypt(enc, ucDecMsg, ucEncMsg, BLOCK_SIZE,
				ucInitVector, 12, ucTag, AES_AUTH_TAG_SZ, ucAdd,
				AES_AUTH_ADD_SZ);
		LWIP_ASSERT("ws_AesCbcDecrypt() failed", ret == 0);
//		DEV_ASSERT(bufferCompare(ucDecMsg, ucMsg, BLOCK_SIZE));
	}
	done_time = current_time_ms();
	p = &result[22];
	memset(p, ' ', 10);
	custom_itoa(p, 5, (done_time - start_time));
	while (*p) p++;
	while (!(*p)) *(p++) = ' ';

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1,
			(uint8_t *)result, strlen(result), TIMEOUT_ENCRYPTION);

	wc_AesFree(enc);
}
#endif

static void benchSha256()
{
	int i;
	int ret = 0;

	memset(&wcHash, 0, sizeof(wcHash));
	ret = wc_InitSha256(&wcHash);
	LWIP_ASSERT("wc_InitSha256() failed", ret == 0);

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1,
			(uint8_t *)"SHA256:\r\n", 9, TIMEOUT_ENCRYPTION);

	// SHA256
	start_time = current_time_ms();
	for (i = 0; i < NUM_BLOCKS; ++i)
	{
		ret = wc_Sha256Update(&wcHash, ucMsg, BLOCK_SIZE);
		LWIP_ASSERT("wc_Sha256Update() failed", ret == 0);

		ret = wc_Sha256Final(&wcHash, ucHash);
		LWIP_ASSERT("wc_Sha256Final() failed", ret == 0);
	}
	done_time = current_time_ms();
	p = &result2[9];
	memset(p, ' ', 10);
	custom_itoa(p, 5, (done_time - start_time));
	while (*p) p++;
	while (!(*p)) *(p++) = ' ';

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1,
			(uint8_t *)result2, strlen(result2), TIMEOUT_ENCRYPTION);
}

static void benchHmac256()
{
	int i;
	int ret = 0;

	memset(&wcHmac, 0, sizeof(wcHmac));
	ret = wc_HmacInit(&wcHmac, NULL, INVALID_DEVID);
	LWIP_ASSERT("wc_HmacInit() failed", ret == 0);
	ret = wc_HmacSetKey(&wcHmac, SHA256, ucPlainKey, sizeof(ucPlainKey));
	LWIP_ASSERT("wc_HmacSetKey() failed", ret == 0);

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1,
			(uint8_t *)"HMAC256:\r\n", 10, TIMEOUT_ENCRYPTION);

	// HMAC256
	start_time = current_time_ms();
	for (i = 0; i < NUM_BLOCKS; ++i)
	{
		ret = wc_HmacUpdate(&wcHmac, ucMsg, BLOCK_SIZE);
		LWIP_ASSERT("wc_HmacUpdate() failed", ret == 0);

		ret = wc_HmacFinal(&wcHmac, ucHash);
		LWIP_ASSERT("wc_Sha256Final() failed", ret == 0);
	}
	done_time = current_time_ms();
	p = &result2[9];
	memset(p, ' ', 10);
	custom_itoa(p, 5, (done_time - start_time));
	while (*p) p++;
	while (!(*p)) *(p++) = ' ';

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1,
			(uint8_t *)result2, strlen(result2), TIMEOUT_ENCRYPTION);
}

static void benchRsaEncrypt()
{

}

static void benchRsaVerify()
{

}

typedef void (*TaskFunc)(void);
static TaskFunc taskFuncs[] = {
		benchNone,
#ifdef HAVE_AES_CBC
		benchAesCbc,
#endif
#ifdef HAVE_AESCCM
		benchAesCcm,
#endif
#ifdef HAVE_AESGCM
		benchAesGcm,
#endif
		benchSha256, benchHmac256,
		benchRsaEncrypt, benchRsaVerify
};

void wolfSSLBenchMainLoopTask(void *pvParam)
{
	enc = (Aes*)XMALLOC(sizeof(Aes), 0, 0);
	do {

		for (int i = TASK_NONE; i <= RSA_VERIFY; ++i)
		{
			vTaskDelay(TASK_DELAY);

			taskFuncs[i]();
		}

	} while (1);
	XFREE(enc, 0, 0);
}

#endif /* ST_BENCH_WOLFSSL */

/** SCRATCH PAD
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/poly1305.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include <wolfssl/internal.h>

// how many kB to test (en/de)cryption
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

static Aes* enc = NULL;
static byte* bench_plain = NULL;
static byte* bench_cipher = NULL;

char* bench_aescbc(word32 keySz);

char* bench_chacha20_poly1305_aead(void);
#if defined(HAVE_AESCCM)
char* bench_aesccm(word32 keySz);
#endif
#if defined(HAVE_AESGCM)
char* bench_aesgcm(word32 keySz);
#endif
char* bench_ecc_key_gen();
char* bench_ecdsa(word32 keySz);
char* bench_ecdhe();
char* bench_rsa();
char* bench_ecc_encrypt();

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

	// init keys
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

	// init keys
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

	// init keys
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

	// init keys
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
 */
