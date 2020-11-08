/*
 * wolfSSLBenchTask.c
 *
 *  Created on: 2020/11/4
 *      Author: shengtuo
 */

#include <wolfSSLBenchTask.h>

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

/* Compares two buffers; returns true if buffers are identical,
 * false if at least one element is different.
 */
bool bufferCompare(uint8_t *buff1, uint8_t *buff2, uint32_t len)
{
    uint32_t idx;
    for (idx = 0; idx < len; idx++)
    {
        if (buff1[idx] != buff2[idx])
        {
            return false;
        }
    }
    return true;
}

double current_time(void)
{
	uint32_t msecs = OSIF_GetMilliseconds();
	return (double) msecs / (double) 1000;
}

uint32_t current_time_ms(void)
{
	return OSIF_GetMilliseconds();
}

void
custom_itoa(char *result, size_t bufsize, int number)
{
  char *res = result;
  char *tmp = result + bufsize - 1;
  int n = (number >= 0) ? number : -number;

  /* handle invalid bufsize */
  if (bufsize < 2) {
    if (bufsize == 1) {
      *result = 0;
    }
    return;
  }

  /* First, add sign */
  if (number < 0) {
    *res++ = '-';
  }
  /* Then create the string from the end and stop if buffer full,
     and ensure output string is zero terminated */
  *tmp = 0;
  while ((n != 0) && (tmp > res)) {
    char val = (char)('0' + (n % 10));
    tmp--;
    *tmp = val;
    n = n / 10;
  }
  if (n) {
    /* buffer is too small */
    *result = 0;
    return;
  }
  if (*tmp == 0) {
    /* Nothing added? */
    *res++ = '0';
    *res++ = 0;
    return;
  }
  /* move from temporary buffer to output buffer (sign is not moved) */
  memmove(res, tmp, (size_t)((result + bufsize) - tmp));
}

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
