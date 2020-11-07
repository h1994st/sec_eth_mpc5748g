#include "hsmBenchTask.h"

#if ST_BENCH_W_HSM

#include "Cpu.h"

#if defined(USING_OS_FREERTOS)
/* FreeRTOS kernel includes. */
#include "FreeRTOS.h"
#include "task.h"
#endif /* defined(USING_OS_FREERTOS) */

#include "hsm1.h"
#include "hsm_driver.h"        /* HSM driver include */

#include <string.h>
#include <wolfssl/wolfcrypt/aes.h>

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
    ENCRYPT_CBC,
    ENCRYPT_CCM,
    ENCRYPT_GCM,
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
static uint8_t ucMsg[BLOCK_SIZE + 1] = { 0 };
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
static char result[38] = "Enc:           ms Dec:           ms\r\n";
static char result2[] = "Duration:           ms\r\n";
static char *p = NULL;

static void benchNone()
{
	// is CBC deterministic?
	status_t hsm_ret;
	memset(ucMsg, 1, BLOCK_SIZE + 1);
	hsm_ret = HSM_DRV_EncryptCBC(HSM_RAM_KEY, (uint8_t*)ucMsg, BLOCK_SIZE, (uint8_t*)ucInitVector, (uint8_t*)ucEncMsg, TIMEOUT_ENCRYPTION);
	DEV_ASSERT(hsm_ret == STATUS_SUCCESS);
	hsm_ret = HSM_DRV_EncryptCBC(HSM_RAM_KEY, (uint8_t*)ucMsg, BLOCK_SIZE, (uint8_t*)ucInitVector, (uint8_t*)ucDecMsg, TIMEOUT_ENCRYPTION);
	DEV_ASSERT(hsm_ret == STATUS_SUCCESS);

	bool ret = bufferCompare(ucEncMsg, ucDecMsg, BLOCK_SIZE);
	if (ret) {
		LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)"yyy\r\n", 5, TIMEOUT_ENCRYPTION);
	} else {
		LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)"nnn\r\n", 5, TIMEOUT_ENCRYPTION);
	}

	// does wolfSSL CBC work well? (wolfSSL CBC will check the address alignment)
	Aes* enc = (Aes*)XMALLOC(sizeof(Aes), 0, 0);
	int wc_ret = 0;
	wc_ret = wc_AesInit(enc, NULL, INVALID_DEVID);
	DEV_ASSERT(wc_ret == 0);

	memset(ucEncMsg, 0, BLOCK_SIZE);
	wc_ret = wc_AesSetKey(enc, (byte*)ucPlainKey, 16, (byte*)ucInitVector,
			AES_ENCRYPTION);
	DEV_ASSERT(wc_ret == 0);
	wc_ret = wc_AesCbcEncrypt(enc, ucEncMsg, ucMsg + 1, BLOCK_SIZE);
	DEV_ASSERT(wc_ret == 0);
	DEV_ASSERT(bufferCompare(ucEncMsg, ucDecMsg, BLOCK_SIZE));

	memset(ucDecMsg, 0, BLOCK_SIZE);
	wc_ret = wc_AesSetKey(enc, (byte*)ucPlainKey, 16, (byte*)ucInitVector,
			AES_ENCRYPTION);
	DEV_ASSERT(wc_ret == 0);
	wc_ret = wc_AesCbcEncrypt(enc, ucDecMsg, ucMsg, BLOCK_SIZE);
	DEV_ASSERT(wc_ret == 0);

	ret = bufferCompare(ucEncMsg, ucDecMsg, BLOCK_SIZE);
	if (ret) {
		LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)"yyyy\r\n", 6, TIMEOUT_ENCRYPTION);
	} else {
		LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)"nnnn\r\n", 6, TIMEOUT_ENCRYPTION);
	}
	XFREE(enc, 0, 0);

	memset(ucMsg, 0, BLOCK_SIZE);
	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)MSG_HELLO, strlen(MSG_HELLO), TIMEOUT_ENCRYPTION);
}

static void benchHsmAesCbc()
{
	int i;
	status_t hsm_ret;

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)"AES-CBC:\r\n", 10, TIMEOUT_ENCRYPTION);

	// Encrypt
	start_time = current_time_ms();
	for (i = 0; i < NUM_BLOCKS; ++i)
	{
		hsm_ret = HSM_DRV_EncryptCBC(HSM_RAM_KEY, (uint8_t*)ucMsg, BLOCK_SIZE, (uint8_t*)ucInitVector, (uint8_t*)ucEncMsg, TIMEOUT_ENCRYPTION);
		DEV_ASSERT(hsm_ret == STATUS_SUCCESS);
	}
	done_time = current_time_ms();
	p = &result[4];
	memset(p, ' ', 10);
	custom_itoa(p, 5, (done_time - start_time));
	while (*p) p++;
	while (!(*p)) *(p++) = ' ';

	// Decrypt
	start_time = current_time_ms();
	for (i = 0; i < NUM_BLOCKS; ++i)
	{
		hsm_ret = HSM_DRV_DecryptCBC(HSM_RAM_KEY, ucEncMsg, BLOCK_SIZE, (uint8_t*)ucInitVector, (uint8_t*)ucDecMsg, TIMEOUT_ENCRYPTION);
		DEV_ASSERT(hsm_ret == STATUS_SUCCESS);
//		DEV_ASSERT(bufferCompare(ucDecMsg, ucMsg, BLOCK_SIZE));
	}
	done_time = current_time_ms();
	p = &result[22];
	memset(p, ' ', 10);
	custom_itoa(p, 5, (done_time - start_time));
	while (*p) p++;
	while (!(*p)) *(p++) = ' ';

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)result, strlen(result), TIMEOUT_ENCRYPTION);
}

static void benchHsmAesCcm()
{
	int i;
	status_t hsm_ret;
	bool authStatus = false;

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)"AES-CCM:\r\n", 10, TIMEOUT_ENCRYPTION);

	// Encrypt
//	status_t HSM_DRV_EncryptCCM(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
//								const uint8_t *authData, uint32_t plainTextLen, const uint8_t *plainText,
//								uint8_t *cipherText, uint32_t tagLen, uint8_t *tag, uint32_t timeout)
	start_time = current_time_ms();
	for (i = 0; i < NUM_BLOCKS; ++i)
	{
		hsm_ret = HSM_DRV_EncryptCCM(HSM_RAM_KEY, 12, ucInitVector, AES_AUTH_TAG_SZ, ucAdd,
				BLOCK_SIZE, ucMsg,
				ucEncMsg, AES_AUTH_TAG_SZ, ucTag, TIMEOUT_ENCRYPTION);
		DEV_ASSERT(hsm_ret == STATUS_SUCCESS);
	}
	done_time = current_time_ms();
	p = &result[4];
	memset(p, ' ', 10);
	custom_itoa(p, 5, (done_time - start_time));
	while (*p) p++;
	while (!(*p)) *(p++) = ' ';

	// Decrypt
//	status_t HSM_DRV_DecryptCCM(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
//								const uint8_t *authData, uint32_t cipherTextLen, const uint8_t *cipherText,
//								uint8_t *decryptedText, uint32_t tagLen, const uint8_t *tag, bool *authStatus,
//								uint32_t timeout)
	start_time = current_time_ms();
	for (i = 0; i < NUM_BLOCKS; ++i)
	{
		hsm_ret = HSM_DRV_DecryptCCM(HSM_RAM_KEY, 12, ucInitVector, AES_AUTH_TAG_SZ, ucAdd,
				BLOCK_SIZE, ucEncMsg,
				ucDecMsg, AES_AUTH_TAG_SZ, ucTag, &authStatus, TIMEOUT_ENCRYPTION);
		DEV_ASSERT(hsm_ret == STATUS_SUCCESS);
		DEV_ASSERT(authStatus == true);
//		DEV_ASSERT(bufferCompare(ucDecMsg, ucMsg, BLOCK_SIZE));
	}
	done_time = current_time_ms();
	p = &result[22];
	memset(p, ' ', 10);
	custom_itoa(p, 5, (done_time - start_time));
	while (*p) p++;
	while (!(*p)) *(p++) = ' ';

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)result, strlen(result), TIMEOUT_ENCRYPTION);
}

static void benchHsmAesGcm()
{
	int i;
	status_t hsm_ret;
	bool authStatus = false;

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)"AES-GCM:\r\n", 10, TIMEOUT_ENCRYPTION);

	// Encrypt
//	status_t HSM_DRV_EncryptGCM(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
//								const uint8_t *authData, uint32_t plainTextLen, const uint8_t *plainText,
//								uint8_t *cipherText, uint32_t tagLen, uint8_t *tag, uint32_t timeout)
	start_time = current_time_ms();
	for (i = 0; i < NUM_BLOCKS; ++i)
	{
		hsm_ret = HSM_DRV_EncryptGCM(HSM_RAM_KEY, 12, ucInitVector, AES_AUTH_TAG_SZ, ucAdd,
				BLOCK_SIZE, ucMsg,
				ucEncMsg, AES_AUTH_TAG_SZ, ucTag, TIMEOUT_ENCRYPTION);
		DEV_ASSERT(hsm_ret == STATUS_SUCCESS);
	}
	done_time = current_time_ms();
	p = &result[4];
	memset(p, ' ', 10);
	custom_itoa(p, 5, (done_time - start_time));
	while (*p) p++;
	while (!(*p)) *(p++) = ' ';

	// Decrypt
//	status_t HSM_DRV_DecryptGCM(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
//								const uint8_t *authData, uint32_t cipherTextLen, const uint8_t *cipherText,
//								uint8_t *decryptedText, uint32_t tagLen, const uint8_t *tag, bool *authStatus,
//								uint32_t timeout)
	start_time = current_time_ms();
	for (i = 0; i < NUM_BLOCKS; ++i)
	{
		hsm_ret = HSM_DRV_DecryptGCM(HSM_RAM_KEY, 12, ucInitVector, AES_AUTH_TAG_SZ, ucAdd,
				BLOCK_SIZE, ucEncMsg,
				ucDecMsg, AES_AUTH_TAG_SZ, ucTag, &authStatus, TIMEOUT_ENCRYPTION);
		DEV_ASSERT(hsm_ret == STATUS_SUCCESS);
		DEV_ASSERT(authStatus == true);
//		DEV_ASSERT(bufferCompare(ucDecMsg, ucMsg, BLOCK_SIZE));
	}
	done_time = current_time_ms();
	p = &result[22];
	memset(p, ' ', 10);
	custom_itoa(p, 5, (done_time - start_time));
	while (*p) p++;
	while (!(*p)) *(p++) = ' ';

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)result, strlen(result), TIMEOUT_ENCRYPTION);
}

static void benchHsmSha256()
{
	int i;
	status_t hsm_ret;

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)"SHA256:\r\n", 9, TIMEOUT_ENCRYPTION);

	// SHA256
//	status_t HSM_DRV_HashSHA256(uint32_t msgLen, const uint8_t *msg, uint8_t *hash, uint32_t timeout)
	start_time = current_time_ms();
	for (i = 0; i < NUM_BLOCKS; ++i)
	{
		hsm_ret = HSM_DRV_HashSHA256(BLOCK_SIZE, ucMsg, ucHash, TIMEOUT_ENCRYPTION);
		DEV_ASSERT(hsm_ret == STATUS_SUCCESS);
	}
	done_time = current_time_ms();
	p = &result2[9];
	memset(p, ' ', 10);
	custom_itoa(p, 5, (done_time - start_time));
	while (*p) p++;
	while (!(*p)) *(p++) = ' ';

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)result2, strlen(result2), TIMEOUT_ENCRYPTION);
}

static void benchHsmHmac256()
{
	int i;
	status_t hsm_ret;
	uint32_t hash_len = SHA256_SIZE;

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)"HMAC256:\r\n", 10, TIMEOUT_ENCRYPTION);

	// HMAC256
//	status_t HSM_DRV_HashHMAC256(hsm_key_id_t keyId, uint32_t msgLen, const uint8_t *msg, uint32_t *hashLen,
//	                             uint8_t *hash, uint32_t timeout)
	start_time = current_time_ms();
	for (i = 0; i < NUM_BLOCKS; ++i)
	{
		hsm_ret = HSM_DRV_HashHMAC256(HSM_HMAC_KEY1, BLOCK_SIZE, ucMsg, &hash_len, ucHash, TIMEOUT_ENCRYPTION);
		DEV_ASSERT(hsm_ret == STATUS_SUCCESS);
		DEV_ASSERT(hash_len == SHA256_SIZE);
	}
	done_time = current_time_ms();
	p = &result2[9];
	memset(p, ' ', 10);
	custom_itoa(p, 5, (done_time - start_time));
	while (*p) p++;
	while (!(*p)) *(p++) = ' ';

	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)result2, strlen(result2), TIMEOUT_ENCRYPTION);
}

static void benchHsmRsaEncrypt()
{

}

static void benchHsmRsaVerify()
{

}

typedef void (*TaskFunc)(void);
static TaskFunc taskFuncs[] = {
		benchNone, benchHsmAesCbc, benchHsmAesCcm, benchHsmAesGcm,
		benchHsmSha256, benchHsmHmac256,
		benchHsmRsaEncrypt, benchHsmRsaVerify
};

void hsmBenchMainLoopTask(void *pvParam)
{
    /** Initialize HSM Driver: */
	status_t hsm_ret;
	hsm_ret = HSM_DRV_Init(&hsm1_State);
	DEV_ASSERT(hsm_ret == STATUS_SUCCESS);

	// Load 128-bit key
	hsm_ret = HSM_DRV_LoadPlainKey(ucPlainKey, TIMEOUT_ENCRYPTION);
	DEV_ASSERT(hsm_ret == STATUS_SUCCESS);

	// Generate HMAC key
	hsm_random_kdf_t random_kdf = { .randomKeyId = HSM_HMAC_KEY1, .randomKeySize = 32 };
	hsm_ret = HSM_DRV_GenerateExtendedRamKeys(HSM_HMAC_KEY1, RANDOM_KEY, &random_kdf, TIMEOUT_ENCRYPTION);

	do {

		for (int i = TASK_NONE; i <= RSA_VERIFY; ++i)
		{
			vTaskDelay(TASK_DELAY);

			taskFuncs[i]();
		}

	} while (1);
}

#endif /* ST_BENCH_W_HSM */
