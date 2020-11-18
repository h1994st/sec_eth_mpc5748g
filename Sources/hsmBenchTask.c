#include "hsmBenchTask.h"
#include "utils.h"

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
#include <wolfssl/wolfcrypt/sha256.h>

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
static uint8_t ucAdd[AES_AUTH_ADD_SZ] = { 0 };
static const uint8_t ucPlainKey[MESSAGE_LENGTH] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
};
static uint8_t ucHash[SHA256_SIZE] = { 0 };
static uint8_t ucHash2[SHA256_SIZE] = { 0 };
static char result[38] = "Enc:           ms Dec:           ms\r\n";
static char result2[] = "Duration:           ms\r\n";
static char *p = NULL;

static void benchNone()
{
	int wc_ret = 0;
	status_t hsm_ret;
	bool ret = false;
	bool authStatus = false;

	// do the HSM-based APIs work correctly?
	// cross-validate AES-GCM
	Aes* enc = (Aes*)XMALLOC(sizeof(Aes), 0, 0);
	wc_ret = wc_AesInit(enc, NULL, INVALID_DEVID);
	DEV_ASSERT(wc_ret == 0);

	memset(ucEncMsg, 0, BLOCK_SIZE);
	memset(ucDecMsg, 1, BLOCK_SIZE); // to distinguish two buffers -- by h1994st
	memset(ucTag, 0, AES_AUTH_TAG_SZ);
	wc_ret = wc_AesGcmSetKey(enc, (byte*)ucPlainKey, 16);
	DEV_ASSERT(wc_ret == 0);

	start_time = current_time_ms();
	for (int i = 0; i < 5; ++i)
	{
		hsm_ret = HSM_DRV_EncryptGCM(HSM_RAM_KEY, 12, ucInitVector,
				AES_AUTH_ADD_SZ, ucAdd,
				BLOCK_SIZE, ucMsg,
				ucEncMsg,
				AES_AUTH_TAG_SZ, ucTag,
				TIMEOUT_ENCRYPTION);
		DEV_ASSERT(hsm_ret == STATUS_SUCCESS);

//		hsm_ret = HSM_DRV_DecryptGCM(HSM_RAM_KEY, 12, ucInitVector,
//				AES_AUTH_ADD_SZ, ucAdd,
//				BLOCK_SIZE, ucEncMsg,
//				ucDecMsg,
//				AES_AUTH_TAG_SZ, ucTag,
//				&authStatus, TIMEOUT_ENCRYPTION);
//		DEV_ASSERT(hsm_ret == STATUS_SUCCESS);
//		DEV_ASSERT(authStatus == true);
//
//		ret = bufferCompare(ucMsg, ucDecMsg, BLOCK_SIZE);
//		if (ret) {
//			printString("1yyyy\r\n");
//		} else {
//			printString("1nnnn\r\n");
//		}
//
//		ret = wc_AesGcmEncrypt(enc, ucEncMsg, ucMsg, BLOCK_SIZE,
//				ucInitVector, 12,
//				ucTag, AES_AUTH_TAG_SZ,
//				ucAdd, AES_AUTH_ADD_SZ);
//		DEV_ASSERT(ret == 0);

		wc_ret = wc_AesGcmDecrypt(enc, ucDecMsg, ucEncMsg, BLOCK_SIZE,
				ucInitVector, 12,
				ucTag, AES_AUTH_TAG_SZ,
				ucAdd, AES_AUTH_ADD_SZ);
		DEV_ASSERT(wc_ret == 0);

		ret = bufferCompare(ucMsg, ucDecMsg, BLOCK_SIZE);
		if (ret) {
			printString("2yyyy\r\n");
		} else {
			printString("2nnnn\r\n");
		}
	}

	XFREE(enc, 0, 0);
	memset(ucMsg, 0, BLOCK_SIZE);
	memset(ucEncMsg, 0, BLOCK_SIZE);
	memset(ucDecMsg, 0, BLOCK_SIZE);

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
		hsm_ret = HSM_DRV_EncryptCCM(HSM_RAM_KEY, 12, ucInitVector, AES_AUTH_ADD_SZ, ucAdd,
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
		hsm_ret = HSM_DRV_DecryptCCM(HSM_RAM_KEY, 12, ucInitVector, AES_AUTH_ADD_SZ, ucAdd,
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
		hsm_ret = HSM_DRV_EncryptGCM(HSM_RAM_KEY, 12, ucInitVector, AES_AUTH_ADD_SZ, ucAdd,
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
		hsm_ret = HSM_DRV_DecryptGCM(HSM_RAM_KEY, 12, ucInitVector, AES_AUTH_ADD_SZ, ucAdd,
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
