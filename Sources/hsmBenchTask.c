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
extern bool HSM_GetAuthResult(void);

#include <string.h>

/* FreeRTOS defines: */
#define TASK0_DELAY         ((TickType_t)100 / portTICK_PERIOD_MS)
#define TASK0_PRIORITY      (tskIDLE_PRIORITY + 1)
#define MESSAGE_LENGTH      16

#define BLOCK_SIZE          1024
#define NUM_BLOCKS          4096
#define SPEED(start, end)   (int)(((end) - (start)) > 0.0 ? ((double)NUM_BLOCKS / ((end) - (start))) : 0)
#define AES_AUTH_ADD_SZ     13
#define AES_AUTH_TAG_SZ     16
#define BENCH_CIPHER_ADD    AES_AUTH_TAG_SZ

/* Application defines: */
#define TIMEOUT_ENCRYPTION    (1000U)
#define PLAINTEXT    "AccessCode:01234"
#define MSG_ECB_OK   "\r\nAES ECB Encryption/Decryption OK\r\n"
#define MSG_CBC_OK   "\r\nAES CBC Encryption/Decryption OK\r\n"
#define MSG_ERROR    "\r\nAn error occurred during the cryptographic operations!\r\n"
#define MSG_HELLO    "hello \r\n"

/* Enums: */
typedef enum{
    ENCRYPT_NONE = 0,
    ENCRYPT_ECB  = 1,
    ENCRYPT_CBC  = 2,
	ENCRYPT_CCM  = 3,
	ENCRYPT_GCM  = 4,
}EncryptionType_e;

/* Structures: */
typedef struct{
    uint8_t ucInitVector[MESSAGE_LENGTH];
    uint8_t ucEncMsg[MESSAGE_LENGTH];
}Data_t;

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

/* Benchmark Task */
const uint8_t ucMsg[BLOCK_SIZE] = { 0 };
uint8_t ucEncMsg[BLOCK_SIZE] = { 0 };
uint8_t ucDecMsg[BLOCK_SIZE] = { 0 };

void hsmBenchMainLoopTask(void *pvParam)
{
	static char result[38] = "Enc:           ms Dec:           ms\r\n";
	char *p = NULL;
	int i = 0;
	uint32_t start_time, done_time;
    uint8_t ucInitVector[MESSAGE_LENGTH] = {
    		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    uint8_t ucTag[AES_AUTH_TAG_SZ] = { 0 };
    uint8_t ucAdd[AES_AUTH_TAG_SZ] = { 0 };
    bool authStatus = true;
    static EncryptionType_e eEncType = ENCRYPT_NONE;

    /** Initialize HSM Driver: */
    const uint8_t ucPlainKey[MESSAGE_LENGTH] = {
    		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };

	status_t hsm_ret;
	HSM_DRV_Init(&hsm1_State);
	HSM_DRV_LoadPlainKey(ucPlainKey, TIMEOUT_ENCRYPTION);

	/* Initialize LINFLEXD peripheral for UART echo to console */
//	LINFLEXD_UART_DRV_Init(INST_LINFLEXD_UART1, &linflexd_uart1_State, &linflexd_uart1_InitConfig0);

	do {
		/* Every 'TASK0_DELAY' encrypt message */
		vTaskDelay(TASK0_DELAY);

        switch (eEncType)
        {
            case ENCRYPT_NONE:
            	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)MSG_HELLO, strlen(MSG_HELLO), TIMEOUT_ENCRYPTION);
                eEncType = ENCRYPT_CBC;
                break;
            case ENCRYPT_CBC:
            {
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
//            		DEV_ASSERT(bufferCompare(ucDecMsg, ucMsg, BLOCK_SIZE));
            	}
            	done_time = current_time_ms();
            	p = &result[22];
            	memset(p, ' ', 10);
            	custom_itoa(p, 5, (done_time - start_time));
            	while (*p) p++;
				while (!(*p)) *(p++) = ' ';

            	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)result, 38, TIMEOUT_ENCRYPTION);
				eEncType = ENCRYPT_CCM;
				break;
            }
            case ENCRYPT_CCM:
            {
            	// Encrypt
//            	status_t HSM_DRV_EncryptCCM(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
//            	                            const uint8_t *authData, uint32_t plainTextLen, const uint8_t *plainText,
//            	                            uint8_t *cipherText, uint32_t tagLen, uint8_t *tag, uint32_t timeout)
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
//				status_t HSM_DRV_DecryptCCM(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
//				                            const uint8_t *authData, uint32_t cipherTextLen, const uint8_t *cipherText,
//				                            uint8_t *decryptedText, uint32_t tagLen, const uint8_t *tag, bool *authStatus,
//				                            uint32_t timeout)
            	start_time = current_time_ms();
            	for (i = 0; i < NUM_BLOCKS; ++i)
            	{
            		hsm_ret = HSM_DRV_DecryptCCM(HSM_RAM_KEY, 12, ucInitVector, AES_AUTH_TAG_SZ, ucAdd,
            				BLOCK_SIZE, ucEncMsg,
							ucDecMsg, AES_AUTH_TAG_SZ, ucTag, &authStatus, TIMEOUT_ENCRYPTION);
            		DEV_ASSERT(hsm_ret == STATUS_SUCCESS);
            		DEV_ASSERT(HSM_GetAuthResult() == true);
//            		DEV_ASSERT(bufferCompare(ucDecMsg, ucMsg, BLOCK_SIZE));
            	}
            	done_time = current_time_ms();
            	p = &result[22];
            	memset(p, ' ', 10);
            	custom_itoa(p, 5, (done_time - start_time));
            	while (*p) p++;
				while (!(*p)) *(p++) = ' ';

            	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)result, 38, TIMEOUT_ENCRYPTION);
				eEncType = ENCRYPT_GCM;
				break;
            }
            case ENCRYPT_GCM:
            {
            	// Encrypt
//            	status_t HSM_DRV_EncryptGCM(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
//            	                            const uint8_t *authData, uint32_t plainTextLen, const uint8_t *plainText,
//            	                            uint8_t *cipherText, uint32_t tagLen, uint8_t *tag, uint32_t timeout)
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
//				status_t HSM_DRV_DecryptGCM(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
//				                            const uint8_t *authData, uint32_t cipherTextLen, const uint8_t *cipherText,
//				                            uint8_t *decryptedText, uint32_t tagLen, const uint8_t *tag, bool *authStatus,
//				                            uint32_t timeout)
            	start_time = current_time_ms();
            	for (i = 0; i < NUM_BLOCKS; ++i)
            	{
            		hsm_ret = HSM_DRV_DecryptGCM(HSM_RAM_KEY, 12, ucInitVector, AES_AUTH_TAG_SZ, ucAdd,
            				BLOCK_SIZE, ucEncMsg,
							ucDecMsg, AES_AUTH_TAG_SZ, ucTag, &authStatus, TIMEOUT_ENCRYPTION);
            		DEV_ASSERT(hsm_ret == STATUS_SUCCESS);
            		DEV_ASSERT(HSM_GetAuthResult() == true);
//            		DEV_ASSERT(bufferCompare(ucDecMsg, ucMsg, BLOCK_SIZE));
            	}
            	done_time = current_time_ms();
            	p = &result[22];
            	memset(p, ' ', 10);
            	custom_itoa(p, 5, (done_time - start_time));
            	while (*p) p++;
				while (!(*p)) *(p++) = ' ';

            	LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)result, 38, TIMEOUT_ENCRYPTION);
				eEncType = ENCRYPT_NONE;
				break;
            }
            default:
                /* Do nothing... */
                break;
        }
	} while (1);
}

#endif /* ST_BENCH_W_HSM */
