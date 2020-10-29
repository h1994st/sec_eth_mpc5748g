/* ###################################################################
**     Filename    : main.c
**     Project     : hsm_freertos_mpc5748g
**     Processor   : MPC5748G_324
**     Version     : Driver 01.00
**     Compiler    : GNU C Compiler
**     Date/Time   : 2017-06-15, 15:35, # CodeGen: 0
**     Abstract    :
**         Main module.
**         This module contains user's application code.
**     Settings    :
**     Contents    :
**         No public methods
**
** ###################################################################*/
/*!
** @file main.c
** @version 01.00
** @brief
**
**        The demo presents the HSM driver functionalities.
**        TASK0 sends an encrypted message to TASK1 using both
**        ECB and CBC encryption.
**
*/
/*!
**  @addtogroup main_module main module documentation
**  @{
*/
/* MODULE main */


/* Including needed modules to compile this module/procedure */
#include "Cpu.h"
#include "clockMan1.h"
#include "FreeRTOS.h"
#include "hsm1.h"

volatile int exit_code = 0;

/* User includes (#include below this line is not maintained by Processor Expert) */
#include "task.h"
#include "queue.h"
#include "hsm_driver.h"        /* HSM driver include */
#include <string.h>

/* FreeRTOS defines: */
#define TASK0_DELAY         ((TickType_t)100 / portTICK_PERIOD_MS)
#define TASK0_PRIORITY      (tskIDLE_PRIORITY + 1)
#define TASK1_DELAY         ((TickType_t)110 / portTICK_PERIOD_MS)
#define TASK1_PRIORITY      (tskIDLE_PRIORITY + 2)
#define NOF_QUEUES          1
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
static QueueHandle_t g_tQueueHandle;

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

void vTASKBench(void *pvParam)
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
	static hsm_state_t state1;
	HSM_DRV_Init(&state1);
	HSM_DRV_LoadPlainKey(ucPlainKey, TIMEOUT_ENCRYPTION);

	/* Initialize LINFLEXD peripheral for UART echo to console */
	LINFLEXD_UART_DRV_Init(INST_LINFLEXD_UART1, &linflexd_uart1_State, &linflexd_uart1_InitConfig0);

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

/* Task 0 code */
//void vTASK0(void *pvParam)
//{
//    const uint8_t ucMsg[MESSAGE_LENGTH] = {PLAINTEXT};
//    static Data_t tTxData = {.ucInitVector = "1234567887654321"};
//    static EncryptionType_e eEncType = ENCRYPT_NONE;
//
//    /** Initialize HSM Driver: */
//    const uint8_t ucPlainKey[MESSAGE_LENGTH] = {0x2b, 0x7e, 0x15, 0x16,
//                                                0x28, 0xae, 0xd2, 0xa6,
//                                                0xab, 0xf7, 0x15, 0x88,
//                                                0x09, 0xcf, 0x4f, 0x3c};
//    static hsm_state_t state;
//    HSM_DRV_Init(&state);
//    HSM_DRV_LoadPlainKey(ucPlainKey, TIMEOUT_ENCRYPTION);
//
//    do{
//        /* Every 'TASK0_DELAY' encrypt message and send it to TASK1: */
//        vTaskDelay(TASK0_DELAY);
//        switch (eEncType)
//        {
//            case ENCRYPT_NONE:
//                xQueueSend(g_tQueueHandle, (void*)&tTxData, (TickType_t)0);
//                eEncType = ENCRYPT_ECB;
//                break;
//            case ENCRYPT_ECB:
//                HSM_DRV_EncryptECB(HSM_RAM_KEY, (uint8_t*)ucMsg, MESSAGE_LENGTH, (uint8_t*)tTxData.ucEncMsg, TIMEOUT_ENCRYPTION);
//                xQueueSend(g_tQueueHandle, (void*)&tTxData, (TickType_t)0);
//                eEncType = ENCRYPT_CBC;
//                break;
//            case ENCRYPT_CBC:
//                HSM_DRV_EncryptCBC(HSM_RAM_KEY, (uint8_t*)ucMsg, MESSAGE_LENGTH, (uint8_t*)tTxData.ucInitVector, (uint8_t*)tTxData.ucEncMsg, TIMEOUT_ENCRYPTION);
//                xQueueSend(g_tQueueHandle, (void*)&tTxData, (TickType_t)0);
//                eEncType = ENCRYPT_NONE;
//                break;
//            default:
//                /* Do nothing... */
//                break;
//        }
//    }while (1);
//}
//
///* Task 1 code */
//void vTASK1(void *pvParam)
//{
//    static uint8_t ucMsg[MESSAGE_LENGTH];
//    static Data_t tRxData;
//    static EncryptionType_e eEncType = ENCRYPT_NONE;
//    status_t stat;
//
//    /* Initialize LINFLEXD peripheral for UART echo to console */
//    LINFLEXD_UART_DRV_Init(INST_LINFLEXD_UART1, &linflexd_uart1_State, &linflexd_uart1_InitConfig0);
//
//    do{
//        /* Receive message from TASK0 and decrypt: */
//        if (xQueueReceive(g_tQueueHandle, &tRxData, (TickType_t)TASK1_DELAY))
//        {
//            switch (eEncType)
//            {
//                case ENCRYPT_NONE:
//                    eEncType = ENCRYPT_ECB;
//                    break;
//                case ENCRYPT_ECB:
//                    stat = HSM_DRV_DecryptECB(HSM_RAM_KEY, (uint8_t*)tRxData.ucEncMsg, MESSAGE_LENGTH, (uint8_t*)ucMsg, TIMEOUT_ENCRYPTION);
//                    eEncType = ENCRYPT_CBC;
//                    /* Send the status to the console */
//                    if ((stat == STATUS_SUCCESS) && bufferCompare(ucMsg, (uint8_t*)PLAINTEXT, MESSAGE_LENGTH))
//                    {
//                        LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)MSG_ECB_OK, strlen(MSG_ECB_OK), TIMEOUT_ENCRYPTION);
//                    }
//                    else
//                    {
//                        LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)MSG_ERROR, strlen(MSG_ERROR), TIMEOUT_ENCRYPTION);
//                    }
//                    break;
//                case ENCRYPT_CBC:
//                    stat = HSM_DRV_DecryptCBC(HSM_RAM_KEY, (uint8_t*)tRxData.ucEncMsg, MESSAGE_LENGTH, (uint8_t*)tRxData.ucInitVector, (uint8_t*)ucMsg, TIMEOUT_ENCRYPTION);
//                    eEncType = ENCRYPT_NONE;
//                    /* Send the status to the console */
//                    if ((stat == STATUS_SUCCESS) && bufferCompare(ucMsg, (uint8_t*)PLAINTEXT, MESSAGE_LENGTH))
//                    {
//                        LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)MSG_CBC_OK, strlen(MSG_CBC_OK), TIMEOUT_ENCRYPTION);
//                    }
//                    else
//                    {
//                        LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)MSG_ERROR, strlen(MSG_ERROR), TIMEOUT_ENCRYPTION);
//                    }
//                    break;
//                default:
//                    /* Do nothing... */
//                    break;
//            }
//
//        }
//    }while (1);
//}

/*!
  \brief The main function for the project.
  \details The startup initialization sequence is the following:
 * - startup asm routine
 * - main()
*/
int main(void)
{
  /* Write your local variable definition here */

  /*** Processor Expert internal initialization. DON'T REMOVE THIS CODE!!! ***/
  #ifdef PEX_RTOS_INIT
    PEX_RTOS_INIT();                   /* Initialization of the selected RTOS. Macro is defined by the RTOS component. */
  #endif
  /*** End of Processor Expert internal initialization.                    ***/
  /* Write your code here */

    /* Initialize clocks */
    CLOCK_SYS_Init(g_clockManConfigsArr,   CLOCK_MANAGER_CONFIG_CNT,
                   g_clockManCallbacksArr, CLOCK_MANAGER_CALLBACK_CNT);
    CLOCK_SYS_UpdateConfiguration(0U, CLOCK_MANAGER_POLICY_AGREEMENT);

    /* Initialize pins */
    PINS_DRV_Init(NUM_OF_CONFIGURED_PINS, g_pin_mux_InitConfigArr);

    /* Initialize FreeRTOS: */
//    xTaskCreate(vTASK0, (const char* const)"TASK0", configMINIMAL_STACK_SIZE, (void*)0, TASK0_PRIORITY, NULL);
//    xTaskCreate(vTASK1, (const char* const)"TASK1", configMINIMAL_STACK_SIZE, (void*)1, TASK1_PRIORITY, NULL);
//    g_tQueueHandle = xQueueCreate(NOF_QUEUES, sizeof(Data_t));
    BaseType_t task_ret = xTaskCreate(vTASKBench, (const char* const)"Benchmark Task", configMINIMAL_STACK_SIZE, NULL, 1, NULL);
    DEV_ASSERT(task_ret == pdPASS);
    vTaskStartScheduler();

    for (;;)
    {
    }

  /*** Don't write any code pass this line, or it will be deleted during code generation. ***/
  /*** RTOS startup code. Macro PEX_RTOS_START is defined by the RTOS component. DON'T MODIFY THIS CODE!!! ***/
  #ifdef PEX_RTOS_START
    PEX_RTOS_START();                  /* Startup of the selected RTOS. Macro is defined by the RTOS component. */
  #endif
  /*** End of RTOS startup code.  ***/
  /*** Processor Expert end of main routine. DON'T MODIFY THIS CODE!!! ***/
  for(;;) {
    if(exit_code != 0) {
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
