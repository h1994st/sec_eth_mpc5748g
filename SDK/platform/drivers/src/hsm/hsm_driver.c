/*
 * Copyright 2017 NXP
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

/*!
 * @page misra_violations MISRA-C:2012 violations
 *
 * @section [global]
 * Violates MISRA 2012 Required Rule 1.3, Taking address of near auto variable.
 * The code is not dynamically linked. An absolute stack address is obtained
 * when taking the address of the near auto variable. Also, the called functions
 * do not store the address into variables with lifetime longer then its own call.
 *
 * @section [global]
 * Violates MISRA 2012 Required Rule 8.4, external symbol defined without a prior
 * declaration.
 * These are symbols weak symbols defined in platform startup files (.s).
 *
 * @section [global]
 * Violates MISRA 2012 Advisory Rule 8.7, External could be made static.
 * Function is defined for usage by application code.
 *
 * @section [global]
 * Violates MISRA 2012 Required Rule 10.3, Expression assigned to a narrower or different
 * essential type.
 * This is required by the conversion of a bit-field of a register into enum type.
 *
 * @section [global]
 * Violates MISRA 2012 Advisory Rule 10.5, Impermissible cast; cannot cast from
 * 'essentially unsigned' to 'essentially enum<i>'.
 * All possible values are covered by the enumeration, direct casting is used to optimize code.
 *
 * @section [global]
 * Violates MISRA 2012 Required Rule 10.8, Impermissible cast of composite
 * expression (different essential type categories).
 * This is required by the conversion of a bit-field of a register into enum type.
 *
 * @section [global]
 * Violates MISRA 2012 Required Rule 11.3, Cast performed between a pointer to object type
 * and a pointer to a different object type.
 * Void pointers are used for functions where one parameter may have a different type, based
 * on the value of another parameter. This approach is enforced by the HSM firmware implementation.
 *
 * @section [global]
 * Violates MISRA 2012 Advisory Rule 11.4, Conversion between a pointer and
 * integer type.
 * The cast is required for checking buffer address alignment.
 *
 * @section [global]
 * Violates MISRA 2012 Advisory Rule 11.5, Conversion from pointer to void to pointer to other type.
 * Void pointers are used for functions where one parameter may have a different type, based
 * on the value of another parameter. This approach is enforced by the HSM firmware implementation.
 *
 * @section [global]
 * Violates MISRA 2012 Required Rule 11.6, Cast from pointer to unsigned long.
 * The cast is required for checking buffer address alignment.
 *
 * @section [global]
 * Violates MISRA 2012 Advisory Rule 15.5, Return statement before end of function.
 * The return statement before end of function is used for simpler code structure
 * and better readability.
 */

#include "hsm_hw_access.h"


/*******************************************************************************
 * Variables
 ******************************************************************************/

/* Pointer to runtime state structure.*/
static hsm_state_t * s_hsmStatePtr = NULL;

/*******************************************************************************
 * Private Functions
 ******************************************************************************/

/* Waits on the synchronization object and updates the internal flags */
static void HSM_DRV_WaitCommandCompletion(uint32_t timeout);
/* Copies data from source to destination buffer */
static void HSM_DRV_CopyBuff(const uint8_t * srcBuff, uint8_t * destBuff, uint32_t len);
/* Performs bitwise XOR between two buffers, storing the result in the output buffer */
static void HSM_DRV_XorBuff(const uint8_t * inBuff, uint8_t * outBuff, uint32_t len);
/* Returns true if HSM is busy processing a command */
static bool HSM_IsBusy(void);

/*******************************************************************************
 * Code
 ******************************************************************************/

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_Init
 * Description   : This function initializes the internal state of the driver
 * and enables the HSM interrupt.
 *
 * Implements    : HSM_DRV_Init_Activity
 * END**************************************************************************/
status_t HSM_DRV_Init(hsm_state_t * state)
{
    /* Check that HSM is enabled and the security firmware flashed in the device */
    DEV_ASSERT(HSM_ENABLED);
    DEV_ASSERT(HSM_VALID_START_ADDR);
    /* Check the driver is initialized */
    DEV_ASSERT(state != NULL);

    status_t status;

    /* Save the driver state structure */
    s_hsmStatePtr = state;
    /* Clear the contents of the state structure */
    s_hsmStatePtr->cmdInProgress = false;
    s_hsmStatePtr->blockingCmd = false;
    s_hsmStatePtr->callback = NULL;
    s_hsmStatePtr->callbackParam = NULL;
    s_hsmStatePtr->cmd = HSM_CMD_NONE;
    s_hsmStatePtr->cmdStatus = STATUS_SUCCESS;
    s_hsmStatePtr->rngInit = false;
    s_hsmStatePtr->verifStatus = NULL;

    /* Create the synchronization semaphore */
    status = OSIF_SemaCreate(&s_hsmStatePtr->cmdComplete, 0U);
    if (status == STATUS_ERROR)
    {
        return STATUS_ERROR;
    }

    /* Enable HSM irq */
    HSM_SetInterrupt(true);

    HSM_SetInterruptExtended(true);

    INT_SYS_EnableIRQ(HSM_IRQ_NUMBER);

    INT_SYS_EnableIRQ(HSM_EXTENDED_IRQ_NUMBER);

    /* Save the firmware version */
    status = HSM_DRV_GetFwVersion(&state->fwVersion, 1U);
    if (status != STATUS_SUCCESS)
    {
        return status;
    }

    return STATUS_SUCCESS;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_Deinit
 * Description   : This function clears the internal state of the driver and
 * disables the HSM interrupt.
 *
 * Implements    : HSM_DRV_Deinit_Activity
 * END**************************************************************************/
status_t HSM_DRV_Deinit()
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Clear the contents of the state structure */
    uint8_t *clearStructPtr;
    uint8_t idx;
    clearStructPtr = (uint8_t *)s_hsmStatePtr;
    for (idx = 0; idx < sizeof(hsm_state_t); idx++)
    {
        clearStructPtr[idx] = 0;
    }

    /* Free the internal state reference */
    s_hsmStatePtr = NULL;

    /* Disable HSM irq */
    INT_SYS_DisableIRQ(HSM_IRQ_NUMBER);
    HSM_SetInterrupt(false);
    HSM_SetInterruptExtended(false);
    INT_SYS_DisableIRQ(HSM_EXTENDED_IRQ_NUMBER);

    return STATUS_SUCCESS;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_InstallCallback
 * Description   : This function installs a user callback for the command
 * complete event.
 *
 * Implements    : HSM_DRV_InstallCallback_Activity
 * END**************************************************************************/
security_callback_t HSM_DRV_InstallCallback(security_callback_t callbackFunction, void * callbackParam)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    security_callback_t currentCallback = s_hsmStatePtr->callback;
    s_hsmStatePtr->callback = callbackFunction;
    s_hsmStatePtr->callbackParam = callbackParam;

    return currentCallback;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_EncryptECB
 * Description   : This function performs the AES-128 encryption in ECB mode of
 * the input plain text buffer.
 *
 * Implements    : HSM_DRV_EncryptECB_Activity
 * END**************************************************************************/
status_t HSM_DRV_EncryptECB(hsm_key_id_t keyId, const uint8_t *plainText,
                            uint32_t length, uint8_t *cipherText, uint32_t timeout)
{
    status_t status;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    /* Launch the command with the parameters received */
    status = HSM_DRV_EncryptECBAsync(keyId, plainText, length, cipherText);

    if (status == STATUS_SUCCESS)
    {
        /* Wait for the command to complete */
        HSM_DRV_WaitCommandCompletion(timeout);

        return s_hsmStatePtr->cmdStatus;
    }
    else
    {
        return status;
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_DecryptECB
 * Description   : This function performs the AES-128 decryption in ECB mode of
 * the input cipher text buffer.
 *
 * Implements    : HSM_DRV_DecryptECB_Activity
 * END**************************************************************************/
status_t HSM_DRV_DecryptECB(hsm_key_id_t keyId, const uint8_t *cipherText,
                             uint32_t length, uint8_t *plainText, uint32_t timeout)
{
    status_t status;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    /* Launch the command with the parameters received */
    status = HSM_DRV_DecryptECBAsync(keyId, cipherText, length, plainText);

    if (status == STATUS_SUCCESS)
    {
        /* Wait for the command to complete */
        HSM_DRV_WaitCommandCompletion(timeout);

        return s_hsmStatePtr->cmdStatus;
    }
    else
    {
        return status;
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_EncryptCBC
 * Description   : This function performs the AES-128 encryption in CBC mode of
 * the input plain text buffer.
 *
 * Implements    : HSM_DRV_EncryptCBC_Activity
 * END**************************************************************************/
status_t HSM_DRV_EncryptCBC(hsm_key_id_t keyId, const uint8_t *plainText, uint32_t length,
                            const uint8_t *iv, uint8_t *cipherText, uint32_t timeout)
{
    status_t status;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    /* Launch the command with the parameters received */
    status = HSM_DRV_EncryptCBCAsync(keyId, plainText, length, iv, cipherText);

    if (status == STATUS_SUCCESS)
    {
        /* Wait for the command to complete */
        HSM_DRV_WaitCommandCompletion(timeout);

        return s_hsmStatePtr->cmdStatus;
    }
    else
    {
        return status;
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_DecryptCBC
 * Description   : This function performs the AES-128 decryption in CBC mode of
 * the input cipher text buffer.
 *
 * Implements    : HSM_DRV_DecryptCBC_Activity
 * END**************************************************************************/
status_t HSM_DRV_DecryptCBC(hsm_key_id_t keyId, const uint8_t *cipherText, uint32_t length,
                            const uint8_t* iv, uint8_t *plainText, uint32_t timeout)
{
    status_t status;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    /* Launch the command with the parameters received */
    status = HSM_DRV_DecryptCBCAsync(keyId, cipherText, length, iv, plainText);

    if (status == STATUS_SUCCESS)
    {
        /* Wait for the command to complete */
        HSM_DRV_WaitCommandCompletion(timeout);

        return s_hsmStatePtr->cmdStatus;
    }
    else
    {
        return status;
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_GenerateMAC
 * Description   : This function calculates the MAC of a given message using CMAC
 * with AES-128.
 *
 * Implements    : HSM_DRV_GenerateMAC_Activity
 * END**************************************************************************/
status_t HSM_DRV_GenerateMAC(hsm_key_id_t keyId, const uint8_t *msg,
                             uint64_t msgLen, uint8_t *mac, uint32_t timeout)
{
    status_t status;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    /* Launch the command with the parameters received */
    status = HSM_DRV_GenerateMACAsync(keyId, msg, msgLen, mac);

    if (status == STATUS_SUCCESS)
    {
        /* Wait for the command to complete */
        HSM_DRV_WaitCommandCompletion(timeout);

        return s_hsmStatePtr->cmdStatus;
    }
    else
    {
        return status;
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_VerifyMAC
 * Description   : This function verifies the MAC of a given message using CMAC
 * with AES-128.
 *
 * Implements    : HSM_DRV_VerifyMAC_Activity
 * END**************************************************************************/
status_t HSM_DRV_VerifyMAC(hsm_key_id_t keyId, const uint8_t *msg, uint64_t msgLen,
                           const uint8_t *mac, uint8_t macLen,
                           bool *verifStatus, uint32_t timeout)
{
    status_t status;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    /* Launch the command with the parameters received */
    status = HSM_DRV_VerifyMACAsync(keyId, msg, msgLen, mac, macLen, verifStatus);

    if (status == STATUS_SUCCESS)
    {
        /* Wait for the command to complete */
        HSM_DRV_WaitCommandCompletion(timeout);

        return s_hsmStatePtr->cmdStatus;
    }
    else
    {
        return status;
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_EncryptECBAsync
 * Description   : This function performs the AES-128 encryption in ECB mode of
 * the input plain text buffer, in an asynchronous manner.
 *
 * Implements    : HSM_DRV_EncryptECBAsync_Activity
 * END**************************************************************************/
status_t HSM_DRV_EncryptECBAsync(hsm_key_id_t keyId, const uint8_t *plainText,
                                 uint32_t length, uint8_t *cipherText)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check the buffer addresses are valid */
    DEV_ASSERT(plainText != NULL);
    DEV_ASSERT(cipherText != NULL);
    /* Check the buffers addresses are 32 bit aligned */
    DEV_ASSERT((((uint32_t)plainText) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)cipherText) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    /* Check the buffer length is multiple of 16 bytes */
    DEV_ASSERT((length & HSM_BUFF_LEN_CHECK_MASK) == 0U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Update the internal flags */
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_ENC_ECB;

    /* Prepare the command */
    HSM_PrepareEncryptEcbCmd(keyId, plainText, length, cipherText);

    /* Send the command to HSM */
    HSM_SendCmd();

    return STATUS_SUCCESS;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_DecryptECBAsync
 * Description   : This function performs the AES-128 decryption in ECB mode of
 * the input cipher text buffer, in an asynchronous manner.
 *
 * Implements    : HSM_DRV_DecryptECBAsync_Activity
 * END**************************************************************************/
status_t HSM_DRV_DecryptECBAsync(hsm_key_id_t keyId, const uint8_t *cipherText,
                                 uint32_t length, uint8_t *plainText)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check the buffer addresses are valid */
    DEV_ASSERT(plainText != NULL);
    DEV_ASSERT(cipherText != NULL);
    /* Check the buffers addresses are 32 bit aligned */
    DEV_ASSERT((((uint32_t)plainText) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)cipherText) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    /* Check the buffer length is multiple of 16 bytes */
    DEV_ASSERT((length & HSM_BUFF_LEN_CHECK_MASK) == 0U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Update the internal flags */
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_DEC_ECB;

    /* Prepare the command */
    HSM_PrepareDecryptEcbCmd(keyId, cipherText, length, plainText);

    /* Send the command to HSM */
    HSM_SendCmd();

    return STATUS_SUCCESS;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_EncryptCBCAsync
 * Description   : This function performs the AES-128 encryption in CBC mode of
 * the input plain text buffer, in an asynchronous manner.
 *
 * Implements    : HSM_DRV_EncryptCBCAsync_Activity
 * END**************************************************************************/
status_t HSM_DRV_EncryptCBCAsync(hsm_key_id_t keyId, const uint8_t *plainText,
                                 uint32_t length, const uint8_t *iv, uint8_t *cipherText)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check the buffer addresses are valid */
    DEV_ASSERT(plainText != NULL);
    DEV_ASSERT(cipherText != NULL);
    DEV_ASSERT(iv != NULL);
    /* Check the buffers addresses are 32 bit aligned */
    DEV_ASSERT((((uint32_t)plainText) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)cipherText) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)iv) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    /* Check the buffer length is multiple of 16 bytes */
    DEV_ASSERT((length & HSM_BUFF_LEN_CHECK_MASK) == 0U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Update the internal flags */
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_ENC_CBC;

    /* Prepare the command */
    HSM_PrepareEncryptCbcCmd(keyId, plainText, length, iv, cipherText);

    /* Send the command to HSM */
    HSM_SendCmd();

    return STATUS_SUCCESS;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_DecryptCBCAsync
 * Description   : This function performs the AES-128 decryption in CBC mode of
 * the input cipher text buffer, in an asynchronous manner.
 *
 * Implements    : HSM_DRV_DecryptCBCAsync_Activity
 * END**************************************************************************/
status_t HSM_DRV_DecryptCBCAsync(hsm_key_id_t keyId, const uint8_t *cipherText,
                                 uint32_t length, const uint8_t* iv, uint8_t *plainText)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check the buffer addresses are valid */
    DEV_ASSERT(plainText != NULL);
    DEV_ASSERT(cipherText != NULL);
    DEV_ASSERT(iv != NULL);
    /* Check the buffers addresses are 32 bit aligned */
    DEV_ASSERT((((uint32_t)plainText) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)cipherText) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)iv) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    /* Check the buffer length is multiple of 16 bytes */
    DEV_ASSERT((length & HSM_BUFF_LEN_CHECK_MASK) == 0U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Update the internal flags */
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_DEC_CBC;

    /* Prepare the command */
    HSM_PrepareDecryptCbcCmd(keyId, cipherText, length, iv, plainText);

    /* Send the command to HSM */
    HSM_SendCmd();

    return STATUS_SUCCESS;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_GenerateMACAsync
 * Description   : This function calculates the MAC of a given message using CMAC
 * with AES-128, in an asynchronous manner.
 *
 * Implements    : HSM_DRV_GenerateMACAsync_Activity
 * END**************************************************************************/
status_t HSM_DRV_GenerateMACAsync(hsm_key_id_t keyId, const uint8_t *msg,
                             uint64_t msgLen, uint8_t *mac)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check the buffer addresses are valid */
    DEV_ASSERT(msg != NULL);
    DEV_ASSERT(mac != NULL);
    /* Check the buffer address is 32 bit aligned */
    DEV_ASSERT((((uint32_t)mac) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)msg) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    /* Check the message length is valid */
    DEV_ASSERT(msgLen < HSM_MAC_MAX_MSG_LEN);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Update the internal flags */
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_GENERATE_MAC;

    /* Prepare the command */
    HSM_PrepareGenerateMacCmd(keyId, msg, msgLen, mac);

    /* Send the command to HSM */
    HSM_SendCmd();

    return STATUS_SUCCESS;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_VerifyMACAsync
 * Description   : This function verifies the MAC of a given message using CMAC
 * with AES-128, in an asynchronous manner.
 *
 * Implements    : HSM_DRV_VerifyMACAsync_Activity
 * END**************************************************************************/
status_t HSM_DRV_VerifyMACAsync(hsm_key_id_t keyId, const uint8_t *msg, uint64_t msgLen,
                                const uint8_t *mac, uint8_t macLen, bool *verifStatus)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check the addresses are valid */
    DEV_ASSERT(msg != NULL);
    DEV_ASSERT(mac != NULL);
    DEV_ASSERT(verifStatus != NULL);
    /* Check the buffer address is 32 bit aligned */
    DEV_ASSERT((((uint32_t)msg) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)mac) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    /* Check the message length is valid */
    DEV_ASSERT(msgLen < HSM_MAC_MAX_MSG_LEN);
    /* Check the mac length is valid */
    DEV_ASSERT(macLen <= 128U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Update the internal flags */
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->verifStatus = verifStatus;
    s_hsmStatePtr->cmd = HSM_CMD_VERIFY_MAC;

    /* Prepare the command */
    HSM_PrepareVerifyMacCmd(keyId, msg, msgLen, mac, macLen);

    /* Send the command to HSM */
    HSM_SendCmd();

    return STATUS_SUCCESS;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_LoadKey
 * Description   : Updates an internal key per the SHE specification.
 *
 * Implements    : HSM_DRV_LoadKey_Activity
 * END**************************************************************************/
status_t HSM_DRV_LoadKey(hsm_key_id_t keyId, const uint8_t *m1, const uint8_t *m2,
                         const uint8_t *m3, uint8_t *m4, uint8_t *m5, uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check the buffer addresses are valid */
    DEV_ASSERT(m1 != NULL);
    DEV_ASSERT(m2 != NULL);
    DEV_ASSERT(m3 != NULL);
    DEV_ASSERT(m4 != NULL);
    DEV_ASSERT(m5 != NULL);
    /* Check the buffer addresses are 32 bit aligned */
    DEV_ASSERT((((uint32_t)m1) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)m2) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)m3) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)m4) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)m5) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Update the internal flags */
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->blockingCmd = true;
    s_hsmStatePtr->cmd = HSM_CMD_LOAD_KEY;

    /* Prepare the command */
    HSM_PrepareLoadKeyCmd(keyId, m1, m2, m3, m4, m5);

    /* Send the command to HSM */
    HSM_SendCmd();
    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_LoadPlainKey
 * Description   : Updates the RAM key memory slot with a 128-bit plaintext.
 *
 * Implements    : HSM_DRV_LoadPlainKey_Activity
 * END**************************************************************************/
status_t HSM_DRV_LoadPlainKey(const uint8_t * plainKey, uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check the buffer address is valid */
    DEV_ASSERT(plainKey != NULL);
    /* Check the buffer address is 32 bit aligned */
    DEV_ASSERT((((uint32_t)plainKey) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Update the internal flags */
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->blockingCmd = true;
    s_hsmStatePtr->cmd = HSM_CMD_LOAD_PLAIN_KEY;

    /* Prepare the command */
    HSM_PrepareLoadPlainKeyCmd(plainKey);

    /* Send the command to HSM */
    HSM_SendCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_ExportRAMKey
 * Description   : Exports the RAM_KEY into a format compatible with the messages
 * used for LOAD_KEY.
 *
 * Implements    : HSM_DRV_ExportRAMKey_Activity
 * END**************************************************************************/
status_t HSM_DRV_ExportRAMKey(uint8_t *m1, uint8_t *m2, uint8_t *m3,
                              uint8_t *m4, uint8_t *m5, uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check the buffer addresses are valid */
    DEV_ASSERT(m1 != NULL);
    DEV_ASSERT(m2 != NULL);
    DEV_ASSERT(m3 != NULL);
    DEV_ASSERT(m4 != NULL);
    DEV_ASSERT(m5 != NULL);
    /* Check the buffer addresses are 32 bit aligned */
    DEV_ASSERT((((uint32_t)m1) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)m2) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)m3) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)m4) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)m5) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Update the internal flags */
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->blockingCmd = true;
    s_hsmStatePtr->cmd = HSM_CMD_EXPORT_RAM_KEY;

    /* Prepare the command */
    HSM_PrepareExportRamKeyCmd(m1, m2, m3, m4, m5);

    /* Send the command to HSM */
    HSM_SendCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_InitRNG
 * Description   : Initializes the seed for the PRNG.
 *
 * Implements    : HSM_DRV_InitRNG_Activity
 * END**************************************************************************/
status_t HSM_DRV_InitRNG(uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Update the internal flags */
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->blockingCmd = true;
    s_hsmStatePtr->cmd = HSM_CMD_INIT_RNG;

    /* Prepare the command */
    HSM_PrepareInitRngCmd();

    /* Send the command to HSM */
    HSM_SendCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    if (s_hsmStatePtr->cmdStatus == STATUS_SUCCESS)
    {
        s_hsmStatePtr->rngInit = true;
    }
    else
    {
        s_hsmStatePtr->rngInit = false;
    }

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_ExtendSeed
 * Description   : Extends the seed for the PRNG.
 *
 * Implements    : HSM_DRV_ExtendSeed_Activity
 * END**************************************************************************/
status_t HSM_DRV_ExtendSeed(const uint8_t *entropy, uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check the buffer address is valid */
    DEV_ASSERT(entropy != NULL);
    /* Check the buffer address is 32 bit aligned */
    DEV_ASSERT((((uint32_t)entropy) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* RNG must be initialized before extending the seed */
    DEV_ASSERT(s_hsmStatePtr->rngInit);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Update the internal flags */
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->blockingCmd = true;
    s_hsmStatePtr->cmd = HSM_CMD_EXTEND_SEED;

    /* Prepare the command */
    HSM_PrepareExtendPrngSeedCmd(entropy);

    /* Send the command to HSM */
    HSM_SendCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_GenerateRND
 * Description   : Generates a vector of 128 random bits.
 *
 * Implements    : HSM_DRV_GenerateRND_Activity
 * END**************************************************************************/
status_t HSM_DRV_GenerateRND(uint8_t *rnd, uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check the buffer address is valid */
    DEV_ASSERT(rnd != NULL);
    /* Check the buffer address is 32 bit aligned */
    DEV_ASSERT((((uint32_t)rnd) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* RNG must be initialized before generating the random value */
    DEV_ASSERT(s_hsmStatePtr->rngInit);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Update the internal flags */
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->blockingCmd = true;
    s_hsmStatePtr->cmd = HSM_CMD_RND;

    /* Prepare the command */
    HSM_PrepareGenerateRndCmd(rnd);

    /* Send the command to HSM */
    HSM_SendCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_GetID
 * Description   : Returns the identity (UID) and the value of the status register
 * protected by a MAC over a challenge and the data.
 *
 * Implements    : HSM_DRV_GetID_Activity
 * END**************************************************************************/
status_t HSM_DRV_GetID(const uint8_t *challenge, uint8_t *uid,
                       uint8_t *sreg, uint8_t *mac, uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check the buffer addresses are valid */
    DEV_ASSERT(challenge != NULL);
    DEV_ASSERT(uid != NULL);
    DEV_ASSERT(sreg != NULL);
    DEV_ASSERT(mac != NULL);
    /* Check the buffer addresses are 32 bit aligned */
    DEV_ASSERT((((uint32_t)challenge) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)mac) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Update the internal flags */
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->blockingCmd = true;
    s_hsmStatePtr->cmd = HSM_CMD_GET_ID;

    /* Prepare the command */
    HSM_PrepareGetIdCmd(challenge, uid, sreg, mac);

    /* Send the command to HSM */
    HSM_SendCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_GenerateTRND
 * Description   :  Generates a vector of 128 random bits using TRNG.
 *
 * Implements    : HSM_DRV_GenerateTRND_Activity
 * END**************************************************************************/
status_t HSM_DRV_GenerateTRND(uint8_t *trnd, uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check the buffer address is valid */
    DEV_ASSERT(trnd != NULL);
    /* Check the buffer address is 32 bit aligned */
    DEV_ASSERT((((uint32_t)trnd) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Update the internal flags */
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->blockingCmd = true;
    s_hsmStatePtr->cmd = HSM_CMD_TRNG_RND;

    /* Prepare the command */
    HSM_PrepareGenerateTrndCmd(trnd);

    /* Send the command to HSM */
    HSM_SendCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_SecureBoot
 * Description   : This function executes the SHE secure boot protocol.
 *
 * Implements    : HSM_DRV_SecureBoot_Activity
 * END**************************************************************************/
status_t HSM_DRV_SecureBoot(uint32_t bootImageSize, const uint8_t *bootImagePtr,
                            uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check the pointer is valid */
    DEV_ASSERT(bootImagePtr != NULL);
    /* Check the boot image address is 32 bit aligned */
    DEV_ASSERT((((uint32_t)bootImagePtr) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Update the internal flags */
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->blockingCmd = true;
    s_hsmStatePtr->cmd = HSM_CMD_SECURE_BOOT;

    /* Prepare the command */
    HSM_PrepareSecureBootCmd(bootImageSize, bootImagePtr);

    /* Send the command to HSM */
    HSM_SendCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_BootFailure
 * Description   : This function signals a failure detected during later stages
 * of the boot process.
 *
 * Implements    : HSM_DRV_BootFailure_Activity
 * END**************************************************************************/
status_t HSM_DRV_BootFailure(uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Update the internal flags */
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->blockingCmd = true;
    s_hsmStatePtr->cmd = HSM_CMD_BOOT_FAILURE;

    /* Prepare the command */
    HSM_PrepareBootFailureCmd();

    /* Send the command to HSM */
    HSM_SendCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_BootOK
 * Description   : This function marks a successful boot verification during
 * later stages of the boot process.
 *
 * Implements    : HSM_DRV_BootOK_Activity
 * END**************************************************************************/
status_t HSM_DRV_BootOK(uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Update the internal flags */
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->blockingCmd = true;
    s_hsmStatePtr->cmd = HSM_CMD_BOOT_OK;

    /* Prepare the command */
    HSM_PrepareBootOkCmd();

    /* Send the command to HSM */
    HSM_SendCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_DbgChal
 * Description   : This function obtains a random number which the user shall
 * use along with the MASTER_ECU_KEY and UID to return an authorization request.
 *
 * Implements    : HSM_DRV_DbgChal_Activity
 * END**************************************************************************/
status_t HSM_DRV_DbgChal(uint8_t *challenge, uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check the pointer is valid */
    DEV_ASSERT(challenge != NULL);
    /* Check the boot image address is 32 bit aligned */
    DEV_ASSERT((((uint32_t)challenge) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Update the internal flags */
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->blockingCmd = true;
    s_hsmStatePtr->cmd = HSM_CMD_DBG_CHAL;

    /* Prepare the command */
    HSM_PrepareDbgChalCmd(challenge);

    /* Send the command to HSM */
    HSM_SendCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_DbgAuth
 * Description   : This function erases all user keys and enables internal
 * debugging if the authorization is confirmed by HSM.
 *
 * Implements    : HSM_DRV_DbgAuth_Activity
 * END**************************************************************************/
status_t HSM_DRV_DbgAuth(const uint8_t *authorization, uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check the pointer is valid and aligned */
    DEV_ASSERT(authorization != NULL);
    DEV_ASSERT((((uint32_t)authorization) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Update the internal flags */
    s_hsmStatePtr->blockingCmd = true;
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_DBG_AUTH;

    /* Prepare the command */
    HSM_PrepareDbgAuthCmd(authorization);

    /* Send the command to HSM */
    HSM_SendCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_MPCompress
 * Description   : This function implements a Miyaguchi-Preneel compression
 * in software.
 *
 * Implements    : HSM_DRV_MPCompress_Activity
 * END**************************************************************************/
status_t HSM_DRV_MPCompress(const uint8_t * msg, uint16_t msgLen,
                            uint8_t * mpCompress, uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check the buffer addresses are valid */
    DEV_ASSERT(msg != NULL);
    DEV_ASSERT(mpCompress != NULL);

    uint32_t block = 0U;
    uint8_t key[16] = {0U, };
    uint32_t msgLenInBytes;
    status_t stat = STATUS_SUCCESS;

    /* Determine the number of bytes to compress (multiply by 16) */
    msgLenInBytes = (uint32_t)(msgLen << 4U);

    /* Perform Miyaguchi-Preneel compression */
    while (block < msgLenInBytes)
    {
        /* Use RAM key */
        stat = HSM_DRV_LoadPlainKey(key, timeout);
        if (stat != STATUS_SUCCESS)
        {
            return stat;
        }

        /* Encrypt this block using the previous compression output */
        stat = HSM_DRV_EncryptECB(HSM_RAM_KEY, &msg[block], 16U, mpCompress, timeout);
        if (stat != STATUS_SUCCESS)
        {
            return stat;
        }

        /* XOR message block, ciphertext and result from previous step */
        HSM_DRV_XorBuff(key, mpCompress, 16U);
        HSM_DRV_XorBuff(&msg[block], mpCompress, 16U);

        /* Update the key to be used for next step */
        HSM_DRV_CopyBuff(mpCompress, key, 16);

        block += 16U;
    }

    return stat;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_GetFwVersion
 * Description   : This function returns the HSM firmware version.
 *
 * Implements    : HSM_DRV_GetFwVersion_Activity
 * END**************************************************************************/
status_t HSM_DRV_GetFwVersion(uint32_t *version, uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check the address is aligned */
    DEV_ASSERT((((uint32_t)version) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    if (s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Set the blocking flag so the synchronization semaphore is posted in the ISR */
    s_hsmStatePtr->blockingCmd = true;
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_GET_VER;

    /* Prepare the command */
    HSM_PrepareCommand(HSM_CMD_GET_VER, (uint32_t)version, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);

    /* Send the command to HSM */
    HSM_SendCmd();

    /* Wait for the cancelled command to complete */
    (void)OSIF_SemaWait(&s_hsmStatePtr->cmdComplete, timeout);

    /* Clear the blocking flag */
    s_hsmStatePtr->blockingCmd = false;

    return STATUS_SUCCESS;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_GetAsyncCmdStatus
 * Description   : This function checks the status of the execution of an
 * asynchronous command. If the command is still in progress, returns STATUS_BUSY.
 *
 * Implements    : HSM_DRV_GetAsyncCmdStatus_Activity
 * END**************************************************************************/
status_t HSM_DRV_GetAsyncCmdStatus(void)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    if (!s_hsmStatePtr->cmdInProgress)
    {
        return s_hsmStatePtr->cmdStatus;
    }

    return STATUS_BUSY;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_CancelCommand
 * Description   : Cancels a previously initiated command.
 *
 * Implements    : HSM_DRV_CancelCommand_Activity
 * END**************************************************************************/
status_t HSM_DRV_CancelCommand(void)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Disable the extended command interrupt, so the semaphore
     * is not posted twice for the same command */
    HSM_SetInterruptExtended(false);

    /* Check if there is a command in progress */
    if (!s_hsmStatePtr->cmdInProgress)
    {
        HSM_SetInterruptExtended(true);
        return STATUS_SUCCESS;
    }

    /* Set the blocking flag so the synchronization semaphore is posted in the ISR */
    s_hsmStatePtr->blockingCmd = true;
    /* Update the busy flag */
    s_hsmStatePtr->cmdInProgress = true;
    /* Prepare the command */
    HSM_PrepareCancelCmd();
    /* Send the command to HSM */
    HSM_SendCmd();
    /* Wait for CANCEL command completion (this one should not time out) */
    (void)OSIF_SemaWait(&s_hsmStatePtr->cmdComplete, OSIF_WAIT_FOREVER);

    /* Clear the blocking flag */
    s_hsmStatePtr->blockingCmd = false;
    /* Re-enable extended interrupts */
    HSM_SetInterruptExtended(true);

    return STATUS_SUCCESS;
}


/*********** EXTENDED SYMMETRIC FUNCTIONS *****************/

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_EncryptGCMAsync
 * Description   : This function performs the AES-128 encryption in GCM mode (Galois/Counter Mode) of
 * the input plain text buffer asynchronously.
 *
 * Implements    : HSM_DRV_EncryptGCMAsync_Activity
 * END**************************************************************************/
status_t HSM_DRV_EncryptGCMAsync(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                                 const uint8_t *authData, uint32_t plainTextLen, const uint8_t *plainText,
                                 uint8_t *cipherText, uint32_t tagLen, uint8_t *tag)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check whether buffers are valid */
    DEV_ASSERT(iv != NULL);
    DEV_ASSERT(authData != NULL);
    DEV_ASSERT(plainText != NULL);
    DEV_ASSERT(cipherText != NULL);
    DEV_ASSERT(tag != NULL);

    /* Check memory alignment */
    DEV_ASSERT((((uint32_t)iv)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)authData)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)plainText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)cipherText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)tag)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check if key index is from AES symmetric key group from both catalogs */
    DEV_ASSERT(HSM_KEY_ID_GROUP(keyId) == 0x00U);

    /* Tag length must be between 4 bytes and 16 bytes */
    DEV_ASSERT((tagLen >= 4U) && (tagLen <= 16U));

    /* Length of input IV (in bytes) must be 12 */
    DEV_ASSERT(ivLen == 12U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_SYM_AES_GCM_ENC;

    /* Write HSM structure parameters */
    HSM_PrepareEncryptGCM((uint32_t)keyId, ivLen, iv, authDataLen, authData,
                          plainTextLen, plainText, cipherText, tagLen, tag);

    /* Send the command to HSM */
    HSM_SendCmd();

    return STATUS_SUCCESS;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_EncryptGCM
 * Description   : This function performs the AES-128 encryption in GCM mode (Galois/Counter Mode) of
 * the input plain text buffer.
 *
 * Implements    : HSM_DRV_EncryptGCM_Activity
 * END**************************************************************************/
status_t HSM_DRV_EncryptGCM(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                            const uint8_t *authData, uint32_t plainTextLen, const uint8_t *plainText,
                            uint8_t *cipherText, uint32_t tagLen, uint8_t *tag, uint32_t timeout)
{
    status_t status;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    /* Launch the command with the parameters received */
    status = HSM_DRV_EncryptGCMAsync(keyId, ivLen, iv, authDataLen, authData, plainTextLen,
                                       plainText, cipherText, tagLen, tag);

    if (status == STATUS_SUCCESS)
    {
        /* Wait for the command to complete */
        HSM_DRV_WaitCommandCompletion(timeout);

        return s_hsmStatePtr->cmdStatus;
    }
    else
    {
        return status;
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_EncryptCCMAsync
 * Description   : This function performs the AES-128 encryption in CCM mode (Counter with CBC-MAC Mode) of
 * the input plain text buffer asynchronously.
 *
 * Implements    : HSM_DRV_EncryptCCMAsync_Activity
 * END**************************************************************************/
status_t HSM_DRV_EncryptCCMAsync(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                                 const uint8_t *authData, uint32_t plainTextLen, const uint8_t *plainText,
                                 uint8_t *cipherText, uint32_t tagLen, uint8_t *tag)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check whether buffers are valid */
    DEV_ASSERT(iv != NULL);
    DEV_ASSERT(authData != NULL);
    DEV_ASSERT(plainText != NULL);
    DEV_ASSERT(cipherText != NULL);
    DEV_ASSERT(tag != NULL);

    /* Check memory alignment */
    DEV_ASSERT((((uint32_t)iv)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)authData)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)plainText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)cipherText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)tag)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check if key index is from AES symmetric key group from both catalogs */
    DEV_ASSERT(HSM_KEY_ID_GROUP(keyId) == 0x00U);

    /* Tag length must be between 4 bytes and 16 bytes */
    DEV_ASSERT((tagLen >= 4U) && (tagLen <= 16U));

    /* IV length must be between 7 bytes and 13 bytes */
    DEV_ASSERT((ivLen >= 7U) && (ivLen <= 13U));

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_SYM_AES_CCM_ENC;

    /* Write HSM structure parameters */
    HSM_PrepareEncryptCCM((uint32_t)keyId, ivLen, iv, authDataLen, authData, plainTextLen,
                          plainText, cipherText, tagLen, tag);

    /* Send the command to HSM */
    HSM_SendCmd();

    return STATUS_SUCCESS;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_EncryptCCM
 * Description   : This function performs the AES-128 encryption in CCM mode (Counter with CBC-MAC Mode) of
 * the input plain text buffer.
 *
 * Implements    : HSM_DRV_EncryptCCM_Activity
 * END**************************************************************************/
status_t HSM_DRV_EncryptCCM(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                            const uint8_t *authData, uint32_t plainTextLen, const uint8_t *plainText,
                            uint8_t *cipherText, uint32_t tagLen, uint8_t *tag, uint32_t timeout)
{
    status_t status;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    /* Launch the command with the parameters received */
    status = HSM_DRV_EncryptCCMAsync(keyId, ivLen, iv, authDataLen, authData, plainTextLen, plainText,
                                     cipherText, tagLen, tag);

    if (status == STATUS_SUCCESS)
    {
        /* Wait for the command to complete */
        HSM_DRV_WaitCommandCompletion(timeout);

        return s_hsmStatePtr->cmdStatus;
    }
    else
    {
        return status;
    }
}

/*FUNCTION**********************************************************************
 *
  Function Name : HSM_DRV_EncryptOFBAsync
 * Description  : This function performs the AES-128 encryption in OFB mode (Output Feedback mode) of
 * the input plain text buffer asynchronously.
 *
 * Implements    : HSM_DRV_EncryptOFBAsync_Activity
 * END**************************************************************************/
status_t HSM_DRV_EncryptOFBAsync(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length,
                                 const uint8_t *plainText, uint8_t *cipherText)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check whether buffers are valid */
    DEV_ASSERT(iv != NULL);
    DEV_ASSERT(plainText != NULL);
    DEV_ASSERT(cipherText != NULL);

    /* Check memory alignment */
    DEV_ASSERT((((uint32_t)iv)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)plainText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)cipherText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check if key index is from AES symmetric key group from both catalogs */
    DEV_ASSERT(HSM_KEY_ID_GROUP(keyId) == 0x00U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_SYM_AES_OFB_ENC;

    /* Write HSM structure parameters */
    HSM_PrepareEncryptOFB((uint32_t)keyId, iv, length, plainText, cipherText);

    /* Send the command to HSM */
    HSM_SendCmd();

    return STATUS_SUCCESS;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_EncryptOFB
 * Description   : This function performs the AES-128 encryption in OFB mode (Output Feedback mode) of
 * the input plain text buffer.
 *
 * Implements    : HSM_DRV_EncryptOFB_Activity
 * END**************************************************************************/
status_t HSM_DRV_EncryptOFB(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length,
                            const uint8_t *plainText, uint8_t *cipherText, uint32_t timeout)
{
    status_t status;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    /* Launch the command with the parameters received */
    status = HSM_DRV_EncryptOFBAsync(keyId, iv, length, plainText, cipherText);

    if (status == STATUS_SUCCESS)
    {
        /* Wait for the command to complete */
        HSM_DRV_WaitCommandCompletion(timeout);

        return s_hsmStatePtr->cmdStatus;
    }
    else
    {
        return status;
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_EncryptCTRAsync
 * Description   : This function performs the AES-128 encryption in CTR mode (Counter Mode) of
 * the input plain text buffer asynchronously.
 *
 * Implements    : HSM_DRV_EncryptCTRAsync_Activity
 * END**************************************************************************/
status_t HSM_DRV_EncryptCTRAsync(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length,
                                 const uint8_t *plainText, uint8_t *cipherText)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check whether buffers are valid */
    DEV_ASSERT(iv != NULL);
    DEV_ASSERT(plainText != NULL);
    DEV_ASSERT(cipherText != NULL);

    /* Check memory alignment */
    DEV_ASSERT((((uint32_t)iv)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)plainText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)cipherText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check if key index is from AES symmetric key group from both catalogs */
    DEV_ASSERT(HSM_KEY_ID_GROUP(keyId) == 0x00U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_SYM_AES_CTR_ENC;

    /* Write HSM structure parameters */
    HSM_PrepareEncryptCTR((uint32_t)keyId, iv, length, plainText, cipherText);

    /* Send the command to HSM */
    HSM_SendCmd();

    return STATUS_SUCCESS;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_EncryptCTR
 * Description   : This function performs the AES-128 encryption in CTR mode (Counter Mode) of
 * the input plain text buffer.
 *
 * Implements    : HSM_DRV_EncryptCTR_Activity
 * END**************************************************************************/
status_t HSM_DRV_EncryptCTR(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length,
                            const uint8_t *plainText, uint8_t *cipherText, uint32_t timeout)
{
    status_t status;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    /* Launch the command with the parameters received */
    status = HSM_DRV_EncryptCTRAsync(keyId, iv, length, plainText, cipherText);

    if (status == STATUS_SUCCESS)
    {
        /* Wait for the command to complete */
        HSM_DRV_WaitCommandCompletion(timeout);

        return s_hsmStatePtr->cmdStatus;
    }
    else
    {
        return status;
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_EncryptCFBAsync
 * Description   : This function performs the AES-128 encryption in CFB mode (Cipher Feedback mode) of
 * the input plain text buffer asynchronously.
 *
 * Implements    : HSM_DRV_EncryptCFBAsync_Activity
 * END**************************************************************************/
status_t HSM_DRV_EncryptCFBAsync(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length,
                                 const uint8_t *plainText, uint8_t *cipherText)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check whether buffers are valid */
    DEV_ASSERT(iv != NULL);
    DEV_ASSERT(plainText != NULL);
    DEV_ASSERT(cipherText != NULL);

    /* Check memory alignment */
    DEV_ASSERT((((uint32_t)iv)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)plainText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)cipherText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check if key index is from AES symmetric key group from both catalogs */
    DEV_ASSERT(HSM_KEY_ID_GROUP(keyId) == 0x00U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_SYM_AES_CFB_ENC;

    /* Write HSM structure parameters */
    HSM_PrepareEncryptCFB((uint32_t)keyId, iv, length, plainText, cipherText);

    /* Send the command to HSM */
    HSM_SendCmd();

    return STATUS_SUCCESS;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_EncryptCFB
 * Description   : This function performs the AES-128 encryption in CFB mode (Cipher Feedback mode) of
 * the input plain text buffer.
 *
 * Implements    : HSM_DRV_EncryptCFB_Activity
 * END**************************************************************************/
status_t HSM_DRV_EncryptCFB(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length,
                            const uint8_t *plainText, uint8_t *cipherText, uint32_t timeout)
{
    status_t status;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    /* Launch the command with the parameters received */
    status = HSM_DRV_EncryptCFBAsync(keyId, iv, length, plainText, cipherText);

    if (status == STATUS_SUCCESS)
    {
        /* Wait for the command to complete */
        HSM_DRV_WaitCommandCompletion(timeout);

        return s_hsmStatePtr->cmdStatus;
    }
    else
    {
        return status;
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_EncryptXTSAsync
 * Description   : This function performs the AES-128 encryption in XTS mode of
 * the input plain text buffer asynchronously.
 *
 * Implements    : HSM_DRV_EncryptXTSAsync_Activity
 * END**************************************************************************/
status_t HSM_DRV_EncryptXTSAsync(hsm_key_id_t keyId1, hsm_key_id_t keyId2, const uint8_t *iv,
                                 uint32_t length, const uint8_t *plainText, uint8_t *cipherText)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check whether buffers are valid */
    DEV_ASSERT(iv != NULL);
    DEV_ASSERT(plainText != NULL);
    DEV_ASSERT(cipherText != NULL);

    /* Check memory alignment */
    DEV_ASSERT((((uint32_t)iv)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)plainText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)cipherText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check if keys indexes are from AES symmetric key group from both catalogs */
    DEV_ASSERT(HSM_KEY_ID_GROUP(keyId1) == 0x00U);
    DEV_ASSERT(HSM_KEY_ID_GROUP(keyId2) == 0x00U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_SYM_AES_XTS_ENC;

    /* Write HSM structure parameters */
    HSM_PrepareEncryptXTS((uint32_t)keyId1,(uint32_t)keyId2, iv, length, plainText, cipherText);

    /* Send the command to HSM */
    HSM_SendCmd();

    return STATUS_SUCCESS;

}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_EncryptXTS
 * Description   : This function performs the AES-128 encryption in XTS mode of
 * the input plain text buffer.
 *
 * Implements    : HSM_DRV_EncryptXTS_Activity
 * END**************************************************************************/
status_t HSM_DRV_EncryptXTS(hsm_key_id_t keyId1, hsm_key_id_t keyId2, const uint8_t *iv, uint32_t length,
                            const uint8_t *plainText, uint8_t *cipherText, uint32_t timeout)
{
    status_t status;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    /* Launch the command with the parameters received */
    status = HSM_DRV_EncryptXTSAsync(keyId1, keyId2, iv, length, plainText, cipherText);

    if (status == STATUS_SUCCESS)
    {
        /* Wait for the command to complete */
        HSM_DRV_WaitCommandCompletion(timeout);

        return s_hsmStatePtr->cmdStatus;
    }
    else
    {
        return status;
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_DecryptGCMAsync
 * Description   : This function performs the AES-128 decryption in GCM mode (Galois/Counter Mode) of
 * the input plain text buffer asynchronously.
 *
 * Implements    : HSM_DRV_DecryptGCMAsync_Activity
 * END**************************************************************************/
status_t HSM_DRV_DecryptGCMAsync(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                                 const uint8_t *authData, uint32_t cipherTextLen, const uint8_t *cipherText,
                                 uint8_t *decryptedText, uint32_t tagLen, const uint8_t *tag, bool *authStatus)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check whether buffers are valid */
    DEV_ASSERT(iv != NULL);
    DEV_ASSERT(authData != NULL);
    DEV_ASSERT(cipherText != NULL);
    DEV_ASSERT(decryptedText != NULL);
    DEV_ASSERT(tag != NULL);
    DEV_ASSERT(authStatus != NULL);

    /* Check memory alignment */
    DEV_ASSERT((((uint32_t)iv)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)authData)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)cipherText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)decryptedText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)tag)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check if key index is part of AES-symmetric keys groups in NVM and RAM catalog*/
    DEV_ASSERT(HSM_KEY_ID_GROUP(keyId) == 0x00U);

    /* IV length must be 12 bytes */
    DEV_ASSERT(ivLen == 12U);

    /* Tag length must be in 4 - 16 bytes range */
    DEV_ASSERT((tagLen >= 4U) && (tagLen <= 16U));

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_SYM_AES_GCM_DEC;
    s_hsmStatePtr->verifStatus = authStatus;

    /* Write HSM structure parameters */
    HSM_PrepareDecryptGCM((uint32_t)keyId, ivLen, iv, authDataLen, authData, cipherTextLen, cipherText,
                          decryptedText, tagLen, tag);

    /* Send the command to HSM */
    HSM_SendCmd();

    return STATUS_SUCCESS;

}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_DecryptGCM
 * Description   : This function performs the AES-128 decryption in GCM mode (Galois/Counter Mode) of
 * the input plain text buffer.
 *
 * Implements    : HSM_DRV_DecryptGCM_Activity
 * END**************************************************************************/
status_t HSM_DRV_DecryptGCM(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                            const uint8_t *authData, uint32_t cipherTextLen, const uint8_t *cipherText,
                            uint8_t *decryptedText, uint32_t tagLen, const uint8_t *tag, bool *authStatus,
                            uint32_t timeout)
{
    status_t status_hsm;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    /* Launch the command with the parameters received */
    status_hsm =  HSM_DRV_DecryptGCMAsync(keyId, ivLen, iv, authDataLen, authData, cipherTextLen,
                                          cipherText, decryptedText, tagLen, tag, authStatus);

    if (status_hsm == STATUS_SUCCESS)
    {
        /* Wait for the command to complete */
        HSM_DRV_WaitCommandCompletion(timeout);

        return s_hsmStatePtr->cmdStatus;
    }
    else
    {
        return status_hsm;
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_DecryptCCMAsync
 * Description   : This function performs the AES-128 decryption in CCM mode (Counter with CBC-MAC Mode) of
 * the input plain text buffer asynchronously.
 *
 * Implements    : HSM_DRV_DecryptCCMAsync_Activity
 * END**************************************************************************/
status_t HSM_DRV_DecryptCCMAsync(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                                 const uint8_t *authData, uint32_t cipherTextLen, const uint8_t *cipherText,
                                 uint8_t *decryptedText, uint32_t tagLen, const uint8_t *tag, bool *authStatus)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check whether buffers are valid */
    DEV_ASSERT(iv != NULL);
    DEV_ASSERT(authData != NULL);
    DEV_ASSERT(cipherText != NULL);
    DEV_ASSERT(decryptedText != NULL);
    DEV_ASSERT(tag != NULL);
    DEV_ASSERT(authStatus != NULL);

    /* Check memory alignment */
    DEV_ASSERT((((uint32_t)iv)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)authData)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)cipherText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)decryptedText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)tag)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check if key index is part of AES-symmetric keys groups in NVM and RAM catalog*/
    DEV_ASSERT(HSM_KEY_ID_GROUP(keyId) == 0x00U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_SYM_AES_CCM_DEC;
    s_hsmStatePtr->verifStatus = authStatus;

    /* Write HSM structure parameters */
    HSM_PrepareDecryptCCM((uint32_t)keyId, ivLen, iv, authDataLen, authData, cipherTextLen, cipherText,
                           decryptedText, tagLen, tag);

    /* Send the command to HSM */
    HSM_SendCmd();

    return STATUS_SUCCESS;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_DecryptCCM
 * Description   : This function performs the AES-128 decryption in CCM mode (Counter with CBC-MAC Mode) of
 * the input plain text buffer.
 *
 * Implements    : HSM_DRV_DecryptCCM_Activity
 * END**************************************************************************/
status_t HSM_DRV_DecryptCCM(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                            const uint8_t *authData, uint32_t cipherTextLen, const uint8_t *cipherText,
                            uint8_t *decryptedText, uint32_t tagLen, const uint8_t *tag, bool *authStatus,
                            uint32_t timeout)
{
    status_t status_hsm;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    /* Launch the command with the parameters received */
    status_hsm =  HSM_DRV_DecryptCCMAsync(keyId, ivLen, iv, authDataLen, authData, cipherTextLen, cipherText,
                                          decryptedText, tagLen, tag, authStatus);

    if (status_hsm == STATUS_SUCCESS)
    {
        /* Wait for the command to complete */
        HSM_DRV_WaitCommandCompletion(timeout);

        return s_hsmStatePtr->cmdStatus;
    }
    else
    {
        return status_hsm;
    }
}

/*FUNCTION**********************************************************************
 *
  Function Name : HSM_DRV_DecryptOFBAsync
 * Description  : This function performs the AES-128 decryption in OFB mode (Output Feedback mode) of
 * the input plain text buffer asynchronously.
 *
 * Implements    : HSM_DRV_DecryptOFBAsync_Activity
 * END**************************************************************************/
status_t HSM_DRV_DecryptOFBAsync(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length,
                                 const uint8_t *cipherText, uint8_t *decryptedText)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check whether buffers are valid */
    DEV_ASSERT(iv != NULL);
    DEV_ASSERT(decryptedText != NULL);
    DEV_ASSERT(cipherText != NULL);

    /* Check memory alignment */
    DEV_ASSERT((((uint32_t)iv)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)cipherText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)decryptedText) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check if key index is part of AES-symmetric keys groups in NVM and RAM catalog */
    DEV_ASSERT(HSM_KEY_ID_GROUP(keyId) == 0x00U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_SYM_AES_OFB_DEC;

    /* Write HSM structure parameters */
    HSM_PrepareDecryptOFB((uint32_t)keyId, iv, length, cipherText, decryptedText);

    /* Send the command to HSM */
    HSM_SendCmd();

    return STATUS_SUCCESS;
}

/*FUNCTION**********************************************************************
 *
  Function Name : HSM_DRV_DecryptOFB
 * Description  : This function performs the AES-128 decryption in OFB mode (Output Feedback mode) of
 * the input plain text buffer.
 *
 * Implements    : HSM_DRV_DecryptOFB_Activity
 * END**************************************************************************/
status_t HSM_DRV_DecryptOFB(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length,
                            const uint8_t *cipherText, uint8_t *decryptedText, uint32_t timeout)
{
    status_t status_hsm;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    /* Launch the command with the parameters received */
    status_hsm =  HSM_DRV_DecryptOFBAsync(keyId, iv, length, cipherText, decryptedText);

    if (status_hsm == STATUS_SUCCESS)
    {
        /* Wait for the command to complete */
        HSM_DRV_WaitCommandCompletion(timeout);

        return s_hsmStatePtr->cmdStatus;
    }
    else
    {
        return status_hsm;
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_DecryptCTRAsync
 * Description   : This function performs the AES-128 decryption in CTR mode (Counter Mode) of
 * the input plain text buffer asynchronously.
 *
 * Implements    : HSM_DRV_DecryptCTRAsync_Activity
 * END**************************************************************************/
status_t HSM_DRV_DecryptCTRAsync(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length,
                                 const uint8_t *cipherText, uint8_t *decryptedText)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check whether buffers are valid */
    DEV_ASSERT(iv != NULL);
    DEV_ASSERT(decryptedText != NULL);
    DEV_ASSERT(cipherText != NULL);

    /* Check memory alignment */
    DEV_ASSERT((((uint32_t)iv)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)cipherText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)decryptedText) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check if key index is part of AES-symmetric keys groups in NVM and RAM catalog */
    DEV_ASSERT(HSM_KEY_ID_GROUP(keyId) == 0x00U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_SYM_AES_CTR_DEC;

    /* Write HSM structure parameters */
    HSM_PrepareDecryptCTR((uint32_t)keyId, iv, length, cipherText, decryptedText);

    /* Send the command to HSM */
    HSM_SendCmd();

    return STATUS_SUCCESS;

}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_DecryptCTR
 * Description   : This function performs the AES-128 decryption in CTR mode (Counter Mode) of
 * the input plain text buffer.
 *
 * Implements    : HSM_DRV_DecryptCTR_Activity
 * END**************************************************************************/
status_t HSM_DRV_DecryptCTR(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length,
                            const uint8_t *cipherText, uint8_t *decryptedText, uint32_t timeout)
{
    status_t status_hsm;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    /* Launch the command with the parameters received */
    status_hsm =  HSM_DRV_DecryptCTRAsync(keyId, iv, length, cipherText, decryptedText);

    if (status_hsm == STATUS_SUCCESS)
    {
        /* Wait for the command to complete */
        HSM_DRV_WaitCommandCompletion(timeout);

        return s_hsmStatePtr->cmdStatus;
    }
    else
    {
        return status_hsm;
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_DecryptCFBAsync
 * Description   : This function performs the AES-128 decryption in CFB mode (Cipher Feedback mode) of
 * the input plain text buffer.
 *
 * Implements    : HSM_DRV_DecryptCFBAsync_Activity
 * END**************************************************************************/
status_t HSM_DRV_DecryptCFBAsync(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length,
                                 const uint8_t *cipherText, uint8_t *decryptedText)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check whether buffers are valid */
    DEV_ASSERT(iv != NULL);
    DEV_ASSERT(decryptedText != NULL);
    DEV_ASSERT(cipherText != NULL);

    /* Check memory alignment */
    DEV_ASSERT((((uint32_t)iv)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)cipherText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)decryptedText) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check if key index is part of AES-symmetric keys groups in NVM and RAM catalog */
    DEV_ASSERT(HSM_KEY_ID_GROUP(keyId) == 0x00U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_SYM_AES_CFB_DEC;

    /* Write HSM structure parameters */
    HSM_PrepareDecryptCFB((uint32_t)keyId, iv, length, cipherText, decryptedText);

    /* Send the command to HSM */
    HSM_SendCmd();

    return STATUS_SUCCESS;

}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_DecryptCFB
 * Description   : This function performs the AES-128 decryption in CFB mode (Cipher Feedback mode) of
 * the input plain text buffer.
 *
 * Implements    : HSM_DRV_DecryptCFB_Activity
 * END**************************************************************************/
status_t HSM_DRV_DecryptCFB(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length,
                            const uint8_t *cipherText, uint8_t *decryptedText, uint32_t timeout)
{
    status_t status_hsm;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    /* Launch the command with the parameters received */
    status_hsm = HSM_DRV_DecryptCFBAsync(keyId, iv, length, cipherText, decryptedText);

    if (status_hsm == STATUS_SUCCESS)
    {
        /* Wait for the command to complete */
        HSM_DRV_WaitCommandCompletion(timeout);

        return s_hsmStatePtr->cmdStatus;
    }
    else
    {
        return status_hsm;
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_DecryptXTSAsync
 * Description   : This function performs the AES-128 decryption in XTS mode of
 * the input plain text buffer asynchronously.
 *
 * Implements    : HSM_DRV_DecryptXTSAsync_Activity
 * END**************************************************************************/
status_t HSM_DRV_DecryptXTSAsync(hsm_key_id_t keyId1, hsm_key_id_t keyId2, const uint8_t *iv,
                                 uint32_t length, const uint8_t *cipherText, uint8_t *decryptedText)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check whether buffers are valid */
    DEV_ASSERT(iv != NULL);
    DEV_ASSERT(decryptedText != NULL);
    DEV_ASSERT(cipherText != NULL);

    /* Check memory alignment */
    DEV_ASSERT((((uint32_t)iv)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)cipherText)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)decryptedText) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check if key index is part of AES-symmetric keys groups in NVM and RAM catalog */
    DEV_ASSERT(HSM_KEY_ID_GROUP(keyId1) == 0x00U);
    DEV_ASSERT(HSM_KEY_ID_GROUP(keyId2) == 0x00U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_SYM_AES_XTS_DEC;

    /* Write HSM structure parameters */
    HSM_PrepareDecryptXTS((uint32_t)keyId1, (uint32_t)keyId2, iv, length, cipherText, decryptedText);

    /* Send the command to HSM */
    HSM_SendCmd();

    return STATUS_SUCCESS;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_DecryptXTS
 * Description   : This function performs the AES-128 decryption in XTS mode of
 * the input plain text buffer.
 *
 * Implements    : HSM_DRV_DecryptXTS_Activity
 * END**************************************************************************/
status_t HSM_DRV_DecryptXTS(hsm_key_id_t keyId1, hsm_key_id_t keyId2, const uint8_t *iv, uint32_t length,
                            const uint8_t *cipherText, uint8_t *decryptedText, uint32_t timeout)
{
    status_t status_hsm;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    /* Launch the command with the parameters received */
    status_hsm =  HSM_DRV_DecryptXTSAsync(keyId1, keyId2, iv, length, cipherText, decryptedText);

    if (status_hsm == STATUS_SUCCESS)
    {
        /* Wait for the command to complete */
        HSM_DRV_WaitCommandCompletion(timeout);

        return s_hsmStatePtr->cmdStatus;
    }
    else
    {
        return status_hsm;
    }
}

/*********** ASYMMETRIC FUNCTIONS *****************/

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_RSA_EncryptAsync
 * Description   : This function will perform pad/encode of the plaintext in either OAEP or PKCS
 * format using SHA 256 as the hashing algorithm. It will apply RSA encryption using specified public key and
 * will store the cipher text in the output buffer.
 *
 * Implements    : HSM_DRV_RsaEncryptAsync_Activity
 * END**************************************************************************/
status_t HSM_DRV_RsaEncryptAsync(hsm_key_mode_t keyMode, uint32_t key, hsm_pkcs_padding_t padding,
                                 uint32_t msgLen, const uint8_t *plainText, uint32_t labelLen, const uint8_t *label,
                                 uint8_t *cipherText)
{
    uint32_t keySent = 0U;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);

    /* Check the buffer addresses are valid */
    DEV_ASSERT(plainText != NULL);
    DEV_ASSERT(cipherText != NULL);

    /* Check the buffers addresses are 32 bit aligned */
    DEV_ASSERT((((uint32_t)plainText) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)label) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)cipherText) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check the key parameter depending on key mode selected */
    if (keyMode == HSM_KEY_ID) /* The second parameter is a key index */
    {
        DEV_ASSERT(HSM_KEY_ID_GROUP(key) == 0x01U);
        keySent = key;
    }
    else if (keyMode == HSM_KEY_ADDR) /* The second parameter is the address of a structure where public key is stored */
    {
        DEV_ASSERT(((hsm_public_key_t*)key)->exponentSize <= 4U);
        DEV_ASSERT((((hsm_public_key_t*)key)->modulusSize <= 256U) && (((hsm_public_key_t*)key)->modulusSize >= 64U));
        DEV_ASSERT(((hsm_public_key_t*)key)->exponent != NULL);
        DEV_ASSERT(((hsm_public_key_t*)key)->modulus != NULL);
        keySent = key;
    }
    else /* The second parameter is the address of the public key in ASN format */
    {
        keySent = (uint32_t)key;
    }

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_ASYM_RSA_PKCS_ENC;

    /* Write HSM structure parameters */
    HSM_PrepareRsaEncryption((uint32_t)keyMode, keySent, (uint32_t)padding, msgLen,
                             plainText, labelLen, label, cipherText);

    /* Send the command to HSM */
    HSM_SendExtendedCmd();

    return STATUS_SUCCESS;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_RsaEncrypt
 * Description   : This function will perform pad/encode of the plaintext in either OAEP or PKCS
 * format using SHA 256 as the hashing algorithm. It will apply RSA encryption using specified public key and
 * will store the cipher text in the output buffer in a blocking manner.
 *
 * Implements    : HSM_DRV_RsaEncrypt_Activity
 * END**************************************************************************/
status_t HSM_DRV_RsaEncrypt(hsm_key_mode_t keyMode, uint32_t keyAddr, hsm_pkcs_padding_t padding,
                            uint32_t msgLen, const uint8_t *plainText, uint32_t labelLen, const uint8_t *label,
                            uint8_t *cipherText, uint32_t timeout)
{
    status_t status;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    /* Launch the command with the parameters received */
    status = HSM_DRV_RsaEncryptAsync(keyMode, keyAddr, padding, msgLen,
                                     plainText, labelLen, label, cipherText);

    if (status == STATUS_SUCCESS)
    {
        /* Wait for the command to complete */
        HSM_DRV_WaitCommandCompletion(timeout);

        return s_hsmStatePtr->cmdStatus;
    }
    else
    {
        return status;
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_RsaDhKeyPairGen
 * Description   : This blocking function will share the DH public key of the HSM to the Host Application.
 * The key will be generated using DH domain parameters.
 *
 * Implements    : HSM_DRV_RsaDhKeyPairGen_Activity
 * END**************************************************************************/
status_t HSM_DRV_RsaDhKeyPairGen(const hsm_g_base_t *gBase, const hsm_p_modulus_t *pModulus, uint32_t *pubKeyLen,
                                 uint8_t *pubKey, uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check if pointers are valid */
    DEV_ASSERT(pModulus != NULL);
    DEV_ASSERT(gBase != NULL);
    DEV_ASSERT(pubKeyLen != NULL);
    DEV_ASSERT(pubKey != NULL);

    /* Check memory alignment */
    DEV_ASSERT((((uint32_t)gBase) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)pModulus) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)pubKeyLen) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)pubKey) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check base size and modulus size */
    DEV_ASSERT(gBase->baseSize < 5U);
    DEV_ASSERT((pModulus->modulusSize >= 64U) && (pModulus->modulusSize <= 256U));

    /* Check the output buffer size to be at least the size of modulus */
    DEV_ASSERT(*pubKeyLen >= pModulus->modulusSize);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
       return STATUS_BUSY;
    }

    /* Specify this is a blocking function - returns upon command completion */
    s_hsmStatePtr->blockingCmd = true;

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_ASYM_DH_RSA_KEY_PAIR_GEN;

    /* Write HSM structure parameters */
    HSM_PrepareKeyPairGen((uint32_t)gBase, (uint32_t)pModulus, pubKeyLen, pubKey);

    /* Send the command to HSM */
    HSM_SendExtendedCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_ComputeSharedSecret
 * Description   : This blocking command will compute the shared secret for Diffie Hellman.
 * The length of shared secret will depend on the size of prime P. It is also called pre-master
 * secret in case it is used for TLS 1.2 implementation.
 *
 * Implements    : HSM_DRV_ComputeSharedSecret_Activity
 * END**************************************************************************/
status_t HSM_DRV_ComputeSharedSecret(hsm_key_id_t keyId, uint32_t keyLen, const uint8_t *key, uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check key index to be in the RAM catalog and Diffie Hellman Group*/
    DEV_ASSERT(HSM_KEY_ID_CATALOG(keyId) == 0x01U);
    DEV_ASSERT(HSM_KEY_ID_GROUP(keyId) == 0x03U);

    /* Check if key buffer is valid */
    DEV_ASSERT(key != NULL);

    /* Check if the public key length is in 64 - 256 bytes range */
    DEV_ASSERT((keyLen >= 64U) && (keyLen <= 256U));

    /* Check memory alignment */
    DEV_ASSERT((((uint32_t)key) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_ASYM_COMPUTE_SHARED_SECRET;
    s_hsmStatePtr->blockingCmd = true;

    /* Write HSM structure parameters */
    HSM_PrepareSharedSecret((uint32_t)keyId, keyLen, key);

    /* Send the command to HSM */
    HSM_SendExtendedCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_RsaVerifyMsg
 * Description   : This function is a subset of the RSA_PKCS_VERIFY_MSG command.
 * It accepts the hash of the input message instead of the input message itself.
 *
 * Implements    : HSM_DRV_RsaVerifyMsg_Activity
 * END**************************************************************************/
status_t HSM_DRV_RsaVerifyMsg(hsm_key_mode_t keyMode, uint32_t key, hsm_pkcs_padding_t padding,
                              uint32_t msgLen, const uint8_t *msg, uint32_t sgnLen, const uint8_t *sgn,
                              uint32_t saltLen, bool *authStatus, uint32_t timeout)
{
    uint32_t keySent = 0U;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check if buffers are valid */
    DEV_ASSERT(msg != NULL);
    DEV_ASSERT(sgn != NULL);
    DEV_ASSERT(authStatus != NULL);

    /* Check memory alignment */
    DEV_ASSERT((((uint32_t)msg) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)sgn) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check the key parameter depending on key mode selected */
    if (keyMode == HSM_KEY_ID) /* The second parameter is a key index */
    {
        DEV_ASSERT(HSM_KEY_ID_GROUP(key) == 0x01U);
        keySent = key;
    }
    else if (keyMode == HSM_KEY_ADDR) /* The second parameter is the address of a structure where public key is stored */
    {
        DEV_ASSERT(((hsm_public_key_t*)key)->exponentSize <= 4U);
        DEV_ASSERT((((hsm_public_key_t*)key)->modulusSize <= 256U) && (((hsm_public_key_t*)key)->modulusSize >= 64U));
        DEV_ASSERT(((hsm_public_key_t*)key)->exponent != NULL);
        DEV_ASSERT(((hsm_public_key_t*)key)->modulus != NULL);
        keySent = key;
    }
    else /* The second parameter is the address of the public key in ASN format */
    {
        keySent = key;
    }

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_ASYM_RSA_PKCS_VERIFY_MSG;
    s_hsmStatePtr->blockingCmd = true;
    s_hsmStatePtr->verifStatus = authStatus;

    /* Write HSM structure parameters */
    HSM_PrepareVerifyMsg((uint32_t)keyMode, keySent, (uint32_t)padding, msgLen, msg, sgnLen, sgn, saltLen);

      /* Send the command to HSM */
    HSM_SendExtendedCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_RsaVerifyHash
 * Description   : This function is a subset of the RSA_PKCS_VERIFY_MSG command. It accepts
 * the hash of the input message instead of the input message itself.
 *
 * Implements    : HSM_DRV_RsaVerifyHash_Activity
 * END**************************************************************************/
status_t HSM_DRV_RsaVerifyHash(hsm_key_mode_t keyMode, uint32_t key, hsm_pkcs_padding_t padding,
                               const uint8_t *hash, uint32_t sgnLen, const uint8_t *sgn, uint32_t saltLen,
                               bool *authStatus, uint32_t timeout)
{
    uint32_t keySent = 0U;

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check if buffers are valid */
    DEV_ASSERT(hash != NULL);
    DEV_ASSERT(sgn != NULL);
    DEV_ASSERT(authStatus != NULL);

    /* Check memory alignment */
    DEV_ASSERT((((uint32_t)hash) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)sgn) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check the key parameter depending on key mode selected */
    if (keyMode == HSM_KEY_ID) /* The second parameter is a key index */
    {
        DEV_ASSERT(HSM_KEY_ID_GROUP(key) == 0x01U);
        keySent = key;
    }
    else if (keyMode == HSM_KEY_ADDR) /* The second parameter is the address of a structure where public key is stored */
    {
        DEV_ASSERT(((hsm_public_key_t*)key)->exponentSize <= 4U);
        DEV_ASSERT((((hsm_public_key_t*)key)->modulusSize <= 256U) && (((hsm_public_key_t*)key)->modulusSize >= 64U));
        DEV_ASSERT(((hsm_public_key_t*)key)->exponent != NULL);
        DEV_ASSERT(((hsm_public_key_t*)key)->modulus != NULL);
        keySent = key;
    }
    else /* The second parameter is the address of the public key in ASN format */
    {
        keySent = key;
    }

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_ASYM_RSA_PKCS_VERIFY_HASH;
    s_hsmStatePtr->blockingCmd = true;
    s_hsmStatePtr->verifStatus = authStatus;

    /* Write HSM structure parameters */
    HSM_PrepareVerifyHash((uint32_t)keyMode, keySent, (uint32_t)padding, hash, sgnLen, sgn, saltLen);

    /* Send the command to HSM */
    HSM_SendExtendedCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_InstallCertificate
 * Description   : This command will install the information of public key certificate in HSM Key store area.
 *
 * Implements    : HSM_DRV_InstallCertificate_Activity
 * END**************************************************************************/
status_t HSM_DRV_InstallCertificate(hsm_key_id_t keyId, hsm_key_id_t authKeyID, const uint8_t *certificate,
                                    uint32_t certificateLen, uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check keys indexes to be part of key group RSA based Asymmetric Public keys (0x01U) or
       RAM based RSA Asymmetric Public Keys (0x01U)*/
    DEV_ASSERT(HSM_KEY_ID_GROUP(keyId) == 0x01U);
    DEV_ASSERT(HSM_KEY_ID_GROUP(authKeyID) == 0x01U);

    /* Check if certificate is valid */
    DEV_ASSERT(certificate != NULL);

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
       return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_ASYM_INSTALL_CERTIFICATE;
    s_hsmStatePtr->blockingCmd = true;

    /* Write HSM structure parameters */
    HSM_PrepareInstallCerficate((uint32_t)keyId, (uint32_t)authKeyID, certificate, certificateLen);

    /* Send the command to HSM */
    HSM_SendExtendedCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_GenerateExtendedRamKeys
 * Description   : This command will generate the session keys based on the shared
 * secret and will store it in corresponding key group in RAM catalog.
 *
 * Implements    : HSM_DRV_GenerateExtendedRamKeys_Activity
 * END**************************************************************************/
status_t HSM_DRV_GenerateExtendedRamKeys(hsm_key_id_t keyId, hsm_kdf_t kdfType,
                                         void *kdf, uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check if key is valid */
    DEV_ASSERT(kdf != NULL);

    /* Check random key restrictions */
    if (kdfType == RANDOM_KEY)
    {
        /* Check whether destination key index where key will be stored is in the RAM Catalog*/
        DEV_ASSERT(HSM_KEY_ID_CATALOG(((hsm_random_kdf_t *)kdf)->randomKeyId) == 0x01U);

        /* Check key sizes depending on the key group*/
        switch(HSM_KEY_ID_GROUP(((hsm_random_kdf_t *)kdf)->randomKeyId))
        {
            /* RAM based AES-128 Symmetric Keys */
            case 0x00:
                DEV_ASSERT(((hsm_random_kdf_t *)kdf)->randomKeySize == 16U);
                break;
            /* RAM based HMAC Keys */
            case 0x02:
                DEV_ASSERT(((hsm_random_kdf_t *)kdf)->randomKeySize <= 64U);
                break;
            /* RAM based RSA Random Shared Secret */
            case 0x04U:
                DEV_ASSERT(((hsm_random_kdf_t *)kdf)->randomKeySize <= 64U);
                break;
            /* Unsupported key groups */
            default:
                DEV_ASSERT(false);
                break;
        }
    }
    /* Check TLS 1.2 PRF restrictions */
    else
    {
        /* Check key index of shared key */
        DEV_ASSERT(HSM_KEY_ID_CATALOG(keyId) == 0x01U);
        DEV_ASSERT((HSM_KEY_ID_GROUP(keyId) == 0x03U) || (HSM_KEY_ID_GROUP(keyId) == 0x04U));

        /* Check if pointers are valid */
        DEV_ASSERT(((hsm_tls_kdf_t*)kdf)->masterKeySeed != NULL);
        DEV_ASSERT(((hsm_tls_kdf_t*)kdf)->keyExpansionSeed != NULL);
        DEV_ASSERT(((hsm_tls_kdf_t*)kdf)->clientIV != NULL);
        DEV_ASSERT(((hsm_tls_kdf_t*)kdf)->serverIV != NULL);

        /* Length of the seed to calculate master secret key value should not be
         * equal to zero or greater than 128 bytes.*/
        DEV_ASSERT((((hsm_tls_kdf_t*)kdf)->masterKeySeedLen > 0U) &&
                    (((hsm_tls_kdf_t*)kdf)->masterKeySeedLen <= 128U));

        /* Length of the seed which will be used to calculate the keys
         * should not be equal to zero or greater than 128 bytes */
        DEV_ASSERT((((hsm_tls_kdf_t*)kdf)->keyExpansionSeedLen > 0U) &&
                   (((hsm_tls_kdf_t*)kdf)->keyExpansionSeedLen <= 128U));

        /* Check whether destination keys indexes where the key will be stored belongs to RAM catalog */
        DEV_ASSERT(HSM_KEY_ID_CATALOG(((hsm_tls_kdf_t*)kdf)->clientKeyMAC) == 0x01U);
        DEV_ASSERT(HSM_KEY_ID_CATALOG(((hsm_tls_kdf_t*)kdf)->serverKeyMAC) == 0x01U);

        /* Check whether destination keys indexes where the keys will be stored belongs to HMAC group */
        DEV_ASSERT(HSM_KEY_ID_GROUP(((hsm_tls_kdf_t*)kdf)->clientKeyMAC) == 0x02U);
        DEV_ASSERT(HSM_KEY_ID_GROUP(((hsm_tls_kdf_t*)kdf)->serverKeyMAC) == 0x02U);

        /* Client and server mac key index should not be same */
        DEV_ASSERT(((hsm_tls_kdf_t*)kdf)->clientKeyMAC != ((hsm_tls_kdf_t*)kdf)->serverKeyMAC);

        /* Check whether destination keys indexes where the key will be stored belongs to RAM catalog */
        DEV_ASSERT(HSM_KEY_ID_CATALOG(((hsm_tls_kdf_t*)kdf)->clientKey) == 0x01U);
        DEV_ASSERT(HSM_KEY_ID_CATALOG(((hsm_tls_kdf_t*)kdf)->serverKey) == 0x01U);

        /* Check whether destination keys indexes where the keys
         * will be stored belongs to AES-128 Symmetric keys group */
        DEV_ASSERT(HSM_KEY_ID_GROUP(((hsm_tls_kdf_t*)kdf)->serverKey) == 0x00U);
        DEV_ASSERT(HSM_KEY_ID_GROUP(((hsm_tls_kdf_t*)kdf)->clientKey) == 0x00U);

        /* Client and server key indexes should not be same */
        DEV_ASSERT(((hsm_tls_kdf_t*)kdf)->clientKey != ((hsm_tls_kdf_t*)kdf)->serverKey);

        /* Length of the IV can be up to 12 bytes */
        DEV_ASSERT(((hsm_tls_kdf_t*)kdf)->ivSize <= 12U);
    }

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_ASYM_GENERATE_EXTENDED_RAM_KEYS;
    s_hsmStatePtr->blockingCmd = true;

    /* Write HSM structure parameters */
    HSM_PrepareGenerateExtendedRamKeys((uint32_t)keyId, (uint32_t)kdfType, (uint8_t*)kdf);

    /* Send the command to HSM */
    HSM_SendExtendedCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_PseudoRandomTLS
 * Description   : This command is used to generate and verify the finished message as
 *  described in TLS 1.2 specification. Master secret is used to calculate the final output message.
 *  Firmware first calculates the master secret from pre-master secret.
 *
 * Implements    : HSM_DRV_PseudoRandomTLS_Activity
 * END**************************************************************************/
status_t HSM_DRV_PseudoRandomTLS(hsm_key_id_t keyId, uint32_t masterSeedLen, const uint8_t *masterSeed,
                                 uint32_t seedLen, const uint8_t *seed, uint32_t msgLen, uint8_t *msg,
                                 uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check if pointers are valid */
    DEV_ASSERT(masterSeed != NULL);
    DEV_ASSERT(seed != NULL);
    DEV_ASSERT(msg != NULL);

    /* Check key index to be in RAM Catalog */
    DEV_ASSERT(HSM_KEY_ID_CATALOG(keyId) == 0x01U);

    /* Check key index to be in RAM based Diffie Hellman RSA Secret or RAM based RSA Random Shared Secret*/
    DEV_ASSERT((HSM_KEY_ID_GROUP(keyId) == 0x03U) || (HSM_KEY_ID_GROUP(keyId) == 0x04U));

    /* Length of the seed to calculate master secret key value should not be equal to zero or greater than 128 bytes */
    DEV_ASSERT((masterSeedLen > 0U) && (masterSeedLen <= 128U));

    /* Length of the output message can be maximum up to 16 bytes.*/
    DEV_ASSERT(msgLen <= 16U);

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    /* Check there is no other command in execution */
    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_ASYM_TLS_PRF;
    s_hsmStatePtr->blockingCmd = true;

    /* Write HSM structure parameters */
    HSM_PreparePseudoRandomTLS((uint32_t)keyId, masterSeedLen, masterSeed, seedLen, seed, msgLen, msg);

    /* Send the command to HSM */
    HSM_SendExtendedCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_ExportExtendedRamKeys
 * Description   : This command is used to export the RAM key from the RAM catalog
 * using the specified method. Currently, only RSA encryption based method is supported.
 * RSA Encryption method will encrypt the specified key with the specified RSA public
 * key certificate. The key group that can be encrypted using this command are AES-128
 * symmetric keys, HMAC Keys or RSA based secret from RAM key catalog.
 *
 * Implements    : HSM_DRV_ExportExtendedRamKeys_Activity
 * END**************************************************************************/
status_t HSM_DRV_ExportExtendedRamKeys(hsm_key_id_t keyId, const hsm_rsa_algorithm_t *rsa_encr, uint32_t *outBufLen,
                                       uint8_t *expKey, uint32_t *expKeyLen, uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check key index group */
    DEV_ASSERT((HSM_KEY_ID_GROUP(keyId) == 0x00U) || /* RAM based AES-128 Symmetric Keys */
               (HSM_KEY_ID_GROUP(keyId) == 0x02U) || /* RAM based HMAC Keys */
               (HSM_KEY_ID_GROUP(keyId) == 0x04U));  /* RAM based RSA Random Shared Secret */

    /* Check if algorithm structure is valid */
    DEV_ASSERT(rsa_encr != NULL);

    /* Check if buffer of exported key is valid */
    DEV_ASSERT(expKey != NULL);

    /* Check if buffer where HSM firmware will write the length of the key in bytes is valid */
    DEV_ASSERT(expKeyLen != NULL);

    /* Check if output buffer where the length will be stored by HSM is valid */
    DEV_ASSERT(outBufLen != NULL);

    /* Check memory alignment*/
    DEV_ASSERT((((uint32_t)rsa_encr) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)expKey) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)expKeyLen) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)rsa_encr->label) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check key index to be in NVM catalog and RSA based Asymmetric Public keys group */
    DEV_ASSERT(HSM_KEY_ID_GROUP(rsa_encr->keyId) == 0x01U);
    DEV_ASSERT(HSM_KEY_ID_CATALOG(rsa_encr->keyId) == 0x00U);

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_ASYM_EXPORT_EXTENDED_RAM_KEY;
    s_hsmStatePtr->blockingCmd = true;

    /* Write HSM structure parameters */
    HSM_PrepareExportExtendedRamKeys((uint32_t)keyId, 0U, (uint32_t)rsa_encr, outBufLen, expKey, expKeyLen);

    /* Send the command to HSM */
    HSM_SendExtendedCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_HashSHA256
 * Description   : This function performs cryptographic hash (SHA-256) of a given input
 *
 * Implements    : HSM_DRV_HashSHA256_Activity
 * END**************************************************************************/
status_t HSM_DRV_HashSHA256(uint32_t msgLen, const uint8_t *msg, uint8_t *hash, uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check whether buffers are valid */
    DEV_ASSERT(msg != NULL);
    DEV_ASSERT(hash != NULL);

    /* Check memory alignment*/
    DEV_ASSERT((((uint32_t)msg)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT(( ((uint32_t)hash) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_HASH_SHA256;
    s_hsmStatePtr->blockingCmd = true;

    /* Write HSM structure parameters */
    HSM_PrepareSHA256(msgLen, msg, hash);

    /* Send the command to HSM */
    HSM_SendExtendedCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_HashHMAC256
 * Description   : This function performs a cryptographic hash of a given input using a keyed-hash message
 * authentication code (HMAC) which is a specific type of message authentication code
 * (MAC) involving a cryptographic hash function and a secret cryptographic key.
 *
 * Implements    : HSM_DRV_HashHMAC256_Activity
 * END**************************************************************************/
status_t HSM_DRV_HashHMAC256(hsm_key_id_t keyId, uint32_t msgLen, const uint8_t *msg, uint32_t *hashLen,
                             uint8_t *hash, uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check whether buffers are valid */
    DEV_ASSERT(msg != NULL);
    DEV_ASSERT(hashLen != NULL);
    DEV_ASSERT(hash != NULL);

    /* Check memory alignment */
    DEV_ASSERT((((uint32_t)msg)& HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)hash) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);
    DEV_ASSERT((((uint32_t)hashLen) & HSM_BUFF_ADDR_CHECK_MASK) == 0U);

    /* Check key index to be one of RAM based HMAC Keys */
    DEV_ASSERT(HSM_KEY_ID_GROUP(keyId) == 0x02U);
    DEV_ASSERT(HSM_KEY_ID_CATALOG(keyId) == 0x01U);

    /* As an input, output buffer length must be greater than 0 */
    DEV_ASSERT(*hashLen != 0U);

    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->cmd = HSM_CMD_HASH_HMAC256;
    s_hsmStatePtr->blockingCmd = true;

    /* Write HSM structure parameters */
    HSM_PrepareHMAC256(keyId, msgLen, msg, hashLen, hash);

    /* Send the command to HSM */
    HSM_SendExtendedCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_EraseExtededRamKey
 * Description   : This command is used to erase the keys of RAM catalog.
 *
 * Implements    : HSM_DRV_EraseExtededRamKey_Activity
 * END**************************************************************************/
status_t HSM_DRV_EraseExtededRamKey(hsm_key_id_t keyId, uint32_t timeout)
{
    /* Check the driver is initialized */
    DEV_ASSERT(s_hsmStatePtr != NULL);
    /* Check if the command is supported in this firmware version */
    DEV_ASSERT(s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION);
    /* Check key index to be in the RAM Catalog */
    DEV_ASSERT(HSM_KEY_ID_CATALOG(keyId) == 0x01U);

    /* Check there is no other command in execution */
    if (HSM_IsBusy() || s_hsmStatePtr->cmdInProgress)
    {
        return STATUS_BUSY;
    }

    s_hsmStatePtr->cmdInProgress = true;
    s_hsmStatePtr->blockingCmd = true;
    s_hsmStatePtr->cmd = HSM_CMD_SYM_ERASE_EXTENDED_RAM_KEY;

    /* Write HSM structure parameters */
    HSM_PrepareEraseExtendedRamKey((uint32_t)keyId);

    /* Send the command to HSM */
    HSM_SendCmd();

    /* Wait for the command to complete */
    HSM_DRV_WaitCommandCompletion(timeout);

    return s_hsmStatePtr->cmdStatus;
}


/*********** PRIVATE FUNCTIONS *****************/

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_IRQHandlerExtended
 * Description   : Implementation of the HSM interrupt handler. Handles completed
 * extended command events.
 *
 * END**************************************************************************/
void HSM_DRV_IRQHandlerExtended(void)
{
    if (s_hsmStatePtr->cmdInProgress)
    {
        /* Wait for the BUSY flag to be cleared by hw */
        while (HSM_IsBusy()) {}

        /* Retrieve the error code of last command */
        uint32_t err = HSM_GetExtErrCode();

        /* Update the internal driver status */
        if (err == 0U)
        {
            s_hsmStatePtr->cmdStatus = STATUS_SUCCESS;
        }
        else
        if (err == 0xBU)
        {
            s_hsmStatePtr->cmdStatus = STATUS_BUSY;
        }
        else
        {
            s_hsmStatePtr->cmdStatus = HSM_CONVERT_ERC(err);
        }

        /* If the command was RSA Verify Message or RSA Verify Hash, retrieve the result of the authentication */
        if ((s_hsmStatePtr->cmd == HSM_CMD_ASYM_RSA_PKCS_VERIFY_MSG) || \
            (s_hsmStatePtr->cmd == HSM_CMD_ASYM_RSA_PKCS_VERIFY_HASH))
        {
            if (s_hsmStatePtr->verifStatus != NULL)
            {
                *s_hsmStatePtr->verifStatus = HSM_GetAuthResult();
                s_hsmStatePtr->verifStatus = NULL;
            }
        }

        /* Call the user callback, if available */
        if (s_hsmStatePtr->callback != NULL)
        {
            s_hsmStatePtr->callback((uint32_t)s_hsmStatePtr->cmd, s_hsmStatePtr->callbackParam);
        }

        if (s_hsmStatePtr->blockingCmd)
        {
            /* Update the internal blocking flag */
            s_hsmStatePtr->blockingCmd = false;

            /* Update the synchronization object */
            (void)OSIF_SemaPost(&s_hsmStatePtr->cmdComplete);
        }

        /* Update the internal busy flag */
        s_hsmStatePtr->cmdInProgress = false;
        /* No command in execution at this point */
        s_hsmStatePtr->cmd = HSM_CMD_NONE;
    }

    /* Clear the interrupt flag */
    HSM_ClearExtendedIntFlag();
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_IRQHandler
 * Description   : Implementation of the HSM interrupt handler. Handles completed
 * command events.
 *
 * END**************************************************************************/
void HSM_DRV_IRQHandler(void)
{
    if (s_hsmStatePtr->cmdInProgress)
    {
        /* Wait for the BUSY flag to be cleared by hw */
        while (HSM_IsBusy()) {}

        /* Retrieve the error code of last command */
        uint32_t err = HSM_GetErrCode();

        /* Update the internal driver status */
        if (err == 0U)
        {
            s_hsmStatePtr->cmdStatus = STATUS_SUCCESS;
        }
        else
        if (err == 0xBU)
        {
            s_hsmStatePtr->cmdStatus = STATUS_BUSY;
        }
        else
        {
            s_hsmStatePtr->cmdStatus = HSM_CONVERT_ERC(err);
        }

        /* If the command was VERIFY_MAC, retrieve the result of the verification */
        if ((s_hsmStatePtr->cmd == HSM_CMD_VERIFY_MAC) && (s_hsmStatePtr->verifStatus != NULL))
        {
            *s_hsmStatePtr->verifStatus = HSM_GetMacVerifResult();
            s_hsmStatePtr->verifStatus = NULL;
        }

        /* If the command was AES GCM/CCM decrypt, retrieve the result of the authentication */
        if ((s_hsmStatePtr->cmd == HSM_CMD_SYM_AES_GCM_DEC) || (s_hsmStatePtr->cmd == HSM_CMD_SYM_AES_CCM_DEC))
        {
            if (s_hsmStatePtr->verifStatus != NULL)
            {
                *s_hsmStatePtr->verifStatus = HSM_GetAuthResult();
                s_hsmStatePtr->verifStatus = NULL;
            }
        }

        /* Call the user callback, if available */
        if (s_hsmStatePtr->callback != NULL)
        {
            s_hsmStatePtr->callback((uint32_t)s_hsmStatePtr->cmd, s_hsmStatePtr->callbackParam);
        }

        if (s_hsmStatePtr->blockingCmd)
        {
            /* Update the internal blocking flag */
            s_hsmStatePtr->blockingCmd = false;

            /* Update the synchronization object */
            (void)OSIF_SemaPost(&s_hsmStatePtr->cmdComplete);
        }

        /* Update the internal busy flag */
        s_hsmStatePtr->cmdInProgress = false;
        /* No command in execution at this point */
        s_hsmStatePtr->cmd = HSM_CMD_NONE;
    }

    /* Clear the interrupt flag */
    HSM_ClearIntFlag();
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_WaitCommandCompletion
 * Description   : Waits on the synchronization semaphore and updates the flags.
 *
 * END**************************************************************************/
static void HSM_DRV_WaitCommandCompletion(uint32_t timeout)
{
    status_t syncStatus;

    /* Wait for command completion */
    syncStatus = OSIF_SemaWait(&s_hsmStatePtr->cmdComplete, timeout);

    /* Update the busy flag and status if timeout expired */
    if (syncStatus == STATUS_TIMEOUT)
    {
        (void)HSM_DRV_CancelCommand();
        s_hsmStatePtr->blockingCmd = false;
        s_hsmStatePtr->cmdStatus = STATUS_TIMEOUT;
    }
}



/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_CopyBuff
 * Description   : Copies data from source to destination buffer.
 *
 * END**************************************************************************/
static void HSM_DRV_CopyBuff(const uint8_t * srcBuff, uint8_t * destBuff, uint32_t len)
{
    uint32_t idx;
    for (idx = 0U; idx < len; idx++)
    {
        destBuff[idx] = srcBuff[idx];
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_DRV_XorBuff
 * Description   : Performs bitwise XOR between input buffers and stores the
 * result in the output buffer.
 *
 * END**************************************************************************/
static void HSM_DRV_XorBuff(const uint8_t * inBuff, uint8_t * outBuff, uint32_t len)
{
    uint32_t idx;
    for (idx = 0U; idx < len; idx++)
    {
        outBuff[idx] ^= inBuff[idx];
    }
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_IsBusy
 * Description   : Returns true if HSM is busy processing a command.
 *
 *END**************************************************************************/
static bool HSM_IsBusy(void)
{
    /* Check BUSY flag */
    if ((HSM->HSM2HTS & HSM2HTS_BUSY_MASK) != 0U)
    {
        return true;
    }

    /* Check EXT_BUSY flag */
    if (s_hsmStatePtr->fwVersion == HSM_SHE_PLUS_FW_VERSION)
    {
        if ((HSM->HSM2HTS & HSM2HTS_EXT_BUSY_MASK) != 0U)
        {
            return true;
        }
    }

    return false;
}

/******************************************************************************
 * EOF
 *****************************************************************************/
