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
 * Violates MISRA 2012 Advisory Rule 11.4, Conversion between a pointer and
 * integer type.
 * The cast is required for passing buffer addresses to HSM firmware; the HSM firmware
 * command parameters are defined as unsigned integers.
 *
 * @section [global]
 * Violates MISRA 2012 Required Rule 11.6, Cast from pointer to unsigned long.
 * The cast is required for passing buffer addresses to HSM firmware; the HSM firmware
 * command parameters are defined as unsigned integers.
 *
 * @section [global]
 * Violates MISRA 2012 Required Rule 11.6, Cast from unsigned int to pointer.
 * The cast is required to initialize a pointer with an unsigned long define,
 * representing an address (base address of the module).
 */

#include "hsm_hw_access.h"

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*! @brief Static structure holding HSM command to be passed to security
 * firmware.
 */
static hsm_fw_command_t s_cmd;

/*! @brief Static variable storing the 64-bits message length; a reference to this
 * variable is passed to HSM for 'generate MAC' command;
 */
static uint64_t s_msgLen;

/*! @brief Static variable storing the 8-bits MAC length; a reference to this
 * variable is passed to HSM for 'verify MAC' command;
 */
static uint32_t s_macLen;

/*! @brief Static variable storing the authentication status; a reference to this
 * variable is passed to HSM for commands that imply authentication;
 */
static uint32_t s_authStatus;

/*******************************************************************************
 * Code
 ******************************************************************************/

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareCommand
 * Description   : Prepares the HSM command structure.
 *
 *END**************************************************************************/
void HSM_PrepareCommand(uint32_t cmd,
                        uint32_t param1,
                        uint32_t param2,
                        uint32_t param3,
                        uint32_t param4,
                        uint32_t param5,
                        uint32_t param6,
                        uint32_t param7,
                        uint32_t param8,
                        uint32_t param9,
                        uint32_t param10,
                        uint32_t param11)
{
    s_cmd.CMD = cmd;
    s_cmd.PARAM_1 = param1;
    s_cmd.PARAM_2 = param2;
    s_cmd.PARAM_3 = param3;
    s_cmd.PARAM_4 = param4;
    s_cmd.PARAM_5 = param5;
    s_cmd.PARAM_6 = param6;
    s_cmd.PARAM_7 = param7;
    s_cmd.PARAM_8 = param8;
    s_cmd.PARAM_9 = param9;
    s_cmd.PARAM_10 = param10;
    s_cmd.PARAM_11 = param11;
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareEncryptEcbCmd
 * Description   : Prepares the HSM ECB encrypt command.
 *
 *END**************************************************************************/
void HSM_PrepareEncryptEcbCmd(hsm_key_id_t keyId, const uint8_t *plainText,
                              uint32_t length, uint8_t *cipherText)
{
    uint32_t cmd, cmdKeyId;

    /* Set ECB encryption command */
    cmd = (uint32_t)HSM_CMD_ENC_ECB;
    /* Check the key bank and update command accordingly */
    if (HSM_CMD_KBS(keyId) != 0U)
    {
        cmd |= HSM_CMD_KBS_MASK;
    }
    /* Get the command key ID (strip the KBS bit) */
    cmdKeyId = HSM_CMD_KEY_ID(keyId);

    HSM_PrepareCommand(cmd, cmdKeyId, HSM_BUFF_BLOCK_COUNT(length), (uint32_t)plainText,
                       (uint32_t)cipherText, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareDecryptEcbCmd
 * Description   : Prepares the HSM ECB decrypt command.
 *
 *END**************************************************************************/
void HSM_PrepareDecryptEcbCmd(hsm_key_id_t keyId, const uint8_t *cipherText,
                              uint32_t length, uint8_t *plainText)
{
    uint32_t cmd, cmdKeyId;

    /* Set ECB decryption command */
    cmd = (uint32_t)HSM_CMD_DEC_ECB;
    /* Check the key bank and update command accordingly */
    if (HSM_CMD_KBS(keyId) != 0U)
    {
        cmd |= HSM_CMD_KBS_MASK;
    }
    /* Get the command key ID (strip the KBS bit) */
    cmdKeyId = HSM_CMD_KEY_ID(keyId);

    HSM_PrepareCommand(cmd, cmdKeyId, HSM_BUFF_BLOCK_COUNT(length), (uint32_t)cipherText,
                       (uint32_t)plainText, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareEncryptCbcCmd
 * Description   : Prepares the HSM CBC encrypt command.
 *
 *END**************************************************************************/
void HSM_PrepareEncryptCbcCmd(hsm_key_id_t keyId, const uint8_t *plainText,
                              uint32_t length, const uint8_t *iv, uint8_t *cipherText)
{
    uint32_t cmd, cmdKeyId;

    /* Set CBC encryption command */
    cmd = (uint32_t)HSM_CMD_ENC_CBC;
    /* Check the key bank and update command accordingly */
    if (HSM_CMD_KBS(keyId) != 0U)
    {
        cmd |= HSM_CMD_KBS_MASK;
    }
    /* Get the command key ID (strip the KBS bit) */
    cmdKeyId = HSM_CMD_KEY_ID(keyId);

    HSM_PrepareCommand(cmd, cmdKeyId, (uint32_t)iv, HSM_BUFF_BLOCK_COUNT(length),
                       (uint32_t)plainText, (uint32_t)cipherText, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareDecryptCbcCmd
 * Description   : Prepares the HSM CBC decrypt command.
 *
 *END**************************************************************************/
void HSM_PrepareDecryptCbcCmd(hsm_key_id_t keyId, const uint8_t *cipherText,
                              uint32_t length, const uint8_t *iv, uint8_t *plainText)
{
    uint32_t cmd, cmdKeyId;

    /* Set CBC decryption command */
    cmd = (uint32_t)HSM_CMD_DEC_CBC;
    /* Check the key bank and update command accordingly */
    if (HSM_CMD_KBS(keyId) != 0U)
    {
        cmd |= HSM_CMD_KBS_MASK;
    }
    /* Get the command key ID (strip the KBS bit) */
    cmdKeyId = HSM_CMD_KEY_ID(keyId);

    HSM_PrepareCommand(cmd, cmdKeyId, (uint32_t)iv, HSM_BUFF_BLOCK_COUNT(length),
                       (uint32_t)cipherText, (uint32_t)plainText, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareGenerateMacCmd
 * Description   : Prepares the HSM generate mac command.
 *
 *END**************************************************************************/
void HSM_PrepareGenerateMacCmd(hsm_key_id_t keyId, const uint8_t *msg,
                               uint64_t msgLen, uint8_t *mac)
{
    uint32_t cmd, cmdKeyId;

    /* Set MAC generate command */
    cmd = (uint32_t)HSM_CMD_GENERATE_MAC;
    /* Check the key bank and update command accordingly */
    if (HSM_CMD_KBS(keyId) != 0U)
    {
        cmd |= HSM_CMD_KBS_MASK;
    }
    /* Get the command key ID (strip the KBS bit) */
    cmdKeyId = HSM_CMD_KEY_ID(keyId);

    /* Save the message length in the internal driver variable */
    s_msgLen = msgLen;

    HSM_PrepareCommand(cmd, cmdKeyId, (uint32_t)(&s_msgLen), (uint32_t)msg, (uint32_t)mac,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareVerifyMacCmd
 * Description   : Prepares the HSM verify mac command.
 *
 *END**************************************************************************/
void HSM_PrepareVerifyMacCmd(hsm_key_id_t keyId, const uint8_t *msg,
                             uint64_t msgLen, const uint8_t *mac, uint8_t macLen)
{
    uint32_t cmd, cmdKeyId;

    /* Set MAC verify command */
    cmd = (uint32_t)HSM_CMD_VERIFY_MAC;
    /* Check the key bank and update command accordingly */
    if (HSM_CMD_KBS(keyId) != 0U)
    {
        cmd |= HSM_CMD_KBS_MASK;
    }
    /* Get the command key ID (strip the KBS bit) */
    cmdKeyId = HSM_CMD_KEY_ID(keyId);

    /* Save the message length in the internal driver variable */
    s_msgLen = msgLen;
    /* Save the MAC length in the internal driver variable */
    s_macLen = macLen;

    HSM_PrepareCommand(cmd, cmdKeyId, (uint32_t)(&s_msgLen), (uint32_t)msg, (uint32_t)mac,
                       (uint32_t)(&s_macLen), HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareLoadKeyCmd
 * Description   : Prepares the HSM load key command.
 *
 *END**************************************************************************/
void HSM_PrepareLoadKeyCmd(hsm_key_id_t keyId, const uint8_t *m1, const uint8_t *m2,
                           const uint8_t *m3, uint8_t *m4, uint8_t *m5)
{
    uint32_t cmd;

    /* Set load key command */
    cmd = (uint32_t)HSM_CMD_LOAD_KEY;
    /* Check the key bank and update command accordingly */
    if (HSM_CMD_KBS(keyId) != 0U)
    {
        cmd |= HSM_CMD_KBS_MASK;
    }

    HSM_PrepareCommand(cmd, (uint32_t)m1, (uint32_t)m2, (uint32_t)m3, (uint32_t)m4, (uint32_t)m5,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);

}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_SendCmd
 * Description   : Sends the command to HSM.
 *
 *END**************************************************************************/
void HSM_SendCmd(void)
{
    /* Write the command structure address in the HSM register */
    HSM->HT2HSMS = ((uint32_t)(&s_cmd));
    /* Send the command to HSM */
    HSM->HT2HSMF |= HT2HSMF_CMD_INT_MASK;
    /* Wait for the command to be acknowledged by HSM */
    while ((HSM->HT2HSMF & HT2HSMF_CMD_INT_MASK) > 0U) {}
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_SendExtendedCmd
 * Description   : Sends the extended command to HSM.
 *
 *END**************************************************************************/
void HSM_SendExtendedCmd(void)
{
    /* Write the command structure address in the HSM register */
    HSM->HT2HSMS = ((uint32_t)(&s_cmd));
    /* Send the command to HSM */
    HSM->HT2HSMF |= HT2HSMF_EXT_CMD_INT_MASK;
    /* Wait for the command to be acknowledged by HSM */
    while ((HSM->HT2HSMF & HT2HSMF_EXT_CMD_INT_MASK) > 0U) {}
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_GetMacVerifResult
 * Description   : Returns the result of the last MAC verification.
 *
 *END**************************************************************************/
bool HSM_GetMacVerifResult(void)
{
    return (s_macLen == 0U);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_GetAuthResult
 * Description   : Returns the result of the last authentication.
 *
 *END**************************************************************************/
bool HSM_GetAuthResult(void)
{
    return (s_authStatus == HSM_RSA_AUTHENTICATION_OK);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareRsaEncryption
 * Description   : Prepares the HSM RSA encryption command.
 *
 *END**************************************************************************/
void HSM_PrepareRsaEncryption(uint32_t keyMode, uint32_t key, uint32_t padding, uint32_t msgLen,
                              const uint8_t *plainText, uint32_t labelLen, const uint8_t *label,
                              uint8_t *cipherText)
{
    uint32_t cmd = 0U;

    /* Set RSA Encryption command code */
    cmd = (uint32_t)HSM_CMD_ASYM_RSA_PKCS_ENC;

    HSM_PrepareCommand(cmd, keyMode, key, padding, msgLen, (uint32_t)plainText,  labelLen, (uint32_t)label,
                       (uint32_t) cipherText, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareVerifyMsg
 * Description   : Prepares the HSM verify message command.
 *
 *END**************************************************************************/
void HSM_PrepareVerifyMsg(uint32_t keyMode, uint32_t key, uint32_t padding, uint32_t plainTextLen,
                          const uint8_t *plainText, uint32_t sgnLen, const uint8_t *sgn, uint32_t saltLen)
{
    uint32_t cmd = 0U;

    /* Set command code */
    cmd = (uint32_t)HSM_CMD_ASYM_RSA_PKCS_VERIFY_MSG;

    HSM_PrepareCommand(cmd, keyMode, key, padding, plainTextLen, (uint32_t)plainText, sgnLen, (uint32_t)sgn, saltLen,
                       (uint32_t)&s_authStatus, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareVerifyHash
 * Description   : Prepares the HSM command that verifies the hash of message command.
 *
 *END**************************************************************************/
void HSM_PrepareVerifyHash(uint32_t keyMode, uint32_t key, uint32_t padding, const uint8_t *hash,
                           uint32_t sgnLen, const uint8_t *sgn, uint32_t saltLen)
{
    uint32_t cmd = 0U;

    /* Set command code */
    cmd = (uint32_t)HSM_CMD_ASYM_RSA_PKCS_VERIFY_HASH;

    HSM_PrepareCommand(cmd, keyMode, key, padding, (uint32_t)hash, sgnLen, (uint32_t)sgn, saltLen,
                       (uint32_t)&s_authStatus, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareInstallCerficate
 * Description   : Prepares the HSM command that installs the information of public key certificate.
 *
 *END**************************************************************************/
void HSM_PrepareInstallCerficate(uint32_t keyID, uint32_t authKeyID, const uint8_t *certificate,
                                 uint32_t certificateLen)
{
    uint32_t cmd = 0U;

    /* Set command code */
    cmd = (uint32_t)HSM_CMD_ASYM_INSTALL_CERTIFICATE;

    HSM_PrepareCommand(cmd, keyID, authKeyID,(uint32_t) certificate, certificateLen,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareKeyPairGen
 * Description   : Prepares the HSM command that shares the DH public key to HOST.
 *
 *END**************************************************************************/
void HSM_PrepareKeyPairGen(uint32_t gBase, uint32_t pModulus, uint32_t *pubKeyLen, uint8_t *pubKey)
{
    uint32_t cmd = 0U;

    /* Set command code */
    cmd = (uint32_t)HSM_CMD_ASYM_DH_RSA_KEY_PAIR_GEN;

    HSM_PrepareCommand(cmd, gBase, pModulus, (uint32_t)pubKeyLen, (uint32_t)pubKey,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareSharedSecret
 * Description   : Prepares the HSM command that computes change of keys for DH.
 *
 *END**************************************************************************/
void HSM_PrepareSharedSecret(uint32_t keyID, uint32_t keyLen, const uint8_t* key)
{
    uint32_t cmd = 0U;

    /* Set command code */
    cmd = (uint32_t)HSM_CMD_ASYM_COMPUTE_SHARED_SECRET;

    HSM_PrepareCommand(cmd, keyID, keyLen, (uint32_t)key, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareGenerateExtendedRamKeys
 * Description   : Prepares the HSM command that generates the session keys.
 *
 *END**************************************************************************/
void HSM_PrepareGenerateExtendedRamKeys(uint32_t keyID, uint32_t kdfType, uint8_t *kdf)
{
    uint32_t cmd = 0U;

    /* Set command code */
    cmd = (uint32_t)HSM_CMD_ASYM_GENERATE_EXTENDED_RAM_KEYS;

    HSM_PrepareCommand(cmd, keyID, kdfType, (uint32_t)kdf, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PreparePseudoRandomTLS
 * Description   : Prepares the HSM command that generates and verifies the finished message.
 *
 *END**************************************************************************/
void HSM_PreparePseudoRandomTLS(uint32_t keyID, uint32_t masterSeedLen, const uint8_t *masterSeed,
                                uint32_t seedLen, const uint8_t *seed, uint32_t msgLen, uint8_t *msg)
{
    uint32_t cmd = 0U;

    /* Set command code */
    cmd = (uint32_t)HSM_CMD_ASYM_TLS_PRF;

    HSM_PrepareCommand(cmd, keyID, masterSeedLen, (uint32_t)masterSeed, seedLen,
                       (uint32_t)seed, msgLen, (uint32_t)msg, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareExportExtendedRamKeyss
 * Description   : Prepares the HSM command that export the RAM key.
 *
 *END**************************************************************************/
void HSM_PrepareExportExtendedRamKeys(uint32_t keyID, uint32_t alg, uint32_t rsa_encr,
                                      uint32_t *outBufLen, uint8_t *expKey, uint32_t *expKeyLen)
{
    uint32_t cmd = 0U;
    (void)alg;
    /* Set command code */
    cmd = (uint32_t)HSM_CMD_ASYM_EXPORT_EXTENDED_RAM_KEY;

    HSM_PrepareCommand(cmd, keyID, HSM_RSA_ENCRYPTION_ALG, (uint32_t) rsa_encr,
                       (uint32_t)outBufLen, (uint32_t)expKey, (uint32_t)expKeyLen, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareSHA256
 * Description   : Prepares the HSM command that computes SHA256.
 *
 *END**************************************************************************/
void HSM_PrepareSHA256(uint32_t msgLen, const uint8_t *msg, uint8_t *hash)
{
    uint32_t cmd = 0U;

    /* Set command code */
    cmd = (uint32_t)HSM_CMD_HASH_SHA256;

    HSM_PrepareCommand(cmd, msgLen,(uint32_t) msg, (uint32_t)hash, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareHMAC256
 * Description   : Prepares the HSM command that computes HMAC256.
 *
 *END**************************************************************************/
void HSM_PrepareHMAC256(uint32_t keyID, uint32_t msgLen, const uint8_t *msg, uint32_t *hashLen, uint8_t *hash)
{
    uint32_t cmd = 0U;

    /* Set command code */
    cmd = (uint32_t)HSM_CMD_HASH_HMAC256;

    HSM_PrepareCommand(cmd, keyID, msgLen,(uint32_t) msg, (uint32_t)hashLen,(uint32_t) hash,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareEncryptGCM
 * Description   : Prepares the HSM command that computes AES encryption in GCM mode.
 *
 *END**************************************************************************/
void HSM_PrepareEncryptGCM(uint32_t keyID, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                           const uint8_t *authData, uint32_t plainTextLen, const uint8_t *plainText,
                           uint8_t *cipherText, uint32_t tagLen, uint8_t *tag)
{
    uint32_t cmd = 0U;
    uint32_t cmdKeyID = 0U;

    /* Set command code */
    cmd = (uint32_t)HSM_CMD_SYM_AES_GCM_ENC;

    /* Check the key bank and update command accordingly */
    if (HSM_CMD_KBS(keyID) != 0U)
    {
        cmd |=(uint32_t) HSM_CMD_KBS_MASK;
    }

	/* Get the command key ID (strip the KBS bit) */
    cmdKeyID = HSM_CMD_KEY_ID(keyID);

    HSM_PrepareCommand(cmd, cmdKeyID, ivLen, (uint32_t) iv, authDataLen, (uint32_t) authData, plainTextLen,
                       (uint32_t)plainText, (uint32_t)cipherText, tagLen, (uint32_t)tag, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareEncryptCCM
 * Description   : Prepares the HSM command that computes AES encryption in CCM mode.
 *
 *END**************************************************************************/
void HSM_PrepareEncryptCCM(uint32_t keyID, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                           const uint8_t *authData, uint32_t plainTextLen, const uint8_t *plainText,
                           uint8_t *cipherText, uint32_t tagLen, uint8_t *tag)
{
    uint32_t cmd = 0U;
    uint32_t cmdKeyID = 0U;

    /* Set command code */
    cmd = (uint32_t)HSM_CMD_SYM_AES_CCM_ENC;

    /* Check the key bank and update command accordingly */
    if (HSM_CMD_KBS(keyID) != 0U)
    {
        cmd |= (uint32_t)HSM_CMD_KBS_MASK;
    }

	/* Get the command key ID (strip the KBS bit) */
    cmdKeyID = HSM_CMD_KEY_ID(keyID);

    HSM_PrepareCommand(cmd, cmdKeyID, ivLen, (uint32_t) iv, authDataLen, (uint32_t)authData, plainTextLen,
                       (uint32_t) plainText, (uint32_t)cipherText, tagLen, (uint32_t)tag, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareEncryptOFB
 * Description   : Prepares the HSM command that computes AES encryption in OFB mode.
 *
 *END**************************************************************************/
void HSM_PrepareEncryptOFB(uint32_t keyID, const uint8_t *iv, uint32_t length,
                           const uint8_t *plainText, uint8_t *cipherText)
{
    uint32_t cmd = 0U;
    uint32_t cmdKeyID = 0U;
    /* Set command code */
    cmd = (uint32_t)HSM_CMD_SYM_AES_OFB_ENC;

    /* Check the key bank and update command accordingly */
    if (HSM_CMD_KBS(keyID) != 0U)
    {
        cmd |= (uint32_t)HSM_CMD_KBS_MASK;
    }

	/* Get the command key ID (strip the KBS bit) */
    cmdKeyID = HSM_CMD_KEY_ID(keyID);

    HSM_PrepareCommand(cmd, cmdKeyID, (uint32_t) iv, HSM_BUFF_BLOCK_COUNT(length), (uint32_t)plainText,
                       (uint32_t)cipherText, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareEncryptCTR
 * Description   : Prepares the HSM command that computes AES encryption in CTR mode.
 *
 *END**************************************************************************/
void HSM_PrepareEncryptCTR(uint32_t keyID, const uint8_t *iv, uint32_t length,
                           const uint8_t *plainText, uint8_t *cipherText)
{
    uint32_t cmd = 0U;
    uint32_t cmdKeyID = 0U;

    /* Set command code */
    cmd = (uint32_t)HSM_CMD_SYM_AES_CTR_ENC;

    /* Check the key bank and update command accordingly */
    if (HSM_CMD_KBS(keyID) != 0U)
    {
        cmd |= (uint32_t)HSM_CMD_KBS_MASK;
    }

	/* Get the command key ID (strip the KBS bit) */
    cmdKeyID = HSM_CMD_KEY_ID(keyID);

    HSM_PrepareCommand(cmd, cmdKeyID, (uint32_t)iv, HSM_BUFF_BLOCK_COUNT(length), (uint32_t)plainText,
                       (uint32_t)cipherText, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);

}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareEncryptCFB
 * Description   : Prepares the HSM command that computes AES encryption in CFB mode.
 *
 *END**************************************************************************/
void HSM_PrepareEncryptCFB(uint32_t keyID, const uint8_t *iv, uint32_t length,
                           const uint8_t *plainText, uint8_t *cipherText)
{
    uint32_t cmd = 0U;
    uint32_t cmdKeyID = 0U;

    /* Set command code */
    cmd = (uint32_t)HSM_CMD_SYM_AES_CFB_ENC;

    /* Check the key bank and update command accordingly */
    if (HSM_CMD_KBS(keyID) != 0U)
    {
        cmd |= (uint32_t)HSM_CMD_KBS_MASK;
    }

    /* Get the command key ID (strip the KBS bit) */
    cmdKeyID = HSM_CMD_KEY_ID(keyID);

    HSM_PrepareCommand(cmd, cmdKeyID, (uint32_t)iv, HSM_BUFF_BLOCK_COUNT(length), (uint32_t)plainText,
                       (uint32_t)cipherText, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareEncryptXTS
 * Description   : Prepares the HSM command that computes AES encryption in XTS mode.
 *
 *END**************************************************************************/
void HSM_PrepareEncryptXTS(uint32_t keyID1, uint32_t keyID2, const uint8_t *iv, uint32_t length,
                           const uint8_t *plainText, uint8_t *cipherText)
{
    uint32_t cmd = 0U;
    uint32_t cmdKeyID1 = 0U;
    uint32_t cmdKeyID2 = 0U;

    /* Set command code */
    cmd = (uint32_t)HSM_CMD_SYM_AES_XTS_ENC;

    /* Check the key for block encryption bank and update command accordingly */
    if (HSM_CMD_KBS(keyID2) != 0U)
    {
        cmd |= (uint32_t)HSM_CMD_KBS_MASK;
    }

    /* Get the command key ID (strip the KBS bit) */
    cmdKeyID1 = HSM_CMD_KEY_ID(keyID1);
    cmdKeyID2 = HSM_CMD_KEY_ID(keyID2);

    HSM_PrepareCommand(cmd, cmdKeyID1, cmdKeyID2, (uint32_t) iv, HSM_BUFF_BLOCK_COUNT(length), (uint32_t) plainText,
                       (uint32_t)cipherText, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);

}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareDecryptGCM
 * Description   : Prepares the HSM command that computes AES decryption in GCM mode.
 *
 *END**************************************************************************/
void HSM_PrepareDecryptGCM(uint32_t keyID, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                           const uint8_t *authData, uint32_t cipherTextLen, const uint8_t *cipherText,
                           uint8_t *decryptedText, uint32_t tagLen, const uint8_t *tag)
{
    uint32_t cmd = 0U;
    uint32_t cmdKeyID = 0U;

    /* Set command code */
    cmd = (uint32_t)HSM_CMD_SYM_AES_GCM_DEC;

    /* Check the key bank and update command accordingly */
    if (HSM_CMD_KBS(keyID) != 0U)
    {
        cmd |= (uint32_t)HSM_CMD_KBS_MASK;
    }

    /* Get the command key ID (strip the KBS bit) */
    cmdKeyID = HSM_CMD_KEY_ID(keyID);

    HSM_PrepareCommand(cmd, cmdKeyID, ivLen, (uint32_t) iv, authDataLen, (uint32_t)authData, cipherTextLen,
                       (uint32_t)cipherText, (uint32_t)decryptedText, tagLen, (uint32_t)tag, (uint32_t)&s_authStatus);

}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareDecryptCCM
 * Description   : Prepares the HSM command that computes AES decryption in CCM mode.
 *
 *END**************************************************************************/
void HSM_PrepareDecryptCCM(uint32_t keyID, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                           const uint8_t *authData, uint32_t cipherTextLen, const uint8_t *cipherText,
                           uint8_t *decryptedText, uint32_t tagLen, const uint8_t *tag)
{
    uint32_t cmd = 0U;
    uint32_t cmdKeyID = 0U;

    /* Set command code */
    cmd = (uint32_t)HSM_CMD_SYM_AES_CCM_DEC;

    /* Check the key bank and update command accordingly */
    if (HSM_CMD_KBS(keyID) != 0U)
    {
        cmd |= (uint32_t)HSM_CMD_KBS_MASK;
    }

    /* Get the command key ID (strip the KBS bit) */
    cmdKeyID = HSM_CMD_KEY_ID(keyID);

    HSM_PrepareCommand(cmd, cmdKeyID, ivLen, (uint32_t) iv, authDataLen, (uint32_t)authData, cipherTextLen,
                       (uint32_t)cipherText, (uint32_t)decryptedText, tagLen, (uint32_t)tag, (uint32_t)&s_authStatus);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareDecryptOFB
 * Description   : Prepares the HSM command that computes AES decryption in OFB mode.
 *
 *END**************************************************************************/
void HSM_PrepareDecryptOFB(uint32_t keyID, const uint8_t *iv, uint32_t length,
                           const uint8_t *cipherText, uint8_t *decryptedText)
{
    uint32_t cmd = 0U;
    uint32_t cmdKeyID = 0U;

    /* Set command code */
    cmd = (uint32_t)HSM_CMD_SYM_AES_OFB_DEC;

    /* Check the key bank and update command accordingly */
    if (HSM_CMD_KBS(keyID) != 0U)
    {
        cmd |= HSM_CMD_KBS_MASK;
    }

    /* Get the command key ID (strip the KBS bit) */
    cmdKeyID = HSM_CMD_KEY_ID(keyID);

    HSM_PrepareCommand(cmd, cmdKeyID, (uint32_t) iv, HSM_BUFF_BLOCK_COUNT(length), (uint32_t) cipherText,
                       (uint32_t) decryptedText, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareDecryptCTR
 * Description   : Prepares the HSM command that computes AES decryption in CTR mode.
 *
 *END**************************************************************************/
void HSM_PrepareDecryptCTR(uint32_t keyID, const uint8_t *iv, uint32_t length,
                           const uint8_t *cipherText, uint8_t *decryptedText)
{
    uint32_t cmd = 0U;
    uint32_t cmdKeyID = 0U;

    /* Set command code */
    cmd = (uint32_t)HSM_CMD_SYM_AES_CTR_DEC;

    /* Check the key bank and update command accordingly */
    if (HSM_CMD_KBS(keyID) != 0U)
    {
        cmd |= (uint32_t)HSM_CMD_KBS_MASK;
    }

    /* Get the command key ID (strip the KBS bit) */
    cmdKeyID = HSM_CMD_KEY_ID(keyID);

    HSM_PrepareCommand(cmd, cmdKeyID, (uint32_t) iv, HSM_BUFF_BLOCK_COUNT(length), (uint32_t) cipherText,
                       (uint32_t) decryptedText, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareDecryptCFB
 * Description   : Prepares the HSM command that computes AES decryption in CFB mode.
 *
 *END**************************************************************************/
void HSM_PrepareDecryptCFB(uint32_t keyID, const uint8_t *iv, uint32_t length,
                           const uint8_t *cipherText, uint8_t *decryptedText)
{
	uint32_t cmd = 0U;
	uint32_t cmdKeyID = 0U;

    cmd = (uint32_t)HSM_CMD_SYM_AES_CFB_DEC;

    /* Check the key bank and update command accordingly */
    if (HSM_CMD_KBS(keyID) != 0U)
    {
        cmd |= (uint32_t)HSM_CMD_KBS_MASK;
    }

    /* Get the command key ID (strip the KBS bit) */
    cmdKeyID = HSM_CMD_KEY_ID(keyID);

    HSM_PrepareCommand(cmd, cmdKeyID, (uint32_t) iv, HSM_BUFF_BLOCK_COUNT(length), (uint32_t) cipherText,
                       (uint32_t) decryptedText, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareDecryptXTS
 * Description   : Prepares the HSM command that computes AES decryption in XTS mode.
 *
 *END**************************************************************************/
void HSM_PrepareDecryptXTS(uint32_t keyID1, uint32_t keyID2, const uint8_t *iv,
                           uint32_t length, const uint8_t *cipherText, uint8_t *decryptedText)
{
    uint32_t cmd = 0U;
    uint32_t cmdKeyID1 = 0U;
    uint32_t cmdKeyID2 = 0U;

    cmd = (uint32_t)HSM_CMD_SYM_AES_XTS_DEC;

    /* Check the key bank and update command accordingly */
    if (HSM_CMD_KBS(keyID2) != 0U)
    {
        cmd |= HSM_CMD_KBS_MASK;
    }

    /* Get the command key ID (strip the KBS bit) */
    cmdKeyID1 = HSM_CMD_KEY_ID(keyID1);
    cmdKeyID2 = HSM_CMD_KEY_ID(keyID2);

    HSM_PrepareCommand(cmd, cmdKeyID1, cmdKeyID2, (uint32_t) iv, HSM_BUFF_BLOCK_COUNT(length), (uint32_t) cipherText,
                       (uint32_t)decryptedText, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}

/*FUNCTION**********************************************************************
 *
 * Function Name : HSM_PrepareEraseExtendedRamKey
 * Description   : Prepares the HSM command that erases the keys of RAM catalog.
 *
 *END**************************************************************************/
void HSM_PrepareEraseExtendedRamKey(uint32_t keyID)
{
    uint32_t cmd = 0U;

    cmd = (uint32_t)HSM_CMD_SYM_ERASE_EXTENDED_RAM_KEY;

    HSM_PrepareCommand(cmd, keyID, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM,
                       HSM_UNUSED_PARAM, HSM_UNUSED_PARAM, HSM_UNUSED_PARAM);
}


/*******************************************************************************
 * EOF
 ******************************************************************************/
