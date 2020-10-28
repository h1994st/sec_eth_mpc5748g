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

#ifndef HSM_DRV_H
#define HSM_DRV_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "status.h"
#include "osif.h"
#include "callbacks.h"

/*!
 * @page misra_violations MISRA-C:2012 violations
 *
 * @section [global]
 * Violates MISRA 2012 Advisory Rule 2.3, Global typedef not referenced.
 * Some types are defined to be used by hsm driver only, not used by Security PAL.
 */

/*! @file hsm_driver.h */

/*!
 * @addtogroup hsm_driver
 * @{
 */

/*!
 * @brief KeyID - identifies cryptographic keys.
 *
 * Implements : hsm_key_id_t_Class
 */
typedef enum {
    /* SHE-based Symmetric Keys */
    HSM_SECRET_KEY = 0x0U,
    HSM_MASTER_ECU,
    HSM_BOOT_MAC_KEY,
    HSM_BOOT_MAC,
    HSM_KEY_1,
    HSM_KEY_2,
    HSM_KEY_3,
    HSM_KEY_4,
    HSM_KEY_5,
    HSM_KEY_6,
    HSM_KEY_7,
    HSM_KEY_8,
    HSM_KEY_9,
    HSM_KEY_10,
    HSM_RAM_KEY,
    HSM_KEY_11 = 0x14U,
    HSM_KEY_12,
    HSM_KEY_13,
    HSM_KEY_14,
    HSM_KEY_15,
    HSM_KEY_16,
    HSM_KEY_17,
    HSM_KEY_18,
    HSM_KEY_19,
    HSM_KEY_20,
    /* NVM Catalog - Asymmetric Keys */
    HSM_ROOT_CERT = 0x10000,
    HSM_CERTIFICATE_REVOCATION,
    HSM_KEY1_CERT,
    HSM_KEY2_CERT,
    HSM_KEY3_CERT,
    HSM_KEY4_CERT,
    HSM_KEY5_CERT,
    HSM_KEY6_CERT,
    HSM_KEY7_CERT,
    HSM_KEY8_CERT,
    HSM_KEY9_CERT,
    HSM_KEY10_CERT,
    /* RAM Catalog - AES-128 Symmetric Keys */
    HSM_RAM_KEY1 = 0x1000000,
    HSM_RAM_KEY2,
    HSM_RAM_KEY3,
    HSM_RAM_KEY4,
    HSM_RAM_KEY5,
    HSM_RAM_KEY6,
    HSM_RAM_KEY7,
    HSM_RAM_KEY8,
    HSM_RAM_KEY9,
    HSM_RAM_KEY10,
    /* RAM Catalog - RSA Asymmetric Public Keys */
    HSM_RSA_ASYMM_RAM_KEY1 = 0x1010000,
    HSM_RSA_ASYMM_RAM_KEY2,
    /* RAM Catalog - HMAC keys */
    HSM_HMAC_KEY1 = 0x1020000,
    HSM_HMAC_KEY2,
    /* RAM Catalog - Diffie Hellman RSA Secret */
    HSM_RSA_DIFFIE_HELLMAN_KEY1 = 0x1030000,
    HSM_RSA_DIFFIE_HELLMAN_KEY2,
    /* RAM Catalog - RSA Random Shared Secret */
    HSM_RSA_RANDOM_KEY1 = 0x1040000,
    HSM_RSA_RANDOM_KEY2
} hsm_key_id_t;

/*!
 * @brief HSM commands which follow the same values as the SHE command definition.
 *
 * Implements : hsm_cmd_t_Class
 */
typedef enum {
    /* SHE Commands */
    HSM_CMD_NONE = 0U,
    HSM_CMD_ENC_ECB,
    HSM_CMD_ENC_CBC,
    HSM_CMD_DEC_ECB,
    HSM_CMD_DEC_CBC,
    HSM_CMD_GENERATE_MAC,
    HSM_CMD_VERIFY_MAC,
    HSM_CMD_LOAD_KEY,
    HSM_CMD_LOAD_PLAIN_KEY,
    HSM_CMD_EXPORT_RAM_KEY,
    HSM_CMD_INIT_RNG,
    HSM_CMD_EXTEND_SEED,
    HSM_CMD_RND,
    HSM_CMD_SECURE_BOOT,
    HSM_CMD_BOOT_FAILURE,
    HSM_CMD_BOOT_OK,
    HSM_CMD_GET_ID,
    HSM_CMD_CANCEL,
    HSM_CMD_DBG_CHAL,
    HSM_CMD_DBG_AUTH,
    HSM_CMD_TRNG_RND,
    HSM_CMD_GET_VER,
    HSM_CMD_CHANGE_TRNG_CLK_SOURCE,
    /* Extended Symmetric Commands */
    HSM_CMD_SYM_AES_GCM_ENC = 0x00010001,
    HSM_CMD_SYM_AES_CCM_ENC,
    HSM_CMD_SYM_AES_OFB_ENC,
    HSM_CMD_SYM_AES_CTR_ENC,
    HSM_CMD_SYM_AES_CFB_ENC,
    HSM_CMD_SYM_AES_XTS_ENC,
    HSM_CMD_SYM_AES_GCM_DEC,
    HSM_CMD_SYM_AES_CCM_DEC,
    HSM_CMD_SYM_AES_OFB_DEC,
    HSM_CMD_SYM_AES_CTR_DEC,
    HSM_CMD_SYM_AES_CFB_DEC,
    HSM_CMD_SYM_AES_XTS_DEC,
    HSM_CMD_SYM_ERASE_EXTENDED_RAM_KEY,
    /* Hash Commands */
    HSM_CMD_HASH_SHA256 = 0x00020001,
    HSM_CMD_HASH_HMAC256,
    /* Asymmetric Commands */
    HSM_CMD_ASYM_RSA_PKCS_ENC = 0x00030001,
    HSM_CMD_ASYM_RSA_PKCS_VERIFY_MSG,
    HSM_CMD_ASYM_RSA_PKCS_VERIFY_HASH,
    HSM_CMD_ASYM_INSTALL_CERTIFICATE,
    HSM_CMD_ASYM_DH_RSA_KEY_PAIR_GEN,
    HSM_CMD_ASYM_COMPUTE_SHARED_SECRET,
    HSM_CMD_ASYM_GENERATE_EXTENDED_RAM_KEYS,
    HSM_CMD_ASYM_TLS_PRF,
    HSM_CMD_ASYM_EXPORT_EXTENDED_RAM_KEY
} hsm_cmd_t;

/*!
 * @brief Specifies how the public key is passed to the HSM firmware.
 *
 * Implements : hsm_key_mode_t_Class
 */
typedef enum {
    HSM_KEY_ID,     /*!< Public key used is already stored in the HSM key area, identified by key ID */
    HSM_KEY_ADDR,   /*!< Public key is passed as a structure defining modulus and exponent (hsm_public_key_t) */
    HSM_KEY_ASN     /*!< Public key encoded in ASN format, passed as an array of bytes */
} hsm_key_mode_t;

/*!
 * @brief Specifies the padding algorithm version.
 *
 * Implements : hsm_pkcs_padding_t_Class
 */
typedef enum {
    PKCS = 0x00,     /*!< PKCS V 1.5 Encoding */
    OAEP             /*!< OAEP Encoding */
} hsm_pkcs_padding_t;

/*!
 * @brief Specifies the key derivation function.
 *
 * Implements : hsm_kdf_t_Class
 */
typedef enum {
    RANDOM_KEY = 0x00,
    TLS_PRF
} hsm_kdf_t;

/*!
 * @brief Structure describing the random key derivation parameters.
 *
 * Implements : hsm_random_kdf_t_Class
 */
typedef struct {
    uint32_t randomKeyId;
    uint32_t randomKeySize;
} hsm_random_kdf_t;

/*!
 * @brief Structure describing the base g of the domain parameters.
 *
 * Implements : hsm_g_base_t_Class
 */
typedef struct {
    uint32_t baseSize;
    uint8_t *base;
} hsm_g_base_t;

/*!
 * @brief Structure describing the modulus p of the domain parameters.
 *
 * Implements : hsm_p_modulus_t_Class
 */
typedef struct {
    uint32_t modulusSize;
    uint8_t *modulus;
} hsm_p_modulus_t;

/*!
 * @brief Structure describing the parameters for TLS 1.2 key derivation function.
 *
 * Implements : hsm_tls_kdf_t_Class
 */
typedef struct {
    uint32_t masterKeySeedLen;
    uint32_t *masterKeySeed;
    uint32_t keyExpansionSeedLen;
    uint32_t *keyExpansionSeed;
    uint32_t clientKeyMAC;
    uint32_t serverKeyMAC;
    uint32_t clientKey;
    uint32_t serverKey;
    uint32_t ivSize;
    uint32_t *clientIV;
    uint32_t *serverIV;
} hsm_tls_kdf_t;

/*!
 * @brief Structure describing the parameters for the RSA encryption algorithm.
 *
 * Implements : hsm_rsa_algorithm_t_Class
 */
typedef struct {
    hsm_key_id_t keyId;
    uint32_t pkcsVersion;
    uint32_t labelLen;
    uint32_t *label;
} hsm_rsa_algorithm_t;

/*!
 * @brief Structure describing the parameters for a public key handled externally by the application.
 *
 * Implements : hsm_public_key_t_Class
 */
typedef struct {
    uint32_t exponentSize;
    uint32_t modulusSize;
    uint8_t *exponent;
    uint8_t *modulus;
} hsm_public_key_t;

/*!
 * @brief Internal driver state information.
 *
 * @note The contents of this structure are internal to the driver and should not be
 *       modified by users. Also, contents of the structure are subject to change in
 *       future releases.
 *
 * Implements : hsm_state_t_Class
 */
typedef struct {
    bool cmdInProgress;           /*!< Specifies if a command is in progress */
    bool blockingCmd;             /*!< Specifies if a command is blocking or asynchronous */
    hsm_cmd_t cmd;                /*!< Specifies the type of the command in execution */
    security_callback_t callback; /*!< The callback invoked when a command is complete */
    void *callbackParam;          /*!< User parameter for the command completion callback */
    semaphore_t cmdComplete;      /*!< Synchronization object for synchronous operation */
    status_t cmdStatus;           /*!< Error code for the last command */
    bool rngInit;                 /*!< Specifies if the internal RNG state is initialized */
    bool *verifStatus;            /*!< Specifies the result of the last executed MAC/signature verification command */
    uint32_t fwVersion;           /*!< Specifies the HSM firmware version */
} hsm_state_t;


/*******************************************************************************
 * API
 ******************************************************************************/

#if defined(__cplusplus)
extern "C" {
#endif

/*!
 * @defgroup hsm_driver_she SHE API
 * @ingroup hsm_driver
 * @addtogroup hsm_driver_she
 * @{
 */

/*!
 * @brief Initializes the internal state of the driver and enables the HSM interrupt.
 *
 * @param[in] state Pointer to the state structure which will be used for holding
 * the internal state of the driver.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_Init(hsm_state_t *state);

/*!
 * @brief Clears the internal state of the driver and disables the HSM interrupt.
 *
 * @return STATUS_SUCCESS.
 */
status_t HSM_DRV_Deinit(void);

/*!
 * @brief Installs a user callback for the command complete event.
 *
 * This function installs a user callback for the command complete event.
 *
 * @return Pointer to the previous callback.
 */
security_callback_t HSM_DRV_InstallCallback(security_callback_t callbackFunction, void * callbackParam);

/*!
 * @brief Performs the AES-128 encryption in ECB mode.
 *
 * This function performs the AES-128 encryption in ECB mode of the input
 * plain text buffer
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] plainText Pointer to the plain text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of plain text message to be encrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[out] cipherText Pointer to the cipher text buffer. The buffer shall
 * have the same size as the plain text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_EncryptECB(hsm_key_id_t keyId, const uint8_t *plainText,
                            uint32_t length, uint8_t *cipherText, uint32_t timeout);

/*!
 * @brief Performs the AES-128 decryption in ECB mode.
 *
 * This function performs the AES-128 decryption in ECB mode of the input
 * cipher text buffer.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation
 * @param[in] cipherText Pointer to the cipher text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of cipher text message to be decrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[out] plainText Pointer to the plain text buffer. The buffer shall
 * have the same size as the cipher text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_DecryptECB(hsm_key_id_t keyId, const uint8_t *cipherText,
                             uint32_t length, uint8_t *plainText, uint32_t timeout);

/*!
 * @brief Performs the AES-128 encryption in CBC mode.
 *
 * This function performs the AES-128 encryption in CBC mode of the input
 * plaintext buffer.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] plainText Pointer to the plain text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of plain text message to be encrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] cipherText Pointer to the cipher text buffer. The buffer shall
 * have the same size as the plain text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_EncryptCBC(hsm_key_id_t keyId, const uint8_t *plainText, uint32_t length,
                            const uint8_t *iv, uint8_t *cipherText, uint32_t timeout);

/*!
 * @brief Performs the AES-128 decryption in CBC mode.
 *
 * This function performs the AES-128 decryption in CBC mode of the input
 * cipher text buffer.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] cipherText Pointer to the cipher text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of cipher text message to be decrypted.
 * It should be multiple of 16 bytes.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] plainText Pointer to the plain text buffer. The buffer shall
 * have the same size as the cipher text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_DecryptCBC(hsm_key_id_t keyId, const uint8_t *cipherText, uint32_t length,
                            const uint8_t* iv, uint8_t *plainText, uint32_t timeout);

/*!
 * @brief Calculates the MAC of a given message using CMAC with AES-128.
 *
 * This function calculates the MAC of a given message using CMAC with AES-128.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] msg Pointer to the message buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] msgLen Number of bits of message on which CMAC will be computed.
 * @param[out] mac Pointer to the buffer containing the result of the CMAC
 * computation.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_GenerateMAC(hsm_key_id_t keyId, const uint8_t *msg,
                             uint64_t msgLen, uint8_t *mac, uint32_t timeout);

/*!
 * @brief Verifies the MAC of a given message using CMAC with AES-128.
 *
 * This function verifies the MAC of a given message using CMAC with AES-128.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] msg Pointer to the message buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] msgLen Number of bits of message on which CMAC will be computed.
 * @param[in] mac Pointer to the buffer containing the CMAC to be verified.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] macLen Number of bits of the CMAC to be compared. A macLength
 * value of zero indicates that all 128-bits are compared.
 * @param[out] verifStatus Status of MAC verification command (true:
 * verification operation passed, false: verification operation failed).
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_VerifyMAC(hsm_key_id_t keyId, const uint8_t *msg, uint64_t msgLen,
                           const uint8_t *mac, uint8_t macLen,
                           bool *verifStatus, uint32_t timeout);

/*!
 * @brief Asynchronously performs the AES-128 encryption in ECB mode.
 *
 * This function performs the AES-128 encryption in ECB mode of the input
 * plain text buffer, in an asynchronous manner.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] plainText Pointer to the plain text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of plain text message to be encrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[out] cipherText Pointer to the cipher text buffer. The buffer shall
 * have the same size as the plain text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_EncryptECBAsync(hsm_key_id_t keyId, const uint8_t *plainText,
                                 uint32_t length, uint8_t *cipherText);

/*!
 * @brief Asynchronously performs the AES-128 decryption in ECB mode.
 *
 * This function performs the AES-128 decryption in ECB mode of the input
 * cipher text buffer, in an asynchronous manner.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation
 * @param[in] cipherText Pointer to the cipher text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of cipher text message to be decrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[out] plainText Pointer to the plain text buffer. The buffer shall
 * have the same size as the cipher text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_DecryptECBAsync(hsm_key_id_t keyId, const uint8_t *cipherText,
                                  uint32_t length, uint8_t *plainText);

/*!
 * @brief Asynchronously performs the AES-128 encryption in CBC mode.
 *
 * This function performs the AES-128 encryption in CBC mode of the input
 * plaintext buffer, in an asynchronous manner.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] plainText Pointer to the plain text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of plain text message to be encrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] cipherText Pointer to the cipher text buffer. The buffer shall
 * have the same size as the plain text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_EncryptCBCAsync(hsm_key_id_t keyId, const uint8_t *plainText,
                                 uint32_t length, const uint8_t *iv, uint8_t *cipherText);

/*!
 * @brief Asynchronously performs the AES-128 decryption in CBC mode.
 *
 * This function performs the AES-128 decryption in CBC mode of the input
 * cipher text buffer, in an asynchronous manner.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] cipherText Pointer to the cipher text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of cipher text message to be decrypted.
 * It should be multiple of 16 bytes.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] plainText Pointer to the plain text buffer. The buffer shall
 * have the same size as the cipher text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_DecryptCBCAsync(hsm_key_id_t keyId, const uint8_t *cipherText,
                                 uint32_t length, const uint8_t* iv, uint8_t *plainText);

/*!
 * @brief Asynchronously calculates the MAC of a given message using CMAC with AES-128.
 *
 * This function calculates the MAC of a given message using CMAC with AES-128,
 * in an asynchronous manner.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] msg Pointer to the message buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] msgLen Number of bits of message on which CMAC will be computed.
 * @param[out] mac Pointer to the buffer containing the result of the CMAC
 * computation.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_GenerateMACAsync(hsm_key_id_t keyId, const uint8_t *msg,
                                  uint64_t msgLen, uint8_t *mac);

/*!
 * @brief Asynchronously verifies the MAC of a given message using CMAC with AES-128.
 *
 * This function verifies the MAC of a given message using CMAC with AES-128,
 * in an asynchronous manner.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] msg Pointer to the message buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] msgLen Number of bits of message on which CMAC will be computed.
 * @param[in] mac Pointer to the buffer containing the CMAC to be verified.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] macLen Number of bits of the CMAC to be compared. A macLength
 * value of zero indicates that all 128-bits are compared.
 * @param[out] verifStatus Status of MAC verification command (true:
 * verification operation passed, false: verification operation failed).
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_VerifyMACAsync(hsm_key_id_t keyId, const uint8_t *msg, uint64_t msgLen,
                                const uint8_t *mac, uint8_t macLen, bool *verifStatus);

/*!
 * @brief Updates an internal key per the SHE specification.
 *
 * This function updates an internal key per the SHE specification.
 *
 * @param[in] keyId KeyID of the key to be updated.
 * @param[in] m1 Pointer to the 128-bit M1 message containing the UID, Key ID
 * and Authentication Key ID.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] m2 Pointer to the 256-bit M2 message contains the new security
 * flags, counter and the key value all encrypted using a derived key generated
 * from the Authentication Key.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] m3 Pointer to the 128-bit M3 message is a MAC generated over
 * messages M1 and M2.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] m4 Pointer to a 256 bits buffer where the computed M4 parameter
 * is stored.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] m5 Pointer to a 128 bits buffer where the computed M5 parameter
 * is stored.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_LoadKey(hsm_key_id_t keyId, const uint8_t *m1, const uint8_t *m2,
                         const uint8_t *m3, uint8_t *m4, uint8_t *m5, uint32_t timeout);

/*!
 * @brief Updates the RAM key memory slot with a 128-bit plaintext.
 *
 * The function updates the RAM key memory slot with a 128-bit plaintext. The
 * key is loaded without encryption and verification of the key, i.e. the key is
 * handed over in plaintext. A plain key can only be loaded into the RAM_KEY
 * slot.
 *
 * @param[in] plainKey Pointer to the 128-bit buffer containing the key that
 * needs to be copied in RAM_KEY slot.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_LoadPlainKey(const uint8_t *plainKey, uint32_t timeout);

/*!
 * @brief Exports the RAM_KEY into a format compatible with the messages
 * used for LOAD_KEY.
 *
 * @param[out] m1 Pointer to a buffer where the M1 parameter will be exported.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] m2 Pointer to a buffer where the M2 parameter will be exported.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] m3 Pointer to a buffer where the M3 parameter will be exported.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] m4 Pointer to a buffer where the M4 parameter will be exported.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] m5 Pointer to a buffer where the M5 parameter will be exported.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_ExportRAMKey(uint8_t *m1, uint8_t *m2, uint8_t *m3,
                              uint8_t *m4, uint8_t *m5, uint32_t timeout);

/*!
 * @brief Initializes the seed for the PRNG.
 *
 * The function must be called before CMD_RND after every power cycle/reset.
 *
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_InitRNG(uint32_t timeout);

/*!
 * @brief Extends the seed of the PRNG.
 *
 * Extends the seed of the PRNG by compressing the former seed value and the
 * supplied entropy into a new seed. This new seed is then to be used to
 * generate a random number by invoking the CMD_RND command. The random number
 * generator must be initialized by CMD_INIT_RNG before the seed may be
 * extended.
 *
 * @param[in] entropy Pointer to a 128-bit buffer containing the entropy.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_ExtendSeed(const uint8_t *entropy, uint32_t timeout);

/*!
 * @brief Generates a vector of 128 random bits.
 *
 * The function returns a vector of 128 random bits. The random number generator
 * has to be initialized by calling HSM_DRV_InitRNG before random numbers can
 * be supplied.
 *
 * @param[out] rnd Pointer to a 128-bit buffer where the generated random number
 * has to be stored.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_GenerateRND(uint8_t *rnd, uint32_t timeout);

/*!
 * @brief Returns the identity (UID) and the value of the status register
 * protected by a MAC over a challenge and the data.
 *
 * This function returns the identity (UID) and the value of the status register
 * protected by a MAC over a challenge and the data.
 *
 * @param[in] challenge Pointer to the 128-bit buffer containing Challenge data.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] uid Pointer to 120 bit buffer where the UID will be stored.
 * @param[out] sreg Value of the status register.
 * @param[out] mac Pointer to the 128 bit buffer where the MAC generated over
 * challenge and UID and status  will be stored.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_GetID(const uint8_t *challenge, uint8_t *uid,
                       uint8_t *sreg, uint8_t *mac, uint32_t timeout);

/*!
 * @brief Generates a vector of 128 random bits using TRNG.
 *
 * The function returns a vector of 128 true random bits, using the TRNG.
 *
 * @param[out] trnd Pointer to a 128-bit buffer where the generated random number
 * has to be stored.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_GenerateTRND(uint8_t *trnd, uint32_t timeout);

/*!
 * @brief Executes the SHE secure boot protocol.
 *
 * The function loads the command processor firmware and memory slot data from
 * the HSM Flash blocks, and then it executes the SHE secure boot protocol.
 *
 * @param[in] bootImageSize Boot image size (in bytes).
 * @param[in] bootImagePtr Boot image start address.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_SecureBoot(uint32_t bootImageSize, const uint8_t *bootImagePtr,
                            uint32_t timeout);

/*!
 * @brief Signals a failure detected during later stages of the boot process.
 *
 * The function is called during later stages of the boot process to detect a
 * failure.
 *
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_BootFailure(uint32_t timeout);

/*!
 * @brief Marks a successful boot verification during later stages of the boot
 * process.
 *
 * The function is called during later stages of the boot process to mark
 * successful boot verification.
 *
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_BootOK(uint32_t timeout);

/*!
 * @brief Obtains a random number which the user shall use along with the
 * MASTER_ECU_KEY and UID to return an authorization request.
 *
 * This function obtains a random number which the user shall use along with the
 * MASTER_ECU_KEY and UID to return an authorization request.
 *
 * @param[out] challenge Pointer to the 128-bit buffer where the challenge data
 * will be stored.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_DbgChal(uint8_t *challenge, uint32_t timeout);

/*!
 * @brief Erases all user keys and enables internal debugging if the
 * authorization is confirmed by HSM.
 *
 * This function erases all user keys and enables internal debugging if the
 * authorization is confirmed by HSM.
 *
 * @param[in] authorization Pointer to the 128-bit buffer containing the
 * authorization value.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_DbgAuth(const uint8_t *authorization, uint32_t timeout);

/*!
 * @}
 */

/*!
 * @defgroup hsm_driver_extended Extended Symmetric API
 * @ingroup hsm_driver
 * @addtogroup hsm_driver_extended
 * @{
 */

/*!
 * @brief Performs the AES-128 GCM authenticated encryption synchronously.
 *
 * This function performs the AES-128 GCM authenticated encryption of the input
 * plain text buffer.
 * Additional authenticated data (AAD) is optional additional input header which
 * is authenticated, but not encrypted.
 * The function waits for the command to complete within the allocated time; it does
 * not return until either the command is complete or the timeout expires.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] ivLen Length of the IV.
 *            @note Only IV length of 12 bytes is supported; any value other than
 *            12 bytes is not accepted and STATUS_SEC_LENGTH_ERROR is returned.
 * @param[in] iv Buffer holding the initialization vector.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] authDataLen Length of the additional authenticated data (in bytes).
 * @param[in] authData Buffer holding the additional authenticated data.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] plainTextLen Number of bytes of plain text message to be encrypted.
 * @param[in] plainText Pointer to the address where input message/payload to be
 *            encrypted & authenticated is stored.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] cipherText Pointer to the cipher text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] tagLen Length of tag (in bytes)
 *            @note Must have a 32-bit value, between 4 and 16 bytes.
 * @param[out] tag Address where output computed tag is stored.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 *            command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_EncryptGCM(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                            const uint8_t *authData, uint32_t plainTextLen, const uint8_t *plainText,
                            uint8_t *cipherText, uint32_t tagLen, uint8_t *tag, uint32_t timeout);

/*!
 * @brief Performs the AES-128 CCM authenticated encryption synchronously.
 *
 * This function performs the AES-128 CCM authenticated encryption of the input
 * plain text buffer.
 * Additional authenticated data (AAD) is optional additional input header which
 * is authenticated, but not encrypted.
 * The function waits for the command to complete within the allocated time; it does
 * not return until either the command is complete or the timeout expires.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] ivLen Length of the IV.
 *            @note Only IV length of 12 bytes is supported; any value other than
 *            12 bytes is not accepted and STATUS_SEC_LENGTH_ERROR is returned.
 * @param[in] iv Buffer holding the initialization vector.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] authDataLen Length of the additional authenticated data (in bytes).
 * @param[in] authData Buffer holding the additional authenticated data.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] plainTextLen Number of bytes of plain text message to be encrypted.
 * @param[in] plainText Pointer to the address where input message/payload to be
 *            encrypted & authenticated is stored.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] cipherText Pointer to the cipher text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] tagLen Length of tag (in bytes)
 *            @note Must have a 32-bit value, between 4 and 16 bytes.
 * @param[out] tag Address where output computed tag is stored.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 *            command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_EncryptCCM(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                            const uint8_t *authData, uint32_t plainTextLen, const uint8_t *plainText,
                            uint8_t *cipherText, uint32_t tagLen, uint8_t *tag, uint32_t timeout);

/*!
 * @brief Performs the AES-128 encryption in OFB mode synchronously.
 *
 * This function performs the AES-128 encryption in OFB mode of the input
 * plaintext buffer.
 * The function waits for the command to complete within the allocated time; it does
 * not return until either the command is complete or the timeout expires.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of plain text message to be encrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[in] plainText Pointer to the plain text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] cipherText Pointer to the cipher text buffer. The buffer shall
 *             have the same size as the plain text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_EncryptOFB(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length, const uint8_t *plainText,
                            uint8_t *cipherText, uint32_t timeout);

/*!
 * @brief Performs the AES-128 encryption in CTR mode synchronously.
 *
 * This function performs the AES-128 encryption in CTR mode of the input
 * plaintext buffer.
 * The function waits for the command to complete within the allocated time; it does
 * not return until either the command is complete or the timeout expires.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of plain text message to be encrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[in] plainText Pointer to the plain text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] cipherText Pointer to the cipher text buffer. The buffer shall
 *             have the same size as the plain text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_EncryptCTR(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length, const uint8_t *plainText,
                            uint8_t *cipherText, uint32_t timeout);

/*!
 * @brief Performs the AES-128 encryption in CFB mode synchronously.
 *
 * This function performs the AES-128 encryption in CFB mode of the input
 * plaintext buffer.
 * The function waits for the command to complete within the allocated time; it does
 * not return until either the command is complete or the timeout expires.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of plain text message to be encrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[in] plainText Pointer to the plain text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] cipherText Pointer to the cipher text buffer. The buffer shall
 *             have the same size as the plain text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_EncryptCFB(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length, const uint8_t *plainText,
                            uint8_t *cipherText, uint32_t timeout);

/*!
 * @brief Performs the AES-128 encryption in XTS mode synchronously.
 *
 * This function performs the AES-128 encryption in XTS mode of the input
 * plaintext buffer.
 * The function waits for the command to complete within the allocated time; it does
 * not return until either the command is complete or the timeout expires.
 *
 * @param[in] keyId1 Key ID used for the IV encryption operation.
 * @param[in] keyId2 Key ID used for the block encryption operation.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of plain text message to be encrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[in] plainText Pointer to the plain text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] cipherText Pointer to the cipher text buffer. The buffer shall
 *             have the same size as the plain text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_EncryptXTS(hsm_key_id_t keyId1, hsm_key_id_t keyId2, const uint8_t *iv, uint32_t length,
                            const uint8_t *plainText, uint8_t *cipherText, uint32_t timeout);

/*!
 * @brief Performs the AES-128 GCM authenticated decryption synchronously.
 *
 * This function performs the AES-128 GCM authenticated decryption of the input
 * cipher text buffer.
 * Additional authenticated data (AAD) is optional additional input header which
 * is authenticated, but not decrypted.
 * The function waits for the command to complete within the allocated time; it does
 * not return until either the command is complete or the timeout expires.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] ivLen Length of the IV.
 *            @note Only IV length of 12 bytes is supported; any value other than
 *            12 bytes is not accepted and STATUS_SEC_LENGTH_ERROR is returned.
 * @param[in] iv Buffer holding the initialization vector.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] authDataLen Length of the additional authenticated data (in bytes).
 * @param[in] authData Buffer holding the additional authenticated data.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] cipherTextLen Number of bytes of cipher text message to be decrypted.
 * @param[in] cipherText Pointer to the address where input message to be decrypted
 *            is stored.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] decryptedText Pointer to the decrypted text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] tagLen Length of tag (in bytes)
 *            @note Must have a 32-bit value, between 4 and 16 bytes.
 * @param[out] tag Address where output computed tag is stored.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] authStatus Authentication status (false - authentication failure, true - authentication success).
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 *            command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_DecryptGCM(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                            const uint8_t *authData, uint32_t cipherTextLen, const uint8_t *cipherText,
                            uint8_t *decryptedText, uint32_t tagLen, const uint8_t *tag, bool *authStatus,
                            uint32_t timeout);

/*!
 * @brief Performs the AES-128 CCM authenticated decryption synchronously.
 *
 * This function performs the AES-128 CCM authenticated decryption of the input
 * cipher text buffer.
 * Additional authenticated data (AAD) is optional additional input header which
 * is authenticated, but not decrypted.
 * The function waits for the command to complete within the allocated time; it does
 * not return until either the command is complete or the timeout expires.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] ivLen Length of the IV.
 *            @note Only IV length of 12 bytes is supported; any value other than
 *            12 bytes is not accepted and STATUS_SEC_LENGTH_ERROR is returned.
 * @param[in] iv Buffer holding the initialization vector.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] authDataLen Length of the additional authenticated data (in bytes).
 * @param[in] authData Buffer holding the additional authenticated data.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] cipherTextLen Number of bytes of cipher text message to be decrypted.
 * @param[in] cipherText Pointer to the address where input message to be decrypted
 *            is stored.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] decryptedText Pointer to the decrypted text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] tagLen Length of tag (in bytes)
 *            @note Must have a 32-bit value, between 4 and 16 bytes.
 * @param[out] tag Address where output computed tag is stored.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] authStatus Authentication status (false - authentication failure, true - authentication success).
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 *            command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_DecryptCCM(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                            const uint8_t *authData, uint32_t cipherTextLen, const uint8_t *cipherText,
                            uint8_t *decryptedText, uint32_t tagLen, const uint8_t *tag, bool *authStatus,
                            uint32_t timeout);

/*!
 * @brief Performs the AES-128 decryption in OFB mode synchronously.
 *
 * This function performs the AES-128 decryption in OFB mode of the input
 * ciphertext buffer.
 * The function waits for the command to complete within the allocated time; it does
 * not return until either the command is complete or the timeout expires.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of cipher text message to be decrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[in] cipherText Pointer to the cipher text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] decryptedText Pointer to the decrypted text buffer. The buffer shall
 *             have the same size as the cipher text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_DecryptOFB(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length, const uint8_t *cipherText,
                            uint8_t *decryptedText, uint32_t timeout);

/*!
 * @brief Performs the AES-128 decryption in CTR mode synchronously.
 *
 * This function performs the AES-128 decryption in CTR mode of the input
 * ciphertext buffer.
 * The function waits for the command to complete within the allocated time; it does
 * not return until either the command is complete or the timeout expires.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of cipher text message to be decrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[in] cipherText Pointer to the cipher text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] decryptedText Pointer to the decrypted text buffer. The buffer shall
 *             have the same size as the cipher text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_DecryptCTR(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length, const uint8_t *cipherText,
                            uint8_t *decryptedText, uint32_t timeout);

/*!
 * @brief Performs the AES-128 decryption in CFB mode synchronously.
 *
 * This function performs the AES-128 decryption in CFB mode of the input
 * ciphertext buffer.
 * The function waits for the command to complete within the allocated time; it does
 * not return until either the command is complete or the timeout expires.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of cipher text message to be decrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[in] cipherText Pointer to the cipher text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] decryptedText Pointer to the decrypted text buffer. The buffer shall
 *             have the same size as the cipher text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_DecryptCFB(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length, const uint8_t *cipherText,
                            uint8_t *decryptedText, uint32_t timeout);

/*!
 * @brief Performs the AES-128 decryption in XTS mode synchronously.
 *
 * This function performs the AES-128 decryption in XTS mode of the input
 * ciphertext buffer.
 * The function waits for the command to complete within the allocated time; it does
 * not return until either the command is complete or the timeout expires.
 *
 * @param[in] keyId1 Key ID used for the IV encryption operation.
 * @param[in] keyId2 Key ID used for the block decryption operation.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of cipher text message to be decrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[in] cipherText Pointer to the cipher text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] decryptedText Pointer to the decrypted text buffer. The buffer shall
 *             have the same size as the cipher text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_DecryptXTS(hsm_key_id_t keyId1, hsm_key_id_t keyId2, const uint8_t *iv, uint32_t length,
                            const uint8_t *cipherText, uint8_t *decryptedText, uint32_t timeout);

/*!
 * @brief Performs the AES-128 GCM authenticated encryption asynchronously.
 *
 * This function performs the AES-128 GCM authenticated encryption of the input
 * plain text buffer.
 * Additional authenticated data (AAD) is optional additional input header which
 * is authenticated, but not encrypted.
 * The function returns after launching the command. Status of the command can be
 * polled by calling \bHSM_DRV_GetAsyncCmdStatus\b.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] ivLen Length of the IV.
 *            @note Only IV length of 12 bytes is supported; any value other than
 *            12 bytes is not accepted and STATUS_SEC_LENGTH_ERROR is returned.
 * @param[in] iv Buffer holding the initialization vector.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] authDataLen Length of the additional authenticated data (in bytes).
 * @param[in] authData Buffer holding the additional authenticated data.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] plainTextLen Number of bytes of plain text message to be encrypted.
 * @param[in] plainText Pointer to the address where input message/payload to be
 *            encrypted & authenticated is stored.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] cipherText Pointer to the cipher text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] tagLen Length of tag (in bytes)
 *            @note Must have a 32-bit value, between 4 and 16 bytes.
 * @param[out] tag Address where output computed tag is stored.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_EncryptGCMAsync(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                                 const uint8_t *authData, uint32_t plainTextLen, const uint8_t *plainText,
                                 uint8_t *cipherText, uint32_t tagLen, uint8_t *tag);

/*!
 * @brief Performs the AES-128 CCM authenticated encryption asynchronously.
 *
 * This function performs the AES-128 CCM authenticated encryption of the input
 * plain text buffer.
 * Additional authenticated data (AAD) is optional additional input header which
 * is authenticated, but not encrypted.
 * The function returns after launching the command. Status of the command can be
 * polled by calling \bHSM_DRV_GetAsyncCmdStatus\b.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] ivLen Length of the IV.
 *            @note Only IV length of 12 bytes is supported; any value other than
 *            12 bytes is not accepted and STATUS_SEC_LENGTH_ERROR is returned.
 * @param[in] iv Buffer holding the initialization vector.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] authDataLen Length of the additional authenticated data (in bytes).
 * @param[in] authData Buffer holding the additional authenticated data.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] plainTextLen Number of bytes of plain text message to be encrypted.
 * @param[in] plainText Pointer to the address where input message/payload to be
 *            encrypted & authenticated is stored.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] cipherText Pointer to the cipher text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] tagLen Length of tag (in bytes)
 *            @note Must have a 32-bit value, between 4 and 16 bytes.
 * @param[out] tag Address where output computed tag is stored.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_EncryptCCMAsync(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                                 const uint8_t *authData, uint32_t plainTextLen, const uint8_t *plainText,
                                 uint8_t *cipherText, uint32_t tagLen, uint8_t *tag);

/*!
 * @brief Performs the AES-128 encryption in OFB mode asynchronously.
 *
 * This function performs the AES-128 encryption in OFB mode of the input
 * plaintext buffer.
 * The function returns after launching the command. Status of the command can be
 * polled by calling \bHSM_DRV_GetAsyncCmdStatus\b.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of plain text message to be encrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[in] plainText Pointer to the plain text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] cipherText Pointer to the cipher text buffer. The buffer shall
 *             have the same size as the plain text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_EncryptOFBAsync(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length,
                                 const uint8_t *plainText, uint8_t *cipherText);

/*!
 * @brief Performs the AES-128 encryption in CTR mode asynchronously.
 *
 * This function performs the AES-128 encryption in CTR mode of the input
 * plaintext buffer.
 * The function returns after launching the command. Status of the command can be
 * polled by calling \bHSM_DRV_GetAsyncCmdStatus\b.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of plain text message to be encrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[in] plainText Pointer to the plain text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] cipherText Pointer to the cipher text buffer. The buffer shall
 *             have the same size as the plain text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_EncryptCTRAsync(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length,
                                 const uint8_t *plainText, uint8_t *cipherText);

/*!
 * @brief Performs the AES-128 encryption in CFB mode asynchronously.
 *
 * This function performs the AES-128 encryption in CFB mode of the input
 * plaintext buffer.
 * The function returns after launching the command. Status of the command can be
 * polled by calling \bHSM_DRV_GetAsyncCmdStatus\b.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of plain text message to be encrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[in] plainText Pointer to the plain text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] cipherText Pointer to the cipher text buffer. The buffer shall
 *             have the same size as the plain text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_EncryptCFBAsync(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length,
                                 const uint8_t *plainText, uint8_t *cipherText);

/*!
 * @brief Performs the AES-128 encryption in XTS mode asynchronously.
 *
 * This function performs the AES-128 encryption in XTS mode of the input
 * plaintext buffer.
 * The function returns after launching the command. Status of the command can be
 * polled by calling \bHSM_DRV_GetAsyncCmdStatus\b.
 *
 * @param[in] keyId1 Key ID used for the IV encryption operation.
 * @param[in] keyId2 Key ID used for the block encryption operation.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of plain text message to be encrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[in] plainText Pointer to the plain text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] cipherText Pointer to the cipher text buffer. The buffer shall
 *             have the same size as the plain text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_EncryptXTSAsync(hsm_key_id_t keyId1, hsm_key_id_t keyId2, const uint8_t *iv,
                                 uint32_t length, const uint8_t *plainText, uint8_t *cipherText);

/*!
 * @brief Performs the AES-128 GCM authenticated decryption asynchronously.
 *
 * This function performs the AES-128 GCM authenticated decryption of the input
 * cipher text buffer.
 * Additional authenticated data (AAD) is optional additional input header which
 * is authenticated, but not decrypted.
 * The function returns after launching the command. Status of the command can be
 * polled by calling \bHSM_DRV_GetAsyncCmdStatus\b.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] ivLen Length of the IV.
 *            @note Only IV length of 12 bytes is supported; any value other than
 *            12 bytes is not accepted and STATUS_SEC_LENGTH_ERROR is returned.
 * @param[in] iv Buffer holding the initialization vector.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] authDataLen Length of the additional authenticated data (in bytes).
 * @param[in] authData Buffer holding the additional authenticated data.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] cipherTextLen Number of bytes of cipher text message to be decrypted.
 * @param[in] cipherText Pointer to the address where input message to be decrypted
 *            is stored.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] decryptedText Pointer to the decrypted text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] tagLen Length of tag (in bytes)
 *            @note Must have a 32-bit value, between 4 and 16 bytes.
 * @param[out] tag Address where output computed tag is stored.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] authStatus Authentication status (false - authentication failure, true - authentication success).
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_DecryptGCMAsync(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                                 const uint8_t *authData, uint32_t cipherTextLen, const uint8_t *cipherText,
                                 uint8_t *decryptedText, uint32_t tagLen, const uint8_t *tag, bool *authStatus);

/*!
 * @brief Performs the AES-128 CCM authenticated decryption asynchronously.
 *
 * This function performs the AES-128 CCM authenticated decryption of the input
 * cipher text buffer.
 * Additional authenticated data (AAD) is optional additional input header which
 * is authenticated, but not decrypted.
 * The function returns after launching the command. Status of the command can be
 * polled by calling \bHSM_DRV_GetAsyncCmdStatus\b.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] ivLen Length of the IV.
 *            @note Only IV length of 12 bytes is supported; any value other than
 *            12 bytes is not accepted and STATUS_SEC_LENGTH_ERROR is returned.
 * @param[in] iv Buffer holding the initialization vector.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] authDataLen Length of the additional authenticated data (in bytes).
 * @param[in] authData Buffer holding the additional authenticated data.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] cipherTextLen Number of bytes of cipher text message to be decrypted.
 * @param[in] cipherText Pointer to the address where input message to be decrypted
 *            is stored.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] decryptedText Pointer to the decrypted text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] tagLen Length of tag (in bytes)
 *            @note Must have a 32-bit value, between 4 and 16 bytes.
 * @param[out] tag Address where output computed tag is stored.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] authStatus Authentication status (false - authentication failure, true - authentication success).
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_DecryptCCMAsync(hsm_key_id_t keyId, uint32_t ivLen, const uint8_t *iv, uint32_t authDataLen,
                                 const uint8_t *authData, uint32_t cipherTextLen, const uint8_t *cipherText,
                                 uint8_t *decryptedText, uint32_t tagLen, const uint8_t *tag, bool *authStatus);

/*!
 * @brief Performs the AES-128 decryption in OFB mode asynchronously.
 *
 * This function performs the AES-128 decryption in OFB mode of the input
 * ciphertext buffer.
 * The function returns after launching the command. Status of the command can be
 * polled by calling \bHSM_DRV_GetAsyncCmdStatus\b.
 *
 * @param[in] keyId Key ID used for the IV encryption operation.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of cipher text message to be decrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[in] cipherText Pointer to the cipher text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] decryptedText Pointer to the decrypted text buffer. The buffer shall
 *             have the same size as the cipher text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_DecryptOFBAsync(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length,
                                 const uint8_t *cipherText, uint8_t *decryptedText);

/*!
 * @brief Performs the AES-128 decryption in CTR mode asynchronously.
 *
 * This function performs the AES-128 decryption in CTR mode of the input
 * ciphertext buffer.
 * The function returns after launching the command. Status of the command can be
 * polled by calling \bHSM_DRV_GetAsyncCmdStatus\b.
 *
 * @param[in] keyId Key ID used for the IV encryption operation.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of cipher text message to be decrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[in] cipherText Pointer to the cipher text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] decryptedText Pointer to the decrypted text buffer. The buffer shall
 *             have the same size as the cipher text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_DecryptCTRAsync(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length,
                                 const uint8_t *cipherText, uint8_t *decryptedText);

/*!
 * @brief Performs the AES-128 decryption in CFB mode asynchronously.
 *
 * This function performs the AES-128 decryption in CFB mode of the input
 * ciphertext buffer.
 * The function returns after launching the command. Status of the command can be
 * polled by calling \bHSM_DRV_GetAsyncCmdStatus\b.
 *
 * @param[in] keyId Key ID used for the IV encryption operation.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of cipher text message to be decrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[in] cipherText Pointer to the cipher text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] decryptedText Pointer to the decrypted text buffer. The buffer shall
 *             have the same size as the cipher text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_DecryptCFBAsync(hsm_key_id_t keyId, const uint8_t *iv, uint32_t length,
                                 const uint8_t *cipherText, uint8_t *decryptedText);

/*!
 * @brief Performs the AES-128 decryption in XTS mode asynchronously.
 *
 * This function performs the AES-128 decryption in XTS mode of the input
 * ciphertext buffer.
 * The function returns after launching the command. Status of the command can be
 * polled by calling \bHSM_DRV_GetAsyncCmdStatus\b.
 *
 * @param[in] keyId1 Key ID used for the IV encryption operation.
 * @param[in] keyId2 Key ID used for the block decryption operation.
 * @param[in] iv Pointer to the initialization vector buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] length Number of bytes of cipher text message to be decrypted.
 *            @note Should be multiple of 16 bytes.
 * @param[in] cipherText Pointer to the cipher text buffer.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] decryptedText Pointer to the decrypted text buffer. The buffer shall
 *             have the same size as the cipher text buffer.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_DecryptXTSAsync(hsm_key_id_t keyId1, hsm_key_id_t keyId2, const uint8_t *iv,
                                 uint32_t length, const uint8_t *cipherText, uint8_t *decryptedText);

/*!
 * @}
 */

/*!
 * @defgroup hsm_driver_assymetric Asymmetric API
 * @ingroup hsm_driver
 * @addtogroup hsm_driver_assymetric
 * @{
 */

/*!
 * @brief Synchronous RSA Encryption.
 * The function performs the following steps in sequence:
 * 1. Pad/encode the input message of specified length in either OAEP or PKCS v1.5
 *    format using SHA 256 as the hashing algorithm.
 * 2. RSA encrypt it using specified public key.
 * 3. Store the cipher text in output buffer. The size of cipher-text will be equal
 *    to modulus size of the key specified.
 * The function waits for the command to complete within the allocated time; it does not return until either the
 * command is complete or the timeout expires.
 *
 * @param[in] keyMode Parameter that specifies the input mode of the public key required for RSA encryption.
 * Depending on the value, definition of the second parameter will be decided.
 * HSM security firmware supports three key modes: keyId, keyAddr, keyAddrASN.
 * @param[in] keyAddr Pointer that specifies the public key used for encryption:
 * If keyMode is keyId the value of pointer is a key index in the internal key storage of HSM.
 * @note Key Groups must be: RSA based Asymmetric Public keys (0x01) or
 * RAM based RSA Asymmetric Public Keys(0x01)
 * If keyMode is keyAddr, this parameter contains the address of the structure where the public key is saved.
 * @note Address passed in this parameter must be 32 bit aligned.
 * If keyMode is keyAddrASN, this parameter contains the address of the public key in ASN format.
 * @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] padding Type of padding algorithm used.
 * @note HSM firmware supports : PKCS V 1.5 Encoding(0x00) or OAEP Encoding(0x01)
 * @param[in] msgLen Parameter that contains length of input message (in bytes).
 * @note Must have a 32-bit value
 * @param[in] plainText Pointer that contains the address where input message/payload is stored
 * @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] labelLen Optional parameter. It is used only when value of padding is OAEP.
 *            It indicates length of label data.
 * @param[in] label This parameter is used only when value of padding is OAEP.
 *            It is the optional label to be associated with the message.
 * @note Address passed in this parameter must be 32 bit aligned.
 * @note If not provided, empty string should be passed.
 * @param[out] cipherText Pointer that indicates the address where output cipher text will be stored.
 * @note The size of this memory area must be at least the byte length of the public modulus n.
 * @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_RsaEncrypt(hsm_key_mode_t keyMode, uint32_t keyAddr, hsm_pkcs_padding_t padding,
                            uint32_t msgLen, const uint8_t *plainText, uint32_t labelLen, const uint8_t *label,
                            uint8_t *cipherText, uint32_t timeout);

/*!
 * @brief Asynchronous RSA Encryption.
 * The function performs the following steps in sequence:
 * 1. Pad/encode the input message of specified length in either OAEP or PKCS v1.5
 *    format using SHA 256 as the hashing algorithm.
 * 2. RSA encrypt it using specified public key.
 * 3. Store the cipher text in output buffer. The size of cipher-text will be equal
 *    to modulus size of the key specified.
 * The function returns right after launching the command to HSM. In order to retrieve the result, the application must
 * call \bHSM_DRV_GetAsyncCmdStatus\b. The output is valid only when the status of the command is STATUS_SUCCESS.
 *
 * @param[in] keyMode Parameter that specifies if the input mode of the public key required for RSA encryption.
 * Depending on the value, definition of the second parameter will be decided.
 * HSM security firmware supports three key modes: keyId, keyAddr, keyAddrASN.
 * @param[in] key Pointer that specifies the public key used for encryption:
 *            If keyMode is keyId the value of pointer is a key index in the internal key storage of HSM.
 * @note Key Groups must be: RSA based Asymmetric Public keys (0x01) or
 *           RAM based RSA Asymmetric Public Keys(0x01)
 *           If keyMode is keyAddr, this parameter contains the address of the structure where the public key is saved.
 * @note Address passed in this parameter must be 32 bit aligned.
 *       If keyMode is keyAddrASN, this parameter contains the address of the public key in ASN format.
 * @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] padding Type of padding algorithm used.
 * @note HSM firmware supports : PKCS V 1.5 Encoding(0x00) or OAEP Encoding(0x01)
 * @param[in] msgLen Parameter that contains length of input message (in bytes).
 * @note Must have a 32-bit value
 * @param[in] plainText Pointer that contains the address where input message/payload is stored
 * @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] labelLen Optional parameter. It is used only when value of padding is OAEP.
 *            It indicates length of label data.
 * @param[in] label This parameter is used only when value of padding is OAEP.
 *            It is the optional label to be associated with the message.
 * @note Address passed in this parameter must be 32 bit aligned.
 * @note If not provided, empty string should be passed.
 * @param[out] cipherText Pointer that indicates the address where output cipher text will be stored.
 * @note The size of this memory area must be at least the byte length of the public modulus n.
 * @note Address passed in this parameter must be 32 bit aligned.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_RsaEncryptAsync(hsm_key_mode_t keyMode, uint32_t key, hsm_pkcs_padding_t padding,
                                 uint32_t msgLen, const uint8_t *plainText, uint32_t labelLen, const uint8_t *label,
                                 uint8_t *cipherText);

/*!
 * @brief Function that performs the following steps in sequence:
 * 1. Calculate the SHA 256 based Hash of the input message
 * 2. RSA decrypt the input signature message using the specified public key.
 * 3. Perform the decoding in PSS or PKCS v1.5 format of the decrypted signature calculated in
 *    previous step and verify the signature as per the standard.
 *
 * @param[in] keyMode Parameter that specifies if the input mode of the public key. Depending
 *            on the value, definition of the second parameter will be decided. HSM security firmware
 *            supports three key modes: keyId, keyAddr, keyAddrASN.
 * @param[in] keyAddr Pointer that specifies the public key used for encryption:
 *            If keyMode is keyId the value of pointer is a key index in the internal key storage of HSM.
 * @note Key Groups must be: RSA based Asymmetric Public keys (0x01) or
 *       RAM based RSA Asymmetric Public Keys(0x01)
 *       If keyMode is keyAddr, this parameter contains the address of the structure where the public key is saved.
 * @note Address passed in this parameter must be 32 bit aligned.
 *       If keyMode is keyAddrASN, this parameter contains the address of the public key in ASN format.
 * @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] padding Type of padding algorithm used.
 * @note HSM firmware supports : PKCS V 1.5 Encoding(0x00) or OAEP Encoding(0x01)
 * @param[in] msgLen Parameter that contains length of input message (in bytes).
 * @note Must have a 32-bit value
 * @param[in] msg Pointer that contains the address where input message/payload is stored
 * @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] sgnLen This parameter contains length of input signature message (in bytes).
 * @note Must be equal to modulus size of the RSA Public key
 * @param[in] sgn This parameter contains the address of the input signature message.
 * @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] saltLen This parameter indicates the length of the salt (in bytes) used during signature.
 *            This parameter is used only when value of PKCS Version is PSS. Salt length parameter is ignored
 *            in case the decoding method is v 1.5.
 * @note If Modulus_Size_In_Bits % 8=1, then the maximum length of Salt should be less than:
 *       (Modulus_Length( in bytes)-HashLen(32)-3)
 * @note If Modulus_Size_In_Bits % 8!=1, the value of salt length should be less than:
 *       (modulus length(bytes)-HashLength(32)-2).
 * @param[out] authStatus Authentication status (false - authentication failure, true - authentication success).
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_RsaVerifyMsg(hsm_key_mode_t keyMode, uint32_t key, hsm_pkcs_padding_t padding, uint32_t msgLen,
                              const uint8_t *msg, uint32_t sgnLen, const uint8_t *sgn, uint32_t saltLen,
                              bool *authStatus, uint32_t timeout);

/*!
 * @brief This function is a subset of the RSA_PKCS_VERIFY_MSG command. It accepts the hash of the input
 * message instead of the input message itself. It will perform the following steps in sequence:
 * 1. RSA decrypt the signature message using the specified public key;
 * 2. Perform the decoding in PSS or PKCS v1.5 format of the decrypted signature calculated in
 *    previous step and verify the signature as per the standard.
 *
 * @param[in] keyMode Parameter that specifies if the input mode of the public key. Depending
 *            on the value, definition of the second parameter will be decided. HSM security firmware
 *            supports three key modes: keyId, keyAddr or keyAddrASN.
 * @param[in] keyAddr Pointer that specifies the public key used for encryption:
 *            If keyMode is keyId the value of pointer is a key index in the internal key storage of HSM.
 * @note Key Groups must be: RSA based Asymmetric Public keys (0x01) or
 *       RAM based RSA Asymmetric Public Keys(0x01)
 * If keyMode is keyAddr, this parameter contains the address of the structure where the public key is saved.
 * @note Address passed in this parameter must be 32 bit aligned.
 *       If keyMode is keyAddrASN, this parameter contains the address of the public key in ASN format.
 * @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] padding Type of padding algorithm used.
 * @note HSM firmware supports : PKCS V 1.5 Encoding(0x00) or OAEP Encoding(0x01)
 * @param[in] hash Pointer that contains the address where input hash message is stored
 * @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] sgnLen This parameter contains length of input signature message (in bytes).
 * @note Must be equal to modulus size of the RSA Public key
 * @param[in] sgn This parameter contains the address of the input signature message.
 * @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] saltLen This parameter indicates the length of the salt (in bytes) used during signature.
 * @note This parameter is used only when value of PKCS Version is PSS.
 *       Salt length parameter is ignored in case the decoding method is v 1.5.
 * @note If Modulus_Size_In_Bits % 8=1, then the maximum length of Salt should be less than:
 *       (Modulus_Length( in bytes)-HashLen(32)-3)
 * @note If Modulus_Size_In_Bits % 8!=1, the value of salt length should be less than:
 *       (modulus length(bytes)-HashLength(32)-2)
 * @param[out] authStatus Authentication status (false - authentication failure, true - authentication success).
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_RsaVerifyHash(hsm_key_mode_t keyMode, uint32_t key, hsm_pkcs_padding_t padding, const uint8_t *hash,
                               uint32_t sgnLen, const uint8_t *sgn, uint32_t saltLen, bool *authStatus, uint32_t timeout);


/*!
 * @brief This command will install the information of public key certificate in HSM Key store area.
 *
 * @param[in] keyId This parameter selects the slot used to store the certificate attributes.
 * @note Valid key index for this command are mentioned in Key Group: RSA based Asymmetric Public keys
 * (0x01) or Key Group: RAM based RSA Asymmetric Public Keys (0x01)
 * @param[in] authKeyID This parameter selects the public key that will be used for signature verification.
 * @note Valid key index for this command are mentioned in Key Group: RSA based Asymmetric Public keys
 * (0x01) or Key Group: RAM based RSA Asymmetric Public Keys (0x01)
 * @param[in] certificate This parameter contains the pointer to certificate location in the memory.
 * @param[in] certificateLen Input length of the certificate in bytes.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_InstallCertificate(hsm_key_id_t keyId, hsm_key_id_t authKeyID, const uint8_t *certificate,
                                    uint32_t certificateLen, uint32_t timeout);

/*!
 * @brief This command will share the DH public key of the HSM to the Host Application.
 * The key will be generated using DH domain parameters. This command will do the following steps:
 * 1. Generate the random number 'd' (private key of HSM) of required number of bytes depending on
 *    the size of domain parameter P.
 * 2. Calculates the public key by performing the following equation: pOutPublicKey = (g_Base)d mod (p_Modulus)
 *
 * @param[in] gBase This parameter represents the base g of the domain parameters. First word shall
 *            contain the size of the base, and the second shall contain the address stored in hex.
 * @note The base size should not be more than 4 bytes.
 * @param[in] pModulus This parameter is the modulus p of the domain parameters. First word shall
 *            contain the size of the modulus, and the second shall contain the address stored in hex.
 * @note The modulus size should be in the range of 64 bytes to 256 bytes.
 * @param[in/out] pubKeyLen As an input, this parameter contains the address
 *                where the length of output buffer is saved. As an output, HSM firmware will
 *                write the length of the HSM public key derived on the given address.
 * @param[out] pubKey Address where the HSM firmware will store the length of the generated public key.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_RsaDhKeyPairGen(const hsm_g_base_t *gBase, const hsm_p_modulus_t *pModulus, uint32_t *pubKeyLen,
                                 uint8_t *pubKey, uint32_t timeout);

/*!
 * @brief This command will compute the shared secret for Diffie Hellman. The length of shared
 * secret will depend on the size of prime P. It is also called pre-master secret in case it is used
 * for TLS 1.2 implementation. DH_KEY_PAIR_GEN_COMMAND should be given before giving this command
 * otherwise STATUS_SEC_SEQUENCE_ERROR will be returned.
 *
 * @param[in] keyId This parameter represents the destination key index where the key will be stored.
 * @note The catalog type field must be RAM (0x01) and key type should be Key Group: RAM based Diffie Hellman
 * RSA Secret (0x03)
 * @param[in] keyLen This parameter contains the length of the public key of other party.
 * @note It should be in the range of 64 bytes to 256 bytes.
 * @param[in] key Address of the public key of other party.
 * @note It is required that other party have used same domain parameter i.e. p & g that were passed during
 * DH_RSA_KEY_PAIR_GEN command while calculating public key of the HSM.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_ComputeSharedSecret(hsm_key_id_t keyId, uint32_t keyLen, const uint8_t *key, uint32_t timeout);

/*!
 * @brief This command will generate the session keys based on the shared secret and will store it in
 * corresponding key group in RAM catalog.
 *
 * @param[in] keyId This parameter represents key index of the shared secret.
 * @note The catalog type field must be RAM (0x01) and key group should be either Diffie Hellman or RSA based
 *       secret.
 * @note This field will be ignored in case Key derivation function type is Random Key.
 * @note Index refers to Key Group: RAM based Diffie Hellman RSA Secret (0x03) or
 *       Key Group: RAM based RSA Random Shared Secret (0x04).
 * @param[in] kdfType This parameter selects the key derivation between random key or TLS PRF.
 * @note It should be in the range of 64 bytes to 256 bytes.
 * @param[in] kdf It should contain the address of structure of key derivation function as per param 2.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_GenerateExtendedRamKeys(hsm_key_id_t keyId, hsm_kdf_t kdfType,
                                         void *kdf, uint32_t timeout);

/*!
 * @brief This command is used to export the RAM key from the RAM catalog using the specified method.
 * Currently, only RSA encryption based method is supported. RSA Encryption method will encrypt the
 * specified key with the specified RSA public key certificate. The key group that can be encrypted
 *  using this command are AES-128 symmetric keys, HMAC Keys or RSA based secret from RAM key catalog.
 *
 * @param[in] keyId This parameter represents key that needs to be encrypted.
 * @note The catalog type field must be Key Group: RAM based AES-128 Symmetric Keys(0x00) or
 *       Key Group: RAM based HMAC Keys (0x02) or Key Group: RAM based RSA Random Shared Secret(0x04)
 * @param[in] rsa_encr It should contain the address of structure of rsa_encryption algorithm
 * @note It should be in the range of 64 bytes to 256 bytes.
 * @param[in] outBufLen This address stores the length of the output buffer where the exported key will be saved.
 * @note The length of this buffer should less than the exported key length
 * @note The length of the buffer should be atleast size of the key modulus
 * @param[in] expKey This is the address where the exported RAM key will be stored.
 * @param[in] expKeyLen This is the address where the HSM firmware will write the length of the key in bytes
 *            which was encrypted as per specified algorithm.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_ExportExtendedRamKeys(hsm_key_id_t keyId, const hsm_rsa_algorithm_t *rsa_encr, uint32_t *outBufLen,
                                       uint8_t *expKey, uint32_t *expKeyLen, uint32_t timeout);

/*!
 * @brief This command is used to generate and verify the finished message as described in
 * TLS 1.2 specification. Master secret is used to calculate the final output message. Firmware
 * first calculates the master secret from pre-master secret.
 * This command will run the PRF function over the specified parameter and get the finished message as an output.
 *
 * @param[in] keyId This parameter represents the index of the secret.
 * @note The catalog type field must be RAM (0x01) and key type should be either Diffie Hellman or RSA
 * based secret. Refer to Key Group: RAM based Diffie Hellman RSA Secret(0x03) or RAM RSA Random Shared Secret(0x04)
 * @param[in] masterSeedLen This parameter contains the length of the seed to calculate master secret key value
 * @note It should not be equal to zero or greater than 128 bytes.
 * @param[in] masterSeed This is the address where seed to calculate the master secret is saved
 * @note This should be same as provided during the GENERATE EXTENDED RAM KEYS.
 * @param[in] seedLen Length of the seed which will be used to calculate the output message.
 * @note It should not be equal to zero or greater than 128 bytes.
 * @param[in] seed Address where the seed value is being stored. This seed
 * value must be the concatenation of the Label value and seed
 * required to calculate the finished message. Label value must
 * be either "client finished" or "server finished".
 * @param[in] msgLen This is the length of the output message
 * @note It can be maximum up to 16 bytes.
 * @param[out] msg Address where the HSM will write the output message.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_PseudoRandomTLS(hsm_key_id_t keyId, uint32_t masterSeedLen, const uint8_t *masterSeed,
                                 uint32_t seedLen, const uint8_t *seed, uint32_t msgLen, uint8_t *msg,
                                 uint32_t timeout);

/*!
 * @}
 */

/*!
 * @defgroup hsm_driver_misc Miscellaneous
 * @ingroup hsm_driver
 * @addtogroup hsm_driver_misc
 * @{
 */

/*!
 * @brief Compresses the given messages using the Miyaguchi-Preneel
 * compression algorithm implemented in software.
 *
 * This function is a software implementation of Miyaguchi-Preneel compression,
 * running on the host. It is defined mainly for obtaining M1->M5 for secure
 * key update.
 *
 * @param[in] msg Pointer to the messages to be compressed. Messages must be
 * pre-processed per SHE specification if they do not already meet the full
 * 128-bit block size requirement.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] msgLen The number of 128 bit messages to be compressed.
 * @param[out] mpCompress Pointer to the 128 bit buffer storing the compressed
 * data.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_MPCompress(const uint8_t *msg, uint16_t msgLen,
                            uint8_t *mpCompress, uint32_t timeout);

/*!
 * @brief Checks the status of the execution of an asynchronous command.
 *
 * This function checks the status of the execution of an asynchronous command.
 * If the command is still in progress, returns STATUS_BUSY.
 *
 * @return Error Code after command execution.
 */
status_t HSM_DRV_GetAsyncCmdStatus(void);

/*!
 * @brief Cancels a previously initiated command.
 *
 * This function cancels any on-going HSM command.
 *
 * @return STATUS_SUCCESS.
 */
status_t HSM_DRV_CancelCommand(void);

/*!
 * @brief Performs cryptographic hash (SHA-256) of a given input.
 *
 * This function computes SHA-256 hash of a given input message.
 *
 * @param[in] msgLen Length of input message (in bytes)
 * @param[in] msg Address where the input message is stored.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] hash address where output hash will be stored.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_HashSHA256(uint32_t msgLen, const uint8_t *msg, uint8_t *hash, uint32_t timeout);

/*!
 * @brief Performs cryptographic hash (HMAC) of a given input.
 *
 * HMAC is a keyed-hash message authentication code (HMAC) which is a specific type of
 * message authentication code (MAC) involving a cryptographic hash function and
 * a secret cryptographic key.
 *
 * @param[in] keyId KeyID used to perform the cryptographic operation.
 * @param[in] msgLen Length of input message (in bytes)
 * @param[in] msg Address where the input message is stored.
 *            @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] hashLen Address where the length of the hash is stored. After successful
 *             completion of command, HSM will write the length of HMAC generated at this address.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[out] hash address where output hash will be stored.
 *             @note Address passed in this parameter must be 32 bit aligned.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution. Output parameters are valid if
 * the error code is STATUS_SUCCESS.
 */
status_t HSM_DRV_HashHMAC256(hsm_key_id_t keyId, uint32_t msgLen, const uint8_t *msg, uint32_t *hashLen,
                             uint8_t *hash, uint32_t timeout);

/*!
 * @brief Erases a RAM key.
 *
 * This command is used to erase the keys of RAM catalog. Only 1 key can be erased at a time.
 * Key Index should be of RAM catalog only as NVM catalog key cannot be deleted using this command.
 *
 * @param[in] keyId ID of the key to be erased (should be from the RAM catalog).
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_EraseExtededRamKey(hsm_key_id_t keyId, uint32_t timeout);

/*!
 * @brief Returns the HSM firmware version.
 *
 * This function returns the HSM firmware version.
 *
 * @param[out] version Variable where the HSM firmware version will be stored.
 * @param[in] timeout Timeout in ms; the function returns STATUS_TIMEOUT if the
 * command is not finished in the allocated period.
 * @return Error Code after command execution.
 */
status_t HSM_DRV_GetFwVersion(uint32_t *version, uint32_t timeout);

/*!
 * @}
 */


#if defined(__cplusplus)
}
#endif

/*! @}*/

#endif /* HSM_DRV_H */

/*******************************************************************************
 * EOF
 ******************************************************************************/
