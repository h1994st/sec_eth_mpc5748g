/*
 * user_settings.h
 *
 *  Created on: 2020/11/7
 *      Author: shengtuo
 */

#ifndef USER_SETTINGS_H_
#define USER_SETTINGS_H_

/* User settings for wolfSSL */
#include "config.h"

#ifdef ST_NO_HSM // without HSM, we need to define the random seed function
#define CUSTOM_RAND_GENERATE_SEED customRandSeed
#endif /* ST_NO_HSM */

#define HAVE_AESCCM
#define HAVE_AESGCM
#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_ONE_TIME_AUTH
#define HAVE_ECC

/* TLS 1.3 */
//#define WOLFSSL_TLS13
//#define HAVE_TLS_EXTENSIONS
//#define HAVE_SUPPORTED_CURVES
//#define HAVE_EXTENDED_MASTER
//#define HAVE_HKDF
//#define WC_RSA_PSS

#endif /* USER_SETTINGS_H_ */
