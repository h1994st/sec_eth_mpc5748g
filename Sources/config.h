/*
 * config.h
 *
 *  Created on: 2020/11/4
 *      Author: shengtuo
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#define ST_HSM					1 // 0: HSM disabled, 1: HSM enabled

#define ST_BENCH_W_HSM			1
#if ST_BENCH_W_HSM
#ifdef ST_HSM // override ST_HSM
#undef ST_HSM
#define ST_HSM					0
#endif /* ST_HSM */
#endif /* ST_BENCH_WOLFSSL */

#define ST_BENCH_WOLFSSL		0
#if ST_BENCH_WOLFSSL
#define ST_RSA_KEY_SIZE			1024
#endif /* ST_BENCH_WOLFSSL */

#define ST_TLS_APP				0
#if ST_TLS_APP

#define ST_TLS_TYPE				0 // 0: client, 1: server
#define ST_TLS_VERSION			0x012 // 0x013: TLS 1.3, 0x012: TLS 1.2
#define ST_TLS_ECHO_BUFFER_SZ	16384 // the data for the communication
#define ST_TLS_CERT_TYPE		0 // 0: RSA_1024, 1: RSA_2048, 2: ECC_256

#if (ST_TLS_VERSION == 0x013)
//#define ST_TLS_CIPHER			"TLS13-AES128-GCM-SHA256" // TLS13-AES-128-GCM
#define ST_TLS_CIPHER			"TLS13-AES128-CCM-SHA256" // TLS13-AES-128-CCM
#elif (ST_TLS_VERSION == 0x012)
//#define ST_TLS_CIPHER			"AES128-GCM-SHA256" // AES-128-GCM
//#define ST_TLS_CIPHER			"AES128-CCM-SHA256" // AES-128-CCM
#define ST_TLS_CIPHER			"AES128-SHA256" // AES-128-CBC
#endif /* ST_TLS_VERSION */

#endif /* ST_TLS_APP */

#if !ST_HSM // without HSM, we need to define the random seed function
#include <stdint.h>
int customRandSeed(uint8_t* output, uint32_t sz);
#endif /* !ST_HSM */

#endif /* CONFIG_H_ */
