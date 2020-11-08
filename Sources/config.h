/*
 * config.h
 *
 *  Created on: 2020/11/4
 *      Author: shengtuo
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#define ST_BENCH_W_HSM			0
#if ST_BENCH_W_HSM
#define ST_HSM					1 // HSM: enabled
#endif /* ST_BENCH_WOLFSSL */

#define ST_BENCH_WOLFSSL		0
#if ST_BENCH_WOLFSSL
#define ST_HSM					0 // 1: HSM enabled, 0: HSM disabled
#endif /* ST_BENCH_WOLFSSL */

#define ST_TLS_APP				1
#if ST_TLS_APP
#define ST_HSM					1 // HSM: enabled

#define ST_TLS_CERT_TYPE		0 // 0: RSA_1024, 1: RSA_2048, 2: ECC_256
#define ST_TLS_TYPE				0 // 1: server, 0: client
#define ST_TLS_VERSION			0x012 // 0x013: TLS 1.3, 0x012: TLS 1.2
#endif /* ST_TLS_APP */

#if !ST_HSM // without HSM, we need to define the random seed function
#include <stdint.h>
int customRandSeed(uint8_t* output, uint32_t sz);
#endif /* !ST_HSM */

#endif /* CONFIG_H_ */
