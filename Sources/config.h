/*
 * config.h
 *
 *  Created on: 2020/11/4
 *      Author: shengtuo
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#define ST_BENCH_W_HSM			1 // HSM: enabled

#define ST_BENCH_WOLFSSL		0
#if ST_BENCH_WOLFSSL
#define ST_HSM					0 // 1: HSM enabled, 0: HSM disabled
#endif

#define ST_TLS_APP				0 // HSM: enabled
#if ST_TLS_APP
#define ST_TLS_CERT_RSA_1024	1
#endif /* ST_TLS_APP */

#if !ST_HSM // without HSM, we need to define the random seed function
#include <stdint.h>
int customRandSeed(uint8_t* output, uint32_t sz);
#endif /* !ST_HSM */

#endif /* CONFIG_H_ */
