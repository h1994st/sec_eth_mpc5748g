/*
 * config.h
 *
 *  Created on: 2020/11/4
 *      Author: shengtuo
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#define ST_BENCH_W_HSM			0 // HSM: enabled

#define ST_BENCH_WOLFSSL		1
#if ST_BENCH_WOLFSSL
#define ST_NO_HSM // HSM: disabled
#endif

#define ST_TLS_APP				0 // HSM: enabled
#if ST_TLS_APP
#define ST_TLS_CERT_RSA_1024	1
#endif /* ST_TLS_APP */

#endif /* CONFIG_H_ */
