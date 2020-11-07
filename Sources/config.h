/*
 * config.h
 *
 *  Created on: 2020/11/4
 *      Author: shengtuo
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#define ST_BENCH_W_HSM			0

#define ST_BENCH_WOLFSSL		1

#define ST_TLS_APP				0
#if ST_TLS_APP
#define ST_TLS_CERT_RSA_1024	1
#endif /* ST_TLS_APP */

#endif /* CONFIG_H_ */
