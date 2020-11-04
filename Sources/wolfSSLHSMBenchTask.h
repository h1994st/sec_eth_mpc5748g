/*
 * wolfSSLHSMBenchTask.h
 *
 *  Created on: 2020/11/4
 *      Author: shengtuo
 */

#ifndef WOLFSSLHSMBENCHTASK_H_
#define WOLFSSLHSMBENCHTASK_H_

#include "config.h"

#if ST_BENCH_WOLFSSL_HSM

void wolfSSLHSMBenchMainLoopTask(void* pvParameters);

#endif /* ST_BENCH_WOLFSSL_HSM */

#endif /* WOLFSSLHSMBENCHTASK_H_ */
