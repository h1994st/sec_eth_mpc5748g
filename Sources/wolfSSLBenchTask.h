/*
 * wolfSSLBenchTask.h
 *
 *  Created on: 2020/11/4
 *      Author: shengtuo
 */

#ifndef WOLFSSLBENCHTASK_H_
#define WOLFSSLBENCHTASK_H_

#include "config.h"

#if ST_BENCH_WOLFSSL

void wolfSSLBenchMainLoopTask(void* pvParameters);

#endif /* ST_BENCH_WOLFSSL */

#endif /* WOLFSSLBENCHTASK_H_ */
