/*
 * hsmBenchTask.h
 *
 *  Created on: 2020/11/4
 *      Author: shengtuo
 */

#ifndef HSMBENCHTASK_H_
#define HSMBENCHTASK_H_

#include "config.h"

#if ST_BENCH_W_HSM

void hsmBenchMainLoopTask(void* pvParameters);

#endif /* ST_BENCH_W_HSM */

#endif /* HSMBENCHTASK_H_ */
