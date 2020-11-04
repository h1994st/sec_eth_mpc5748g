/*
 * tlsTask.h
 *
 *  Created on: 2020/11/4
 *      Author: shengtuo
 */

#ifndef TLSTASK_H_
#define TLSTASK_H_

#include "config.h"

#if ST_TLS_APP

void tlsMainLoopTask(void* pvParameters);

#endif /* ST_TLS_APP */

#endif /* TLSTASK_H_ */
