/*
 * utils.h
 *
 *  Created on: 2020/11/8
 *      Author: shengtuo
 */

#ifndef UTILS_H_
#define UTILS_H_

#include <stdint.h>
#include <stdbool.h>

double current_time(void);
uint32_t current_time_ms(void);

bool bufferCompare(uint8_t *buff1, uint8_t *buff2, uint32_t len);

#endif /* UTILS_H_ */
