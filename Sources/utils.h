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
#include <string.h>

#include "linflexd_uart1.h"

double current_time(void);
uint32_t current_time_ms(void);

bool bufferCompare(uint8_t *buff1, uint8_t *buff2, uint32_t len);
size_t custom_itoa(char *result, size_t bufsize, int number);

void printTimestamp();
#define printData(data, data_len) LINFLEXD_UART_DRV_SendDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)(data), (data_len), 1000U)
#define getData(data, data_len) LINFLEXD_UART_DRV_ReceiveDataBlocking(INST_LINFLEXD_UART1, (uint8_t *)(data), (data_len), 1000U)
#define printString(str) printData((str), strlen((str)))

#endif /* UTILS_H_ */
