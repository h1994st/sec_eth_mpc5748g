/*
 * utils.c
 *
 *  Created on: 2020/11/8
 *      Author: shengtuo
 */

#include "utils.h"
#include "osif.h"

double current_time(void) {
	uint32_t msecs = OSIF_GetMilliseconds();
	return (double) msecs / (double) 1000;
}

uint32_t current_time_ms(void) {
	return OSIF_GetMilliseconds();
}

/* Compares two buffers; returns true if buffers are identical,
 * false if at least one element is different.
 */
bool bufferCompare(uint8_t *buff1, uint8_t *buff2, uint32_t len) {
	uint32_t idx;
	for (idx = 0; idx < len; idx++) {
		if (buff1[idx] != buff2[idx]) {
			return false;
		}
	}
	return true;
}
