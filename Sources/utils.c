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

size_t custom_itoa(char *result, size_t bufsize, int number) {
	char *res = result;
	char *tmp = result + bufsize - 1;
	int n = (number >= 0) ? number : -number;

	/* handle invalid bufsize */
	if (bufsize < 2) {
		if (bufsize == 1) {
			*result = 0;
		}
		return 0;
	}

	/* First, add sign */
	if (number < 0) {
		*res++ = '-';
	}
	/* Then create the string from the end and stop if buffer full,
	 and ensure output string is zero terminated */
	*tmp = 0;
	while ((n != 0) && (tmp > res)) {
		char val = (char) ('0' + (n % 10));
		tmp--;
		*tmp = val;
		n = n / 10;
	}
	if (n) {
		/* buffer is too small */
		*result = 0;
		return 0;
	}
	if (*tmp == 0) {
		/* Nothing added? */
		*res++ = '0';
		*res++ = 0;
		return 1;
	}
	/* move from temporary buffer to output buffer (sign is not moved) */
	size_t len = (result + bufsize) - tmp;
	memmove(res, tmp, len);
	return len;
}

void printUint32(uint32_t num) {
	char buf[10];
	size_t len = custom_itoa(buf, 10, num);
	printData((uint8_t*)buf, len);
}
