/*
 * tlsServer.h
 *
 *  Created on: 2020/10/28
 *      Author: shengtuo
 */

#ifndef TLSSERVER_H_
#define TLSSERVER_H_

#include "lwip/opt.h"

#if LWIP_SOCKET

/* Use 1024 bits certificate */
#define CERT_1024

// -- by h1994st: use 256-bit ecc key
#define CERT_256

void tlsInit(void);

#endif

#endif /* TLSSERVER_H_ */
