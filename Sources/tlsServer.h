/*
 * tlsServer.h
 *
 *  Created on: 2020/10/28
 *      Author: shengtuo
 */

#ifndef TLSSERVER_H_
#define TLSSERVER_H_

#include "config.h"

#if ST_TLS_APP

#include "lwip/opt.h"

#if LWIP_SOCKET

#if ST_TLS_CERT_RSA_1024
/* Use 1024 bits certificate */
#define CERT_1024
#else
// -- by h1994st: use 256-bit ecc key
#define CERT_256
#endif /* ST_TLS_CERT_RSA_1024 */

void tlsInit(void);

#endif /* LWIP_SOCKET */

#endif /* ST_TLS_APP */

#endif /* TLSSERVER_H_ */
