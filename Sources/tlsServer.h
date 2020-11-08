/*
 * tlsServer.h
 *
 *  Created on: 2020/10/28
 *      Author: shengtuo
 */

#ifndef TLSSERVER_H_
#define TLSSERVER_H_

#include "config.h"

#if ST_TLS_APP && (ST_TLS_TYPE == 1)

#include "lwip/opt.h"

#if LWIP_SOCKET

void tlsServerInit(void);

#endif /* LWIP_SOCKET */
#endif /* ST_TLS_APP && (ST_TLS_TYPE == 1) */
#endif /* TLSSERVER_H_ */
