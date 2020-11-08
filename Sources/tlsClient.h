/*
 * tlsClient.h
 *
 *  Created on: 2020/11/8
 *      Author: shengtuo
 */

#ifndef TLSCLIENT_H_
#define TLSCLIENT_H_

#include "config.h"

#if ST_TLS_APP && (ST_TLS_TYPE == 0)

#include "lwip/opt.h"

#if LWIP_SOCKET

void tlsClientInit(void);

#endif /* LWIP_SOCKET */
#endif /* ST_TLS_APP && (ST_TLS_TYPE == 0) */
#endif /* TLSCLIENT_H_ */
