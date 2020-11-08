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

/* Application type */
#if (ST_TLS_TYPE == 0) // client
#include "tlsClient.h"
#define tlsInit tlsClientInit
#elif (ST_TLS_TYPE == 1) // server
#include "tlsServer.h"
#define tlsInit tlsServerInit
#else // error
#error "No such TLS application types!"
#endif /* ST_TLS_TYPE */

/* Certificate configurations */
#if (ST_TLS_CERT_TYPE == 0) // RSA 1024

/* Use 1024 bits certificate */
#define USE_CERT_BUFFERS_1024
#include <certs_test.h>

#define CA_CERT				ca_cert_der_1024
#define CA_CERT_SIZE		sizeof_ca_cert_der_1024
#define SERVER_CERT			server_cert_der_1024
#define SERVER_CERT_SIZE	sizeof_server_cert_der_1024
#define CLIENT_CERT			client_cert_der_1024
#define CLIENT_CERT_SIZE	sizeof_client_cert_der_1024
#define SERVER_KEY			server_key_der_1024
#define SERVER_KEY_SIZE		sizeof_server_key_der_1024

#elif (ST_TLS_CERT_TYPE == 1) // RSA 2048

#define USE_CERT_BUFFERS_2048
#include <certs_test.h>

#define CA_CERT				ca_cert_der_2048
#define CA_CERT_SIZE		sizeof_ca_cert_der_2048
#define SERVER_CERT			server_cert_der_2048
#define SERVER_CERT_SIZE	sizeof_server_cert_der_2048
#define CLIENT_CERT			client_cert_der_2048
#define CLIENT_CERT_SIZE	sizeof_client_cert_der_2048
#define SERVER_KEY			server_key_der_2048
#define SERVER_KEY_SIZE		sizeof_server_key_der_2048

#elif (ST_TLS_CERT_TYPE == 2) // ECC 256

// -- by h1994st: use 256-bit ecc key
#define USE_CERT_BUFFERS_256
#include <certs_test.h>
#define CA_CERT				cliecc_cert_der_256
#define CA_CERT_SIZE		sizeof_cliecc_cert_der_256
#define SERVER_CERT			serv_ecc_der_256
#define SERVER_CERT_SIZE	sizeof_serv_ecc_der_256
#define CLIENT_CERT			cliecc_cert_der_256
#define CLIENT_CERT_SIZE	sizeof_cliecc_cert_der_256
#define SERVER_KEY			ecc_key_der_256
#define SERVER_KEY_SIZE		sizeof_ecc_key_der_256

#else // error
#error "No such TLS certificate type!"
#endif /* ST_TLS_CERT_TYPE */

/* Main loop */
void tlsMainLoopTask(void* pvParameters);

#endif /* ST_TLS_APP */

#endif /* TLSTASK_H_ */
