#ifndef LWIP_TLS_SOCKET_H
#define LWIP_TLS_SOCKET_H

#include "lwip/opt.h"

#if LWIP_SOCKET

/* Use 1024 bits certificate */
#define CERT_1024

// -- by h1994st: use 256-bit ecc key
#define CERT_256

void secure_socket_init(void);

#endif /* LWIP_SOCKET */

#endif /* LWIP_TLS_SOCKET_H */
