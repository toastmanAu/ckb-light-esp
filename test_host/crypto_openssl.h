/*
 * crypto_openssl.h — OpenSSL crypto callbacks for secio_crypto_t
 */
#ifndef CRYPTO_OPENSSL_H
#define CRYPTO_OPENSSL_H

#include "ckb_secio.h"

#ifdef __cplusplus
extern "C" {
#endif

void crypto_openssl_init(secio_crypto_t *c);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_OPENSSL_H */
