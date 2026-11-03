/* SPDX-License-Identifier: Apache-2.0 */
#ifndef AA_TLS_CONFIG_H
#define AA_TLS_CONFIG_H
#include <stdint.h>
#include <stddef.h>
#ifdef AA_TLS_HOST
/* Linux host proof uses libc formatting. The freestanding formatter remains
 * a separate, unvalidated platform dependency; this is not a native build. */
#include <stdio.h>
#define MBEDTLS_PLATFORM_SNPRINTF_MACRO snprintf
#define MBEDTLS_PLATFORM_VSNPRINTF_MACRO vsnprintf
#endif
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C
#define MBEDTLS_MEMORY_DEBUG
int aa_tls_ignore_fprintf(void *, const char *, ...);
void aa_tls_allocator_fatal(int);
#define MBEDTLS_PLATFORM_FPRINTF_MACRO(stream, ...) aa_tls_ignore_fprintf(NULL, __VA_ARGS__)
#define MBEDTLS_PLATFORM_EXIT_MACRO aa_tls_allocator_fatal
#define MBEDTLS_PLATFORM_STD_EXIT_FAILURE 1
#define MBEDTLS_PLATFORM_STD_EXIT_SUCCESS 0
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE
#define MBEDTLS_PLATFORM_TIME_TYPE_MACRO int64_t
int64_t aa_tls_clock_read(int64_t *);
#define MBEDTLS_PLATFORM_TIME_MACRO aa_tls_clock_read
#define MBEDTLS_PLATFORM_GMTIME_R_ALT
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_GCM_C
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
#define MBEDTLS_SSL_IN_CONTENT_LEN 16384
#define MBEDTLS_SSL_OUT_CONTENT_LEN 16384
#endif
