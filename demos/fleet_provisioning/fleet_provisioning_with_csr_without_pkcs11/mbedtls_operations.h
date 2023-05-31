/*
 * AWS IoT Device SDK for Embedded C 202211.00
 * Copyright (C) 2021 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef MBEDTLS_OPERATIONS_H_
#define MBEDTLS_OPERATIONS_H_

/* Standard includes. */
#include <stdlib.h>
#include <stdbool.h>

/* MbedTLS include. */
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/entropy_poll.h"
#include "mbedtls/error.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "mbedtls/pk_internal.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"

/**
 * @brief Save the certificate obtained from the csr in a file.
 *
 * @param[in] certBuffer The buffer to write the certificate.
 * @param[in] size Length of #certBuffer.
 * @param[in] filename The path of the written certificate.
 *
 * @return True on success.
 */
bool writeCertificateToFile( char *pCertBuffer, size_t certSize, const char *pFileName );

/**
 * @brief Save the private key to a file.
 *
 * @param[in] pKey The context to write the private key.
 * @param[in] pOutputFile The path of the written private key.
 *
 * @return True on success.
 */
bool writePrivateKeyToFile( mbedtls_pk_context *pKey, const char *pFileName );

/**
 * @brief Generate a new public-private key pair in the PKCS #11 module, and
 * generate a certificate signing request (CSR) for them.
 *
 * This device-generated private key and CSR can be used with the
 * CreateCertificateFromCsr API of the the Fleet Provisioning feature of AWS IoT
 * Core in order to provision a unique client certificate.
 *
 * @param[out] pCsrBuffer The buffer to write the CSR to.
 * @param[in] csrBufferLength Length of #pCsrBuffer.
 * @param[out] pOutCsrLength The length of the written CSR.
 *
 * @return True on success.
 */
bool generateKeyAndCsr( char * pCsrBuffer, size_t csrBufferLength, size_t * pOutCsrLength );

#endif /* ifndef MBEDTLS_OPERATIONS_H_ */
