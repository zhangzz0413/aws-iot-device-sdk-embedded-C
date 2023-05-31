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

/**
 * @file mbedtls_operations.c
 *
 * @brief This file provides wrapper functions for mbedtls operations.
 */

/* Standard includes. */
#include <errno.h>
#include <assert.h>

/* Config include. */
#include "demo_config.h"

/*Include mbedtls operation header. */
#include "mbedtls_operations.h"

/**
 * @brief Size of rsa key in which to generate rsa key.
 */
#define RSA_KEY_SIZE                   2048

/**
 * @brief Size of rsa exponent in which to generate rsa key.
 */
#define RSA_KEY_EXPONENT               65537

/**
 * @brief Size of buffer in which to hold the certificate signing request (CSR).
 */
#define PRIVATE_KEY_BUFFER_LENGTH      16000

/*-----------------------------------------------------------*/

bool writeCertificateToFile( char *pCertBuffer, size_t certSize, const char *pFileName )
{
    int i = 0;
    FILE *file = NULL;

    if ( pCertBuffer == NULL || pFileName == NULL )
    {
        LogError( ( "Invalid parameters to writecertificate..." ) );
        return false;
    }

    file = fopen( pFileName, "w" );
    if ( !file )
    {
        LogError( ( "Failed to open file %s for writing certificate...", pFileName ) );
        return false;
    }

    for ( i = 0; i < certSize; i++ )
    {
        fprintf( file, "%c", pCertBuffer[i]);
    }

    fclose( file );

    return true;
}

bool writePrivateKeyToFile( mbedtls_pk_context *pKey, const char *pFileName )
{
    int32_t ret = -1;
    unsigned char output_buf[PRIVATE_KEY_BUFFER_LENGTH];
    unsigned char *c = output_buf;
    FILE *f;
    size_t len = 0;

    if ( pKey == NULL || pFileName == NULL)
    {
        LogError( ( "Invalid parameters to write private key..." ) );
        return false;
    }

    memset( output_buf, 0, PRIVATE_KEY_BUFFER_LENGTH );
    ret = mbedtls_pk_write_key_pem( pKey, output_buf, PRIVATE_KEY_BUFFER_LENGTH );
    if( ret != 0 )
    {
        LogError( ( "Failed to write private key to pem..." ) );
        return false;
    }

    len = strlen( (char *)output_buf );

    if( ( f = fopen( pFileName, "wb" ) ) == NULL )
    {
        LogError( ( "Failed to open file %s for writing private key...", pFileName ) );
        return false;
    }

    if( fwrite( c, 1, len, f ) != len )
    {
        fclose( f );
        LogError( ( "Failed to write file for saved private key..." ) );
        return false;
    }

    fclose( f );

    return true;
}

bool generateKeyAndCsr( char * pCsrBuffer, size_t csrBufferLength, size_t * pOutCsrLength )
{
    int32_t mbedtlsRet = -1;
    mbedtls_pk_context privKey;
    mbedtls_pk_info_t privKeyInfo;
    mbedtls_x509write_csr req;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const mbedtls_pk_info_t * header = mbedtls_pk_info_from_type( MBEDTLS_PK_ECKEY );

    mbedtls_x509write_csr_init( &req );
    mbedtls_x509write_csr_set_md_alg( &req, MBEDTLS_MD_SHA256 );

    mbedtlsRet = mbedtls_x509write_csr_set_key_usage( &req, MBEDTLS_X509_KU_DIGITAL_SIGNATURE );

    if( mbedtlsRet == 0 )
    {
        mbedtlsRet = mbedtls_x509write_csr_set_ns_cert_type( &req, MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT );
    }

    if( mbedtlsRet == 0 )
    {
        mbedtlsRet = mbedtls_x509write_csr_set_subject_name( &req, CSR_SUBJECT_NAME );
    }

    if( mbedtlsRet == 0 )
    {
        mbedtls_pk_init( &privKey );
        mbedtls_ctr_drbg_init( &ctr_drbg );
        mbedtls_entropy_init( &entropy );
    }

    /* Add entropy and setup random generator. */
    mbedtlsRet = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0 );

    if( mbedtlsRet == 0 )
    {
        mbedtlsRet = mbedtls_pk_setup( &privKey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA) );
    }

    if( mbedtlsRet == 0 )
    {
        /* Generate key pair */
        mbedtlsRet = mbedtls_rsa_gen_key( mbedtls_pk_rsa(privKey),
                                          mbedtls_ctr_drbg_random,
                                          &ctr_drbg,
                                          RSA_KEY_SIZE,
                                          RSA_KEY_EXPONENT );
        if ( ( writePrivateKeyToFile( &privKey, DEVICE_PRIVATE_KEY_PATH ) ) != true )
        {
            LogError( ( "Failed to write private key..." ) );
            mbedtlsRet = -1;
        }
    }

    if( mbedtlsRet == 0 )
    {
        mbedtls_x509write_csr_set_key( &req, &privKey );

        mbedtlsRet = mbedtls_x509write_csr_pem( &req, ( unsigned char * ) pCsrBuffer,
                                                csrBufferLength, mbedtls_ctr_drbg_random, &ctr_drbg );
    }

    mbedtls_x509write_csr_free( &req );
    mbedtls_pk_free( &privKey );
    mbedtls_entropy_free( &entropy );
    mbedtls_ctr_drbg_free( &ctr_drbg );

    *pOutCsrLength = strlen( pCsrBuffer );

    return( mbedtlsRet == 0 );
}

/*-----------------------------------------------------------*/
