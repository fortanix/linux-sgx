/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 *
 */


#include <femc_enclave.h>
#include <femc_common.h>

static int64_t femc_cb_sha256 (size_t data_size, uint8_t *data,
        struct femc_sha256_digest *digest)

{
    sgx_status_t sgx_ret = SGX_SUCCESS;
    sgx_ret = sgx_sha256_msg(data, data_size, digest->md);
    if (sgx_ret != SGX_SUCCESS) {
        return = -1;
    }

    return 0;
}


static int db_rng (void *rng_param, unsigned char *output_buffer,
        size_t output_len)
{
    femc_encl_status_t ret;
    // Parameter passed should be used.
    if (rng_param) {
        return -1;
    }

    ret = femc_random(output_buffer, output_len);
    if (ret) {
        return -1;
    }
    return 0;
}
/*
typedef struct _sgx_rsa3072_public_key_t
{
    uint8_t mod[SGX_RSA3072_KEY_SIZE];
    uint8_t exp[SGX_RSA3072_PUB_EXP_SIZE];
} sgx_rsa3072_public_key_t;

typedef struct _sgx_rsa3072_key_t
{
    uint8_t mod[SGX_RSA3072_KEY_SIZE];
    uint8_t d[SGX_RSA3072_PRI_EXP_SIZE];
    uint8_t e[SGX_RSA3072_PUB_EXP_SIZE];
} sgx_rsa3072_key_t;
typedef uint8_t sgx_rsa3072_signature_t[SGX_RSA3072_KEY_SIZE];
*/

typedef struct rsa3072_pk_context_t
{
    sgx_rsa3072_public_key_t rsa3072_pub;
    sgx_rsa3072_key_t rsa3072;
} rsa3072_pk_context_t;


static int64_t femc_cb_sig (void *opaque_signing_context, uint8_t *data,
        size_t data_len, size_t max_sig_len, struct  femc_sig *signature,
        size_t *sig_len, femc_signing_algorithm_t *algorithm)
{
    int ret = 0;
    struct femc_sha256_digest digest;
    rsa3072_pk_context_t *ctx = (rsa3072_pk_context_t*)opaque_signing_context; // needs to be a pk_handle
    ret = femc_cb_sha256(data_len, data, &digest);
    if (ret) {
        //z_log(Z_LOG_ERROR, "Error db_femc_cb_sha256 %d\n", ret);
        goto out;
    }

    //ret = DkPkSign(ctx, md_alg, digest.md, sizeof(digest.md),
    //       (unsigned char *)&signature->sig, sig_len, db_rng, NULL);
    sgx_status_t stat = sgx_rsa3072_sign(data, ata_len,
        //const sgx_rsa3072_key_t *p_key,
        & ctx.rsa3072;
        sgx_rsa3072_signature_t *p_signature);

    if (stat != SGX_SUCCESS) {
        //z_log(Z_LOG_ERROR, "Error DkPksign %d\n", ret);
        goto out;
    }
    *algorithm = SIGN_SHA256_RSA;
    ret = 0;
out:
    return ret;


    /** Computes signature for a given data based on RSA 3072 private key
    *
    * A digital signature over a message consists of a 3072 bit number.
    *
    * Return: If private key, signature or data pointer is NULL,
    *                    SGX_ERROR_INVALID_PARAMETER is returned.
    *         If the signing process fails then SGX_ERROR_UNEXPECTED is returned.
    * Parameters:
    *   Return: sgx_status_t  - SGX_SUCCESS or failure as defined in sgx_error.h
    *   Inputs: uint8_t *p_data - Pointer to the data to be signed
    *           uint32_t data_size - Size of the data to be signed
    *           sgx_rsa3072_key_t *p_key - Pointer to the RSA key.
    *				Note: In IPP based version p_key->e is unused, hence it can be NULL.
    *   Output: sgx_rsa3072_signature_t *p_signature - Pointer to the signature output
    */
}


static int64_t db_femc_cb_verify_sha256_rsa (uint8_t *public_key,
        size_t public_key_len, uint8_t *data, size_t data_len,
        uint8_t *signature, size_t sig_len)
{
    int ret;
    PAL_PK_CONTEXT pub_ctx;
    struct femc_sha256_digest digest;

    ret = DkPublicKeyParse(&pub_ctx, public_key, public_key_len);
    if (ret) {
        z_log(Z_LOG_ERROR, "Error DkPublicKeyParse %d\n", ret);
        goto out;
    }

    ret = femc_cb_sha256(data_len, data, &digest);
    if (ret) {
        z_log(Z_LOG_ERROR, "Error db_femc_cb_sha256 %d\n", ret);
        goto out;
    }

    ret = DkPkVerify(&pub_ctx, PAL_MD_SHA256,
            digest.md, sizeof(digest.md), signature, sig_len);
    if (ret) {
        z_log(Z_LOG_ERROR, "Error DkPkVerify %d\n", ret);
        goto out;
    }

out:
    return ret;


    /** Verifies the signature for the given data based on the RSA 3072 public key.
    *
    * A digital signature over a message consists of a 3072 bit number.
    *
    * The typical result of the digital signature verification is one of the two values:
    *     SGX_Generic_ECValid - Digital signature is valid
    *     SGX_Generic_ECInvalidSignature -  Digital signature is not valid
    *
    * Return: If public key, signature, result or data pointer is NULL,
    *                    SGX_ERROR_INVALID_PARAMETER is returned.
    *         If the verification process fails then SGX_ERROR_UNEXPECTED is returned.
    * Parameters:
    *   Return: sgx_status_t  - SGX_SUCCESS or failure as defined in sgx_error.h
    *   Inputs: uint8_t *p_data - Pointer to the data to be verified
    *           uint32_t data_size - Size of the data to be verified
    *           sgx_rsa3072_public_key_t *p_public - Pointer to the public key
    *           sgx_rsa3072_signature_t *p_signature - Pointer to the signature
    *   Output: sgx_rsa_result_t *p_result - Pointer to the result of verification check
    */
    sgx_status_t sgx_rsa3072_verify(const uint8_t *p_data,
        uint32_t data_size,
        const sgx_rsa3072_public_key_t *p_public,
        const sgx_rsa3072_signature_t *p_signature,
		sgx_rsa_result_t *p_result);

}


static int64_t db_femc_cb_aes_cmac_128 (femc_aes_cmac_128_key_t *key, uint8_t *data,
        size_t data_len, struct femc_aes_cmac_128_mac *mac)
{
    const PAL_CIPHER_INFO *cipher_info;
    cipher_info = DkCipherInfoFromType(PAL_CIPHER_AES_128_ECB);

    return (int64_t) DkCipherCmac(cipher_info,
                        (unsigned char *)key->key_bytes,
                        (sizeof(key->key_bytes) *8),
                        (unsigned char *)data,
                        data_len,
                        (unsigned char *)mac);

    sgx_status_t SGXAPI sgx_rijndael128_cmac_msg(const sgx_cmac_128bit_key_t *p_key,
                                                    const uint8_t *p_src,
                                                    uint32_t src_len,
                                                    sgx_cmac_128bit_tag_t *p_mac);
}


static int init_femc_signer (struct femc_enclave_ctx_init_args *args,
        PAL_PK_CONTEXT *pk_ctx)
{

    int ret = 0;
    unsigned char* pub_key_buf = calloc(1, KEY_BUF_SIZE);
    size_t size = KEY_BUF_SIZE;
    if (!pub_key_buf) {
        ret = -ENOMEM;
        //z_log(Z_LOG_ERROR, "Can't alloc/ pem_key_buf memroy %d \n", ret);
        goto out;
    }

    ret = DkPublicKeyEncode(PAL_ENCODE_DER, pk_ctx,
                            pub_key_buf, &size);
    if (ret != 0) {
        //z_log(Z_LOG_ERROR, "Can't encode Private key in der format %d \n", ret);
        goto out;
    }

    args->app_public_key = pub_key_buf;
    args->app_public_key_len = size;
    args->crypto_functions.signer.sign = femc_cb_sig;
    args->crypto_functions.signer.opaque_signer_context = pk_ctx;
out:
    if (ret) {
        // TODO This should get freed after zircon calls libexit also.
        if (pub_key_buf) {
            free(pub_key_buf);
        }
    }
    return ret;
}


static int init_femc_crypto (struct femc_enclave_ctx_init_args *femc_ctx_args,
        PAL_PK_CONTEXT *pk_ctx)
{
    int ret;
    femc_ctx_args->crypto_functions.hash_sha256 = db_femc_cb_sha256;
    femc_ctx_args->crypto_functions.verify_sha256_rsa = db_femc_cb_verify_sha256_rsa;
    femc_ctx_args->crypto_functions.aes_cmac_128 = db_femc_cb_aes_cmac_128;
    ret = db_init_femc_signer(femc_ctx_args, pk_ctx);
    return ret;
}

/*typedef struct femc_encl_context PAL_FEMC_CONTEXT;
typedef enum femc_req_type PAL_FEMC_REQ;
enum femc_req_type {
    FEMC_REQ_ATTEST_KEY = 0,
    FEMC_REQ_HEARTBEAT = 1,
    FEMC_REQ_MAX = 2
};*/



static int db_init_femc_ctx_args (struct femc_enclave_ctx_init_args *femc_ctx_args,
        PAL_PK_CONTEXT *pk_ctx, femc_req_type req_type)
{
    femc_ctx_args->req_type = req_type;
    return init_femc_crypto(femc_ctx_args, pk_ctx);
}


static void
init_femc_global_args(struct femc_enclave_global_init_args *global_args)
{
    global_args->encl_helper_functions.enclave_calloc = calloc;
    global_args->encl_helper_functions.enclave_free = free;
    global_args->encl_helper_functions.buffer_is_within_enclave = sgx_is_within_enclave;
    global_args->encl_helper_functions.buffer_is_outside_enclave = sgx_is_outside_enclave;
}


typedef struct femc_encl_context PAL_FEMC_CONTEXT;

/* Init femc_context */
int _FEMCInit (PAL_FEMC_CONTEXT **femc_ctx, int req_type)
{
    int ret = 0;
    struct femc_enclave_ctx_init_args femc_ctx_init_args;
    struct femc_enclave_global_init_args femc_global_args;
    *femc_ctx = NULL;

    ret = db_init_femc_ctx_args(&femc_ctx_init_args, (PAL_PK_CONTEXT*)pk_ctx, req_type);
    if (ret < 0) {
        z_log(Z_LOG_ERROR, "db_init_femc_ctx_args error %d\n", ret);
        goto out;
    }
    /*
    db_init_femc_global_args(&femc_global_args);
    */
    ret = femc_enclave_global_init(&femc_global_args);
    if (ret != FEMC_STATUS_SUCCESS) {
        //z_log(Z_LOG_ERROR, "femc_enclave_global_init error %d\n", ret);
        ret = -1;
        goto out;

    }

    ret = femc_enclave_ctx_init(femc_ctx, &femc_ctx_init_args);
    if (ret != FEMC_STATUS_SUCCESS) {
        //z_log(Z_LOG_ERROR, "femc_enclave_ctx_init error %d\n", ret);
        ret = -1;
        goto out;
    }

out:
    if (ret < 0)
        *femc_ctx = NULL;
    return ret;
}

/* Init Fortanix certificate provisioning
 * If certificate is present bail out with a message
 * returns 0 on sucess
 * */
static int ftx_manager_cert_flow (const char* config_key)
{
    int ret = 0;
    char value[CONFIG_MAX];
    PAL_FEMC_CONTEXT   *femc_ctx  = NULL;
    PAL_PK_CONTEXT     pk_ctx     = {0};
    struct shim_handle *shim_hdl  = NULL;
    void               *femc_cert = NULL;

    /*
     * An un-initiliazed context can not be freed.
     * But a freed context is always initialized, hence can be
     * freed again.
     */
    DkPkInit(&pk_ctx);

    //TODO verify cert validity and with the key ZIRC-2662
    /* Create the cert file if it doesn't already exist */
    ret = create_file(value, &shim_hdl);
    if (ret == -EEXIST){
        z_log(Z_LOG_DEBUG, "%s certificate found at %s \n", FORTANIX_MANAGER_UI_NAME, value);
        z_log(Z_LOG_DEBUG, "Please remove certificate %s to request a new certificate \n", value);
        ret = 0;
        goto out;
    } else if (ret != 0) {
        z_log(Z_LOG_FATAL, "Can't open cert file ret = %d\n", ret);
        goto out;
    }

    // TODO Figure out extended attributes
    ret = config_get_value(config_key, "subject", value);
    if (ret != 0) {
        z_log(Z_LOG_FATAL, "Cert subject not found in configuration\n");
        goto out;
    }

    /* Generate private key and write it to file */
    ret = create_key(config_key, &pk_ctx);
    if (ret != 0) {
        z_log(Z_LOG_FATAL, "Can't create private key error %d\n", ret);
        goto out;
    }

    /* Initialize FEMC context */
    ret = DkFEMCInit(&femc_ctx, &pk_ctx, FEMC_REQ_ATTEST_KEY);
    if (!ret) {
        ret = -PAL_ERRNO;
        z_log(Z_LOG_FATAL, "Femc init failed error %d\n", ret);
        goto out;
    }

    /* Fortanix certificate provisioning - uses FEMC API to connect
     * to malbork and returns a buffer containing certificate data.
     */
    ret = DkFEMCCertProvision(femc_ctx, value, &femc_cert);
    if (!ret) {
        ret = -PAL_ERRNO;
        z_log(Z_LOG_FATAL, "Fortanix certificate provisioning failed %s error %d\n" ,config_key, ret);
        goto out;
    }

    /* Write the cert data to file, exclude the null character at the end */
    ret = write_all_data(shim_hdl, femc_cert, strlen(femc_cert) -1, 0);
    if (ret < strlen(femc_cert) -1) {
        z_log(Z_LOG_FATAL, "Can't write Cert to file %d \n", ret);
        goto out;
    }

    ret = 0;

out:
    DkPkFree(&pk_ctx);
    /* FEMC context delete */
    if (femc_ctx) {
        if (!DkFEMCExit(&femc_ctx)) {
            z_log(Z_LOG_FATAL, "Femc exit failed\n");
        }
    }
    /* Buffer allocated in the pal, containing the certificate */
    if (femc_cert) {
        free(femc_cert);
    }

    return ret;
}





int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    PAL_FEMC_CONTEXT *femc_ctx;
    int req_type = 0;
    _FEMCInit (&femc_ctx, req_type);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;


}
