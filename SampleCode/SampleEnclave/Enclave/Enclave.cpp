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
typedef struct {
    uint8_t key_bytes[AES_CMAC_128_KEY_SIZE];
} femc_aes_cmac_128_key_t;

__attribute__((__packed__)) struct femc_aes_cmac_128_mac {
    uint8_t mac[AES_CMAC_128_MAC_SIZE];
}
*/


typedef struct rsa3072_pk_context_t
{
    sgx_rsa3072_public_key_t rsa3072_pub;
    sgx_rsa3072_key_t rsa3072;
} rsa3072_pk_context_t;

//typedef uint8_t sgx_cmac_128bit_key_t[SGX_CMAC_KEY_SIZE];
// typedef uint8_t sgx_cmac_128bit_tag_t[SGX_CMAC_MAC_SIZE];
//
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
    sgx_status_t stat = sgx_rsa3072_sign(data, data_len,
        //const sgx_rsa3072_key_t *p_key,
        & ctx.rsa3072;
        signature->sig);

    if (stat != SGX_SUCCESS) {
        //z_log(Z_LOG_ERROR, "Error DkPksign %d\n", ret);
        goto out;
    }
    *algorithm = SIGN_SHA256_RSA;
    ret = 0;
out:
    return ret;

}


static int64_t femc_cb_verify_sha256_rsa (uint8_t *public_key,
        size_t public_key_len, uint8_t *data, size_t data_len,
        uint8_t *signature, size_t sig_len)
{
    int ret;
    PAL_PK_CONTEXT pub_ctx;
    struct femc_sha256_digest digest;

    ret = femc_cb_sha256(data_len, data, &digest);
    if (ret) {
        z_log(Z_LOG_ERROR, "Error db_femc_cb_sha256 %d\n", ret);
        goto out;
    }

    /*ret = DkPkVerify(&pub_ctx, PAL_MD_SHA256,
            digest.md, sizeof(digest.md), signature, sig_len);
    */
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

    sgx_status_t ret = sgx_rsa3072_verify(data,
        data_len,
        const sgx_rsa3072_public_key_t *p_public,
        const sgx_rsa3072_signature_t *p_signature,
		sgx_rsa_result_t *p_result);
    if (ret) {
        //z_log(Z_LOG_ERROR, "Error DkPkVerify %d\n", ret);
        goto out;
    }

out:
    return ret;


}


static int64_t femc_cb_aes_cmac_128 (femc_aes_cmac_128_key_t *key, uint8_t *data,
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

    sgx_status_t ret = sgx_rijndael128_cmac_msg(key->key_bytes,
                                                    data,
                                                    data_len,
                                                    mac->mac);
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
    femc_ctx_args->crypto_functions.aes_cmac_128 = femc_cb_aes_cmac_128;
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


// Local attestation, Needs cert fields
static int _FEMCLocalAttestation (PAL_FEMC_CONTEXT *femc_ctx,
        struct femc_la_rsp **la_rsp, PAL_STR subject)
{
    int ret = 0;
    struct femc_data_bytes *tgt_info = NULL;
    struct femc_la_req *la_req = NULL;
    size_t la_req_size;
    struct femc_la_rsp *la_rsp_temp = NULL;

    // Generate Local Attestation Request:
    struct femc_data_bytes const * const extra_subject = NULL;
    struct femc_data_bytes const *extra_attr = NULL;

    ret = ocall_get_targetinfo(femc_ctx, &tgt_info);
    if (ret < 0) {
        z_log(Z_LOG_ERROR, "ocall_get_targetinfo error %d\n", ret);
        goto out;
    }
    // Generate Local Attestation Request:
    ret = femc_generate_la_req(&la_req, &la_req_size, femc_ctx, &tgt_info,
            subject, strlen(subject), extra_subject, extra_attr);
    if (ret != FEMC_STATUS_SUCCESS) {
        z_log(Z_LOG_ERROR, "femc_generate_la_req error %d\n", ret);
        ret = -PAL_ERROR_INVAL;
        goto out;
    }
    // Ocall to attest with node agent
    ret = ocall_local_attest(femc_ctx, &la_req, &la_rsp_temp, &la_req_size);
    if (ret < 0) {
        z_log(Z_LOG_ERROR, "ocall_local_attest error %d\n", ret);
        goto out;
    }
out:
    *la_rsp = la_rsp_temp;
    if (la_req) {
        free_la_req(femc_ctx, &la_req);
    }
    if (tgt_info) {
        free_tgt_info_rsp(femc_ctx, &tgt_info);
    }
    return ret;
}

// Remote attestation
static int _FEMCRemoteAttestation (PAL_FEMC_CONTEXT *femc_ctx,
    struct femc_la_rsp **la_rsp, struct femc_ra_rsp **ra_rsp, PAL_STR subject)
{

    int ret = 0;

    /* TODO: fill cert info*/
    struct femc_data_bytes const * const extra_subject = NULL;
    struct femc_data_bytes const *extra_attr = NULL;

    struct femc_ra_req *ra_req = NULL;
    size_t ra_req_size;
    struct femc_ra_rsp *ra_rsp_tmp = NULL;

    // frees la_rsp
    ret = femc_generate_ra_req(femc_ctx, &ra_req, &ra_req_size,
            la_rsp, subject, strlen(subject), extra_subject, extra_attr);
    if (ret != FEMC_STATUS_SUCCESS) {
        z_log(Z_LOG_ERROR, "femc_generate_ra_req error %d\n", ret);
        ret = -PAL_ERROR_INVAL;
        goto out;
    }
    // Ocall to send ra_req_oe to node agent to get ra_rsp_oe
    ret = ocall_remote_attest(femc_ctx, &ra_req, &ra_rsp_tmp, &ra_req_size);
    if (ret < 0) {
        z_log(Z_LOG_ERROR, "ocall_remote_attest error %d\n", ret);
        goto out;
    }
    // Verify ra_resp
    ret = verify_ra_rsp(femc_ctx, ra_rsp_tmp);

    if (ret != FEMC_STATUS_SUCCESS) {
        z_log(Z_LOG_ERROR, "verify_ra_rsp error %d\n", ret);
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

out:
    *ra_rsp = ra_rsp_tmp;
    if (ra_req) {
        free_ra_req(femc_ctx, &ra_req);
    }
    if (ret) {
        if (*ra_rsp) {
            free(*ra_rsp);
            *ra_rsp = NULL;
        }
    }


    return ret;
}


int _DkFEMCCertProvision(PAL_FEMC_CONTEXT *femc_ctx, PAL_STR subject, void **femc_cert)
{
    int ret = 0;

    struct femc_la_rsp *la_rsp = NULL;
    struct femc_ra_rsp *ra_rsp = NULL;

    ret = _FEMCLocalAttestation (femc_ctx, &la_rsp, subject);
    if (ret) {
        z_log(Z_LOG_ERROR, "Femc local attestation failed \n");
        goto out;
    }

    ret = _FEMCRemoteAttestation (femc_ctx, &la_rsp, &ra_rsp, subject);
    if (ret || ra_rsp == NULL || ra_rsp->app_cert.data_len < 1) {
        z_log(Z_LOG_ERROR, "Femc remote attestation failed \n");
        goto out;
    }

    // Check PEM is null ternimated -> don't write the last character.
    assert(ra_rsp->app_cert.pem[ra_rsp->app_cert.data_len -1]=='\0');

    /* Allocate a buffer for the certificate data and pass it
     * to shim since shim does not have access to free_ra_rsp.
     * The shim is responsible of freeing this buffer after writing it
     * to file.
     */
    void *cert_data = malloc(ra_rsp->app_cert.data_len);
    memcpy(cert_data, ra_rsp->app_cert.pem, ra_rsp->app_cert.data_len);
    *femc_cert = cert_data;

    SGX_DBG(DBG_I, " Femc Attestation response cert recvd: bytes  %d for cert \n  %s\n",
        ra_rsp->app_cert.data_len, (char*)*femc_cert);
out:
    if (la_rsp) {
        free_la_rsp(femc_ctx, &la_rsp);
    }

    if (ra_rsp) {
        free_ra_rsp(femc_ctx, &ra_rsp);
    }

    return ret;
}

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

    /** Create RSA key pair with <n_byte_size> key size and <e_byte_size> public exponent.
    *
    * Parameters:
    *   Return: sgx_status_t  - SGX_SUCCESS or failure as defined in sgx_error.h
    *   Inputs: p_e [In/Out] Pointer to the public exponent e.
    *           n_byte_size [In] Size in bytes of the key modulus.
    *           e_byte_size	[In] Size in bytes of the key public exponent.
    *   Output: p_*			[Out] Pointer to the matching key parameter/factor buffer.
    */
    sgx_status_t sgx_create_rsa_key_pair(int n_byte_size, int e_byte_size, unsigned char *p_n, unsigned char *p_d, unsigned char *p_e,
        unsigned char *p_p, unsigned char *p_q, unsigned char *p_dmp1,
        unsigned char *p_dmq1, unsigned char *p_iqmp);

    /* Generate private key and write it to file */
    ret = create_key(config_key, &pk_ctx);
    if (ret != 0) {
        //z_log(Z_LOG_FATAL, "Can't create private key error %d\n", ret);
        goto out;
    }

    /* Initialize FEMC context */
    ret = _FEMCInit(&femc_ctx, &pk_ctx, FEMC_REQ_ATTEST_KEY);
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
