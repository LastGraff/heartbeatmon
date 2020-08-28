#include "ecdsa.h"

int ecc_base::load_pubkey(std::string pubkey) {
    FILE *fp;
    // load in the keys
    fp = fopen(pubkey.c_str(), "r");
    if (!fp)
        return -1;
    publickey = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!publickey) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    evp_verify_key = EVP_PKEY_new();
    int ret;
    ret = EVP_PKEY_assign_EC_KEY(evp_verify_key, publickey);
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 0;
}

int ecc_base::load_privkey(std::string privkey) {
    FILE *fp;
    fp = fopen(privkey.c_str(), "r");
    if (!fp)
        return -1;
    privatekey = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!privatekey) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    // validate the key
    int ret;
    ret = EC_KEY_check_key(privatekey);
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    evp_sign_key = EVP_PKEY_new();
    
    ret = EVP_PKEY_assign_EC_KEY(evp_sign_key, privatekey);
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    return 0;
}

int ecc_base::sign(const unsigned char *msg, size_t msglen) {
    if (!evp_sign_key || !msg)
        return -1;
    
    int ret;

    EVP_PKEY_CTX * key_ctx = EVP_PKEY_CTX_new(evp_sign_key, NULL);

    ret = EVP_PKEY_sign_init(key_ctx);
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    ret = EVP_PKEY_CTX_set_signature_md(key_ctx, EVP_sha256());
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    size_t sig_len=0;

    ret = EVP_PKEY_sign(key_ctx,NULL,&sig_len, msg , msglen);
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    signature.assign(sig_len,0);

    ret = EVP_PKEY_sign(key_ctx,(unsigned char *)&signature[0],&sig_len, msg, msglen);
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    signature_len = sig_len;
    EVP_PKEY_CTX_free(key_ctx);
    return 0;
}

std::string ecc_base::get_signature() {
    return signature;
}

size_t ecc_base::get_signature_len() {
    return signature_len;
}

int ecc_base::verify(const unsigned char *sig, size_t siglen, const unsigned char *msg, size_t msglen) {
    if (!evp_verify_key || !msg || !sig)
        return -1;
    int ret;
    
    EVP_PKEY_CTX * key_ctx = EVP_PKEY_CTX_new(evp_verify_key,NULL);
    ret = EVP_PKEY_verify_init(key_ctx);
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    ret = EVP_PKEY_CTX_set_signature_md(key_ctx, EVP_sha256());
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    ret = EVP_PKEY_verify(key_ctx, sig, siglen, msg , msglen);
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    EVP_PKEY_CTX_free(key_ctx);

    return 0;
}
