#pragma once


#include <iostream>
#include <string>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
//#include <stdio.h>
#include <string.h>
//#include <stdint.h>

class ecc_base 
{
public:
    ecc_base() 
    {
        evp_sign_key = nullptr;
        evp_verify_key = nullptr;
        publickey = nullptr;
        privatekey = nullptr;
        signature = "";
        signature_len = 0;

        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
    }

    ~ecc_base() 
    {
        if (evp_sign_key)
            EVP_PKEY_free(evp_sign_key);
        if (evp_verify_key)
            EVP_PKEY_free(evp_verify_key);

        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data();
        ERR_free_strings();
    }

    int load_pubkey(std::string pubkey);
    int load_privkey(std::string privkey);
    int sign(const unsigned char *msg, size_t msglen);
    std::string get_signature();
    size_t get_signature_len();
    int verify(const unsigned char *sig, size_t siglen, const unsigned char *msg, size_t msglen);

private:
    size_t signature_len;
    std::string signature;

    EC_KEY *publickey;
    EC_KEY *privatekey;
    EVP_PKEY *evp_sign_key;
    EVP_PKEY *evp_verify_key;
};
