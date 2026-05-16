#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/rc4.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/obj_mac.h>

void bad_md5_legacy(const unsigned char* data, size_t len, unsigned char* out) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, len);
    MD5_Final(out, &ctx);
}

void bad_md5_evp() {
    const EVP_MD* md = EVP_md5();
    (void)md;
}

void bad_sha1_legacy(const unsigned char* data, size_t len, unsigned char* out) {
    SHA1_Init(NULL);
    SHA1_Update(NULL, data, len);
    SHA1_Final(out, NULL);
}

void bad_des() {
    DES_key_schedule ks;
    DES_cblock key = {0};
    DES_set_key_unchecked(&key, &ks);
}

void bad_3des() {
    DES_ede3_cbc_encrypt(NULL, NULL, 0, NULL, NULL, NULL, NULL, 0);
}

void bad_rc4() {
    RC4_KEY k;
    unsigned char keymat[16] = {0};
    RC4_set_key(&k, sizeof(keymat), keymat);
}

void weak_rsa() {
    RSA* r = RSA_generate_key(1024, RSA_F4, NULL, NULL);
    (void)r;
}

const int kBadCurve = NID_secp256k1;
