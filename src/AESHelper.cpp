#include "AESHelper.h"
#include <mbedtls/gcm.h>
#include <cstring>

// Hàm mã hóa AES-GCM
bool aesEncryptGCM(const uint8_t* key, const uint8_t* iv, const uint8_t* in, size_t inLen,
                   uint8_t* out, uint8_t* tag) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128) != 0) {
        mbedtls_gcm_free(&ctx);
        return false;
    }

    int ret = mbedtls_gcm_crypt_and_tag(
        &ctx, MBEDTLS_GCM_ENCRYPT,
        inLen,
        iv, 12,
        nullptr, 0,
        in, out,
        16, tag
    );

    mbedtls_gcm_free(&ctx);
    return ret == 0;
}

// Hàm giải mã AES-GCM
bool aesDecryptGCM(const uint8_t* key, const uint8_t* iv, const uint8_t* in, size_t inLen,
                   const uint8_t* tag, uint8_t* out) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128) != 0) {
        mbedtls_gcm_free(&ctx);
        return false;
    }

    int ret = mbedtls_gcm_auth_decrypt(
        &ctx,
        inLen,
        iv, 12,
        nullptr, 0,
        tag, 16,
        in, out
    );

    mbedtls_gcm_free(&ctx);
    return ret == 0;
}
