#pragma once
#include <cstddef>
#include <cstdint>

// Hàm mã hóa AES-GCM
bool aesEncryptGCM(const uint8_t* key, const uint8_t* iv, const uint8_t* in, size_t inLen,
                   uint8_t* out, uint8_t* tag);

// Hàm giải mã AES-GCM
bool aesDecryptGCM(const uint8_t* key, const uint8_t* iv, const uint8_t* in, size_t inLen,
                   const uint8_t* tag, uint8_t* out);
