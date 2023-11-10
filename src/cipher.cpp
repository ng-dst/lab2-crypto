#pragma clang diagnostic push
#pragma ide diagnostic ignored "hicpp-signed-bitwise"

#include "../include/cipher.h"


uint64_t L(uint64_t x) {
    /**
     * @brief L-transform, left shift by 11
     * @details
     * Cyclic left shift of 48-bit word achieved by combining 'overflow' and regular shifted parts.
     */
    return (x << 11)&MASK | (x >> (BLOCK_SIZE - 11));
}

uint8_t S_8(uint8_t x) {
    /**
     * @brief S-transform for 8-bit subblock (x2 of 4-bit)
     * @details
     * Two paired 4-bit S-boxes for each halves of 8-bit word.
     *
     * @bug can be optimized if we avoid using arrays.
     */
    static const uint8_t Sbox[] = {14, 7, 8, 4, 1, 9, 2, 15, 5, 10, 11, 0, 6, 12, 13, 3};
    return Sbox[x & 0x0f] | (Sbox[(x >> 4) & 0x0f] << 4);
}

uint64_t S(uint64_t x) {
    /**
     * @brief S-transform for 48-bit block (x12 of 4-bit)
     * @details
     * Takes 48-bit buffer (formally 64-bit).
     * Then represents it as array of 6 8-bit subblocks, each of them is passed to paired 8-bit S-box.
     * First 48 bits are processed, thanks to Little byte order. Resulting buffer is returned.
     *
     * @bug Can be optimized if we avoid using pointers and arrays.
     */
     uint64_t buf = x;
     auto* y = (uint8_t*) &buf;
     for (auto i = 0; i < NUM_SUBBLOCKS; i++)
         y[i] = S_8(y[i]);
     return buf;
}

uint64_t X(uint64_t x, uint64_t k) {
    /**
     * @brief XOR with 48-bit key
     */
     return x^k;
}


uint64_t inv_L(uint64_t x) {
    /**
     * @brief inverse L-transform, right shift by 11
     */
    return (x >> 11) | (x << (BLOCK_SIZE - 11))&MASK;
}

uint8_t inv_S_8(uint8_t x) {
    /**
     * @brief inverse S-transform for 8-bit subblock (x2 of 4-bit)
     * @bug can be optimized if we avoid using arrays.
     */
    static const uint8_t iSbox[] = {11, 4, 6, 15, 3, 8, 12, 1, 2, 5, 9, 10, 13, 14, 0, 7};
    return iSbox[x & 0x0f] | (iSbox[(x >> 4) & 0x0f] << 4);
}

uint64_t inv_S(uint64_t x) {
    /**
     * @brief inverse S-transform for 48-bit block (x12 of 4-bit)
     * @bug Can be optimized if we avoid using pointers and arrays.
     */
    uint64_t buf = x;
    auto* y = (uint8_t*) &buf;
    for (auto i = 0; i < NUM_SUBBLOCKS; i++)
        y[i] = inv_S_8(y[i]);
    return buf;
}

uint64_t decrypt(uint64_t x, uint64_t k) {
    /**
     * @brief Decrypt routine with 48-bit key
     * @details
     * Applies 32-round encryption SP-net in reverse
     */
     for (auto i = 0; i < NUM_ROUNDS; i++)
         x = X(inv_S(inv_L(x)), k);

     return x;
}

#pragma clang diagnostic pop
