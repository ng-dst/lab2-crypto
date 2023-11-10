#ifndef CRYPT2_CIPHER_H
#define CRYPT2_CIPHER_H

#include <cstdint>

#define BLOCK_SIZE 48
#define NUM_SUBBLOCKS 6

#define NUM_ROUNDS 32

#define MASK 0xffffffffffffull


uint64_t L(uint64_t);
uint64_t S(uint64_t);
uint8_t S_8(uint8_t);
uint64_t X(uint64_t, uint64_t);

uint64_t inv_L(uint64_t);
uint64_t inv_S(uint64_t);
uint8_t inv_S_8(uint8_t);

uint64_t decrypt(uint64_t, uint64_t);

#endif //CRYPT2_CIPHER_H
