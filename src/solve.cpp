#include <unordered_map>
#include <iostream>
#include <random>
#include <ctime>

#include "../lib/cm.h"
#include "../include/solve.h"
#include "../include/cipher.h"

#define DEBUG_TIME_STEP 5000000

using namespace std;

uint64_t F(uint64_t x, uint64_t k) {
    /**
     * @brief Round function F = XSL
     */
    return L(S(X(x,k)));
}

uint64_t rand48() {
    uint64_t x = rand();
    x <<= 16u;
    x ^= rand();
    return x;
}

uint64_t retrieve_key() {
    /**
     * @brief Slide attack to retrieve 48-bit key
     * @details
     * General slide-attack algorithm idea:
     *   1.  M, M'  random texts
     *   2.  C, C'  corr. enctexts
     *   3.  suppose  M' = F(M),  C' = F(C)  =>   (M,C), (M',C')  - slid pair
     *   4.  check Kfirst = Klast
     *   5.  check E(M) == Ek(M)
     *
     * More detailed algorithm representation:
     *
     * while (true)
     *   1. pick random M
     *   2. compute C = enc(M),  store  (inv_S(inv_L(M)) + inv_S(inv_L(C))) -> (M, C)
     *   4. suppose (M',C') = (F(M),F(C)),
     *      derive K_first from M' = F(M), and K_last from C' = F(C):
     *
     *          M' = L(S(M + k))
     *          inv_S(inv_L(M')) = M + k
     *
     *          k  =  M + inv_S(inv_L(M'))
     *          k' =  C + inv_S(inv_L(C'))
     *
     *          =>   0 = M + C + inv_S(inv_L(M')) + inv_S(inv_L(C'))
     *
     *          =>   M + C = inv_S(inv_L(M')) + inv_S(inv_L(C'))
     *
     *          condition:   M+C == stored,  => get M, C, M', C'
     *          check k = k'
     *
     *          check enc(M, k) = C
     *
     *   M' = F(M)
     *   M' + C' = LS M + LS C
     *   M' + k = L S M
     *   S-1 L-1 M' + k = M
     *   S-1 L-1 C' + k = C
     *
     *   M+C = S-1L-1M' + S-1L-1C'
     *
     *
     *
     *
     *    5. if K_first = K_last, and enc(M, K) = C, return K
     */

    uint64_t M, M_, C, C_, K_first, K_last;
    unordered_map <uint64_t, pair<uint64_t, uint64_t>> pairs;

    auto start_time = time(nullptr);
    cerr << "[DEBUG] Key retrieval started at " << time(nullptr) << endl;

    while (true) {
        if (pairs.size() % DEBUG_TIME_STEP == 0)
            cerr << "[DEBUG] Collected " << pairs.size() << " pairs in " << time(nullptr) - start_time << " s" << endl;

        M = rand48();
        C = enc(M);

        if (pairs.contains(M^C)) {
            M_ = pairs[M^C].first;
            C_ = pairs[M^C].second;
            if (M_ == M) continue;

            cerr << "[DEBUG] found (M',C') pair, checking k1 = k2..." << endl;

            K_first = M ^ inv_S(inv_L(M_));
            K_last = C ^ inv_S(inv_L(C_));

            if (K_first == K_last) {
                cerr << "[DEBUG] verified k1 = k2 = " << std::hex << K_first << " for M = " << M << endl;

                if (M == decrypt(C, K_first) && M_ == decrypt(C_, K_first)) {
                    cerr << "[INFO]  Found key: " << std::hex << K_first << " in " << std::dec << time(nullptr) - start_time << " s" << endl;
                    return K_first;
                } else cerr << "[DEBUG] sorry, it was a false-positive" << std::dec << endl;
            }
        }
        pairs[(inv_S(inv_L(M)) ^ inv_S(inv_L(C)))] = make_pair(M, C);
    }
}