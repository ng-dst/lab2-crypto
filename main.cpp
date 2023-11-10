#include <iostream>

#include "lib/cm.h"
#include "include/cipher.h"
#include "include/solve.h"

using namespace std;

// Ciphertext = 097f07940fec 1159ed6cffa9
const uint64_t msg_enc[] = {0x097f07940fec, 0x1159ed6cffa9};


int main() {
    char buf[8] = {0};
    setlocale(LC_ALL, "UTF8");

    cerr << "[INFO]  Decryption program launched, retrieving key..." << endl;
    uint64_t k = retrieve_key();  // 0xfe46328c1738

    cerr << "[SUCCESS] Key retrieved, decrypting..." << endl;
    for (auto block: msg_enc) {
        *((uint64_t*) buf) = decrypt(block, k);
        cout << buf[5] << buf[4] << buf[3] << buf[2] << buf[1] << buf[0];
    }
    cout << endl;

    return 0;
}
