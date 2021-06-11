//
// Created by zhiyong on 4/14/20.
//

#ifndef ZKDT_HHASH_H
#define ZKDT_HHASH_H

#include <cstdlib>
/*
const int HASH_SIZE = 256; // bits

void naive_hash_function(unsigned char *input_1, unsigned char *input_2, unsigned char *output) {
    for (int i = 0; i < HASH_SIZE / 8; ++i) {
        output[i] = input_1[i] ^ input_2[i];
    }
}
*/

// based on description in this paper:
// https://www.alonrosen.net/PAPERS/lattices/swifft.pdf
namespace swifft{

    const int SWIFFT_M = 16;
    const int SWIFFT_N = 64;
    const int SWIFFT_P = 257;

    const int SWIFFT_INPUT_SIZE = 1024;
    const int SWIFFT_OUTPUT_SIZE = 512;

    const int SWIFFT_ROOT_OF_UNITY = 42;
    unsigned *powers;
    unsigned **coef;

    void init_swifft() {
        powers = new unsigned[2 * SWIFFT_N];
        coef = new unsigned*[SWIFFT_M];
        for (int i = 0; i < SWIFFT_M; ++i) {
            coef[i] = new unsigned[SWIFFT_N];
            for (int j = 0; j < SWIFFT_N; ++j) {
                coef[i][j] = rand() % SWIFFT_P;
            }
        }

        powers[0] = 1;
        for (int i = 1; i < 2 * SWIFFT_N; ++i) {
            powers[i] = powers[i - 1] * SWIFFT_ROOT_OF_UNITY % SWIFFT_P;
        }
    }

    void _naive_dft(unsigned *input_field, unsigned *output_field) {

        for (int i = 0; i < SWIFFT_N; ++i) {
            unsigned sum = 0;
            for (int j = 0; j < SWIFFT_N; ++j) {
                unsigned power = j * (2 * i + 1);
                sum += input_field[j] * powers[power % (2 * SWIFFT_N)];
            }
            output_field[i] = sum;
        }
    }

    void hash(unsigned *input_bits, unsigned *output_bits, unsigned *linear_combination_result) {

        unsigned *dft_result = new unsigned[SWIFFT_INPUT_SIZE];

        // dft
        for (int i = 0; i < SWIFFT_M; ++i) {
            _naive_dft(input_bits + i * SWIFFT_N, dft_result + i * SWIFFT_N);
        }

        // linear combination
        for (int j = 0; j < SWIFFT_N; ++j) {
            unsigned sum = 0;
            for (int i = 0; i < SWIFFT_M; ++i) {
                sum += dft_result[i * SWIFFT_N + j] * coef[i][j];
            }
            linear_combination_result[j] = sum;
        }

        // use the least significant bits as output
        for (int j = 0; j < SWIFFT_N; ++j) {
            for (int i = 0; i < 8; ++i) {
                output_bits[j * 8 + i] = ((linear_combination_result[j] % 257) >> (7 - i) ) & 1U ;
            }
        }

        delete [] dft_result;

    }


};

#endif //ZKDT_HHASH_H
