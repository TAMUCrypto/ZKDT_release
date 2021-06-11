//
// Created by zhiyong on 4/14/20.
//

#ifndef ZKDT_SWIFFT_H
#define ZKDT_SWIFFT_H

#include "gadgets/common.h"
#include "hash.h"

using namespace libsnark;



template<typename FieldT>
class SwifftGadget : public gadget<FieldT> {
public:
    const int max_quotient_bits = 22; // ensure non-overflow of the large group

    pb_variable <FieldT> *input, *output;

    linear_combination <FieldT> *dft_result, *linear_combination_result;
    pb_variable <FieldT> *quotient, *remainder;

    pb_variable <FieldT> *quotient_bits;
    pb_variable <FieldT> *carry_bits;

public:

    SwifftGadget(protoboard <FieldT> &pb, pb_variable <FieldT> *input_, pb_variable <FieldT> *output_,
                 const std::string &annotation = "")
            : gadget<FieldT>(pb, annotation) {
        input = input_;
        output = output_;
        _init_pb_array(pb, quotient, swifft::SWIFFT_N, annotation + std::string("/quotient"));
        _init_pb_array(pb, remainder, swifft::SWIFFT_N, annotation + std::string("/remainder"));
        _init_pb_array(pb, carry_bits, swifft::SWIFFT_N, annotation + std::string("/carry_bits"));
        _init_pb_array(pb, quotient_bits, swifft::SWIFFT_N * max_quotient_bits, annotation + std::string("/quotient_bits"));
        dft_result = new linear_combination<FieldT>[swifft::SWIFFT_INPUT_SIZE];
        linear_combination_result = new linear_combination<FieldT>[swifft::SWIFFT_N];
    }

    ~SwifftGadget() {
        delete[] dft_result;
        delete[] linear_combination_result;
        delete[] quotient;
        delete[] remainder;
        delete[] carry_bits;
        delete[] quotient_bits;
    }

    void generate_r1cs_constraints() {
        // dft
        for (int i = 0; i < swifft::SWIFFT_M; ++i) {
            for (int j = 0; j < swifft::SWIFFT_N; ++j) {
                for (int k = 0; k < swifft::SWIFFT_N; ++k) {
                    dft_result[i * swifft::SWIFFT_N + j] = dft_result[i * swifft::SWIFFT_N + j] +
                                                           input[i * swifft::SWIFFT_N + k] *
                                                           swifft::powers[(2 * j + 1) * k % (2 * swifft::SWIFFT_N)];
                }
            }
        }

        // linear combination
        for (int j = 0; j < swifft::SWIFFT_N; ++j) {
            for (int i = 0; i < swifft::SWIFFT_M; ++i) {
                linear_combination_result[j] = linear_combination_result[j] + dft_result[i * swifft::SWIFFT_N + j] * swifft::coef[i][j];
            }
        }

        // modular
        for (int j = 0; j < swifft::SWIFFT_N; ++j) {
            // this only results in 64 constraints out of 2000+, do this check later
            add_r1cs(quotient[j], swifft::SWIFFT_P, linear_combination_result[j] - remainder[j]);
            // reminder should be less than p
        }

        // bit decomposition of remainder
        for (int i = 0; i < swifft::SWIFFT_N; ++i) {
            auto sum = linear_combination<FieldT>();
            for (int j = 0; j < 8; ++j) {
                auto &x = output[i * 8 + j];
                sum = sum + x * (1U << (7 - j));

            }
            sum = sum + carry_bits[i] * (1U << 8);
            add_r1cs(sum, 1, remainder[i]);
        }

        //carry_bits is 0 or 1
        for (int i = 0; i < swifft::SWIFFT_N; ++i) {
            add_r1cs(carry_bits[i], (1 - carry_bits[i]), 0);
        }

        // bit decomposition of quotient
        for (int i = 0; i < swifft::SWIFFT_N; ++i) {
            auto sum = linear_combination<FieldT>();
            for (int j = 0; j < max_quotient_bits; ++j) {
                auto &x = quotient_bits[i * max_quotient_bits + j];
                sum = sum + x * (1U << (max_quotient_bits - 1 - j));
                add_r1cs(x, (1 - x), 0);
            }
            add_r1cs(sum, 1, quotient[i]);
        }

    }

    void generate_r1cs_witness(unsigned *linear_combination_result) {
        for (int i = 0; i < swifft::SWIFFT_N; ++i) {
            unsigned q = linear_combination_result[i] / swifft::SWIFFT_P;
            unsigned r = linear_combination_result[i] % swifft::SWIFFT_P;
            eval(quotient[i]) = q;
            eval(remainder[i]) = r;
            for (int j = 0; j < max_quotient_bits; ++j) {
                eval(quotient_bits[i * max_quotient_bits + j]) = (q >> (max_quotient_bits - 1 - j)) & 1U;
            }

            eval(carry_bits[i]) = r == swifft::SWIFFT_P - 1;
        }
    }
};


#endif //ZKDT_SWIFFT_H
