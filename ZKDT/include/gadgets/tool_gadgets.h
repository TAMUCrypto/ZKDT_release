//
// Created by zhiyong on 4/14/20.
//

#ifndef ZKDT_TOOL_GADGETS_H
#define ZKDT_TOOL_GADGETS_H

#include "gadgets/common.h"
#include <cmath>

template<typename FieldT>
class AssignTestGadget : public gadget<FieldT> {
private:
    pb_variable <FieldT> x, a, b, c, d;
public:
    AssignTestGadget(protoboard <FieldT> &pb, const std::string &annotation = "") : gadget<FieldT>(pb, annotation) {
        a.allocate(pb, annotation + "a");
        b.allocate(pb, annotation + "b");
        c.allocate(pb, annotation + "c");
        d.allocate(pb, annotation + "d");
    }

    void generate_r1cs_constraints() {
        x = a;
        add_r1cs(x, 1, 1);

        x = b;
        add_r1cs(x, 1, 2);

        x = c;
        add_r1cs(x, 1, 3);

        x = d;
        add_r1cs(x, 1, 4);
    }

    void generate_r1cs_witness() {
        eval(a) = 1;
        eval(b) = 2;
        eval(c) = 3;
        eval(d) = 4;
    }

};

template<typename FieldT>
class PermutationGadget : public gadget<FieldT> {
private:
    pb_variable <FieldT> *original_values, *permuted_values;
    pb_variable <FieldT> *cumulated_prod_original, *cumulated_prod_permuted; // helper variable to calculate the product.
    const pb_variable <FieldT> &challenge_point;

    int size;
public:

    PermutationGadget(protoboard <FieldT> &pb, pb_variable <FieldT> *original_values_,
                      pb_variable <FieldT> *permuted_values_, const pb_variable <FieldT> &challenge_point_, int size_,
                      const std::string &annotation = "")
            : gadget<FieldT>(pb, annotation), challenge_point(challenge_point_) {
        original_values = original_values_;
        permuted_values = permuted_values_;
        size = size_;

        _init_pb_array(pb, cumulated_prod_original, size - 1, annotation + std::string("/cumulated_prod_original"));
        _init_pb_array(pb, cumulated_prod_permuted, size - 1, annotation + std::string("/cumulated_prod_permuted"));
    }

    ~PermutationGadget() {
        delete[] cumulated_prod_original;
        delete[] cumulated_prod_permuted;
    }

    void generate_r1cs_constraints() {
        add_r1cs(original_values[0] - challenge_point, original_values[1] - challenge_point,
                 cumulated_prod_original[0]);
        add_r1cs(permuted_values[0] - challenge_point, permuted_values[1] - challenge_point,
                 cumulated_prod_permuted[0]);
        for (int i = 1; i < size - 1; ++i) {
            auto &z = cumulated_prod_original[i];
            auto &x = cumulated_prod_original[i - 1];
            auto &&y = original_values[i + 1] - challenge_point;
            auto &zz = cumulated_prod_permuted[i];
            auto &xx = cumulated_prod_permuted[i - 1];
            auto &&yy = permuted_values[i + 1] - challenge_point;
            add_r1cs(x, y, z);
            add_r1cs(xx, yy, zz);
        }

        add_r1cs(cumulated_prod_original[size - 2], 1, cumulated_prod_permuted[size - 2]);
    }

    void generate_r1cs_witness() {
        eval(cumulated_prod_original[0]) =
                (eval(original_values[0]) - eval(challenge_point)) * (eval(original_values[1]) - eval(challenge_point));
        eval(cumulated_prod_permuted[0]) =
                (eval(permuted_values[0]) - eval(challenge_point)) * (eval(permuted_values[1]) - eval(challenge_point));

        for (int i = 1; i < size - 1; ++i) {
            eval(cumulated_prod_original[i]) = eval(cumulated_prod_original[i - 1])
                                               * (eval(original_values[i + 1]) - eval(challenge_point));
            eval(cumulated_prod_permuted[i]) = eval(cumulated_prod_permuted[i - 1])
                                               * (eval(permuted_values[i + 1]) - eval(challenge_point));
        }
    }
};

// check <a_1, a_2> <b_1, b_2> is permutation of each other
template<typename FieldT>
class PairwisePermutationGadget : public gadget<FieldT> {
private:
    int size;
    const pb_variable <FieldT> &coef, &challenge_point;
    pb_variable <FieldT> *a_1, *a_2, *b_1, *b_2;

    pb_variable <FieldT> *a_combine, *b_combine;
    PermutationGadget<FieldT> *permutationGadget;
public:
    PairwisePermutationGadget(protoboard <FieldT> &pb, pb_variable <FieldT> *a_1_, pb_variable <FieldT> *a_2_,
                              pb_variable <FieldT> *b_1_, pb_variable <FieldT> *b_2_, const pb_variable <FieldT> &coef_,
                              const pb_variable <FieldT> &challenge_point_, int size_,
                              const std::string &annotation = "")
            : gadget<FieldT>(pb, annotation), coef(coef_), challenge_point(challenge_point_) {
        size = size_;
        a_1 = a_1_;
        a_2 = a_2_;
        b_1 = b_1_;
        b_2 = b_2_;
        _init_pb_array(pb, a_combine, size, annotation + std::string("/a_combine"));
        _init_pb_array(pb, b_combine, size, annotation + std::string("/b_combine"));
        permutationGadget = new PermutationGadget<FieldT>(pb, a_combine, b_combine, challenge_point_, size_,
                                                          annotation + std::string("/permutation_gadget"));
    }

    ~PairwisePermutationGadget() {
        delete[] a_combine;
        delete[] b_combine;
        delete permutationGadget;
    }

    void generate_r1cs_constraints() {
        for (int i = 0; i < size; ++i) {
            add_r1cs(coef, a_1[i], a_combine[i] - a_2[i]);
            add_r1cs(coef, b_1[i], b_combine[i] - b_2[i]);
        }
        permutationGadget->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        auto &x = eval(coef);
        for (int i = 0; i < size; ++i) {
            eval(a_combine[i]) = eval(a_1[i]) * x + eval(a_2[i]);
            eval(b_combine[i]) = eval(b_1[i]) * x + eval(b_2[i]);
        }
        permutationGadget->generate_r1cs_witness();
    }
};


// assume frequency bits are in big-endian
template<typename FieldT>
class MultiSetGadget : public gadget<FieldT> {
private:
    pb_variable <FieldT> *original_vars, *multiset_vars, *frequency_in_bits;
    unsigned n_original, n_multiset, n_frequency_bits;
    const pb_variable <FieldT> &challenge_point;

    pb_variable <FieldT> *var_powers, *var_power_filtered;
    pb_variable <FieldT> *cumulated_product_original, *cumulated_product_multiset;
public:
    MultiSetGadget(protoboard <FieldT> &pb, pb_variable <FieldT> *original_vars_, pb_variable <FieldT> *multiset_vars_,
                   pb_variable <FieldT> *frequency_in_bits_, unsigned n_original_, unsigned n_multiset_,
                   unsigned n_frequency_bits_,
                   const pb_variable <FieldT> &challenge_point_, const std::string &annotation = "") : gadget<FieldT>(
            pb, annotation), challenge_point(challenge_point_) {
        assert(n_original_ >= 2);

        original_vars = original_vars_;
        multiset_vars = multiset_vars_;
        n_frequency_bits = n_frequency_bits_;
        n_original = n_original_;
        n_multiset = n_multiset_;
        frequency_in_bits = frequency_in_bits_;

        _init_pb_array(pb, var_powers, n_original * n_frequency_bits, annotation + std::string("var_powers"));
        _init_pb_array(pb, var_power_filtered, n_original * n_frequency_bits,
                       annotation + std::string("var_power_filtered"));
        _init_pb_array(pb, cumulated_product_original, n_original * n_frequency_bits - 1,
                       annotation + std::string("cumulated_product_original"));
        _init_pb_array(pb, cumulated_product_multiset, n_multiset - 1,
                       annotation + std::string("cumulated_product_multiset"));
    }

    ~MultiSetGadget() {
        delete[] var_powers;
        delete[] var_power_filtered;
        delete[] cumulated_product_original;
        delete[] cumulated_product_multiset;
    }

    void generate_r1cs_constraints() {

        // big-endian powers, ...(x - c)^4, (x - c)^2, x - c
        for (int i = 0; i < n_original; ++i) {
            int base_index = i * n_frequency_bits + n_frequency_bits - 1;
            add_r1cs(original_vars[i] - challenge_point, 1, var_powers[base_index]);
            for (int j = 1; j < n_frequency_bits; ++j) {
                auto &y = var_powers[base_index - j];
                auto &x = var_powers[base_index - j + 1];
                add_r1cs(x, x, y);
            }
        }

        // if b = 0: var_filtered = 1 else var_filtered = var_powers
        for (int i = 0; i < n_original * n_frequency_bits; ++i) {
            auto &b = frequency_in_bits[i];
            add_r1cs(b, var_powers[i], var_power_filtered[i] - 1 + b);
        }

        // evaluation of original characteristic polynomial at challenge point
        add_r1cs(var_power_filtered[0], var_power_filtered[1], cumulated_product_original[0]);
        for (int i = 1; i < n_original * n_frequency_bits - 1; ++i) {
            add_r1cs(cumulated_product_original[i - 1], var_power_filtered[i + 1], cumulated_product_original[i]);
        }

        // evaluation of multiset characteristic polynomial at challenge point
        if (n_multiset > 1) {
            add_r1cs(multiset_vars[0] - challenge_point, multiset_vars[1] - challenge_point,
                     cumulated_product_multiset[0]);
            for (int i = 1; i < n_multiset - 1; ++i) {
                add_r1cs(cumulated_product_multiset[i - 1], multiset_vars[i + 1] - challenge_point,
                         cumulated_product_multiset[i]);

            }

            add_r1cs(cumulated_product_original[n_original * n_frequency_bits - 2], 1,
                     cumulated_product_multiset[n_multiset - 2]);
        } else {
            add_r1cs(multiset_vars[0] - challenge_point, 1,
                     cumulated_product_original[n_original * n_frequency_bits - 2]);
        }
    }

    void generate_r1cs_witness() {
        for (int i = 0; i < n_original; ++i) {
            int base_index = i * n_frequency_bits + n_frequency_bits - 1;
            eval(var_powers[base_index]) = eval(original_vars[i]) - eval(challenge_point);
            for (int j = 1; j < n_frequency_bits; ++j) {
                auto &y = eval(var_powers[base_index - j]);
                auto &x = eval(var_powers[base_index - j + 1]);
                y = x * x;
            }
        }

        for (int i = 0; i < n_original * n_frequency_bits; ++i) {
            auto &b = eval(frequency_in_bits[i]);
            eval(var_power_filtered[i]) = FieldT(1) - b + b * eval(var_powers[i]);
        }

        // evaluation of original characteristic polynomial at challenge point
        eval(cumulated_product_original[0]) = eval(var_power_filtered[0]) * eval(var_power_filtered[1]);
        for (int i = 1; i < n_original * n_frequency_bits - 1; ++i) {
            eval(cumulated_product_original[i]) =
                    eval(cumulated_product_original[i - 1]) * eval(var_power_filtered[i + 1]);
        }

        // evaluation of multiset characteristic polynomial at challenge point
        if (n_multiset > 1) {
            eval(cumulated_product_multiset[0]) =
                    (eval(multiset_vars[0]) - eval(challenge_point)) * (eval(multiset_vars[1]) - eval(challenge_point));
            for (int i = 1; i < n_multiset - 1; ++i) {
                eval(cumulated_product_multiset[i]) =
                        eval(cumulated_product_multiset[i - 1]) * (eval(multiset_vars[i + 1]) - eval(challenge_point));

            }
        }
    }
};

template<typename FieldT>
class PairwiseMultiSetGadget : public gadget<FieldT> {
private:
    unsigned n_original, n_multiset;
    const pb_variable <FieldT> &coef, &challenge_point;
    pb_variable <FieldT> *a_1, *a_2, *b_1, *b_2;

    pb_variable <FieldT> *a_combine, *b_combine;
    MultiSetGadget<FieldT> *multiSetGadget;
public:
    PairwiseMultiSetGadget(protoboard <FieldT> &pb, pb_variable <FieldT> *a_1_, pb_variable <FieldT> *a_2_,
                           pb_variable <FieldT> *b_1_, pb_variable <FieldT> *b_2_,
                           pb_variable <FieldT> *frequency_in_bits, const pb_variable <FieldT> &coef_,
                           const pb_variable <FieldT> &challenge_point_, unsigned n_original_, unsigned n_multiset_,
                           unsigned n_frequency_in_bits, const std::string &annotation = "")
            : gadget<FieldT>(pb, annotation), coef(coef_), challenge_point(challenge_point_) {
        n_original = n_original_;
        n_multiset = n_multiset_;
        a_1 = a_1_;
        a_2 = a_2_;
        b_1 = b_1_;
        b_2 = b_2_;
        _init_pb_array(pb, a_combine, n_original, annotation + std::string("/a_combine"));
        _init_pb_array(pb, b_combine, n_multiset, annotation + std::string("/b_combine"));
        multiSetGadget = new MultiSetGadget<FieldT>(pb, a_combine, b_combine, frequency_in_bits, n_original, n_multiset,
                                                    n_frequency_in_bits, challenge_point,
                                                    annotation + "multiset_gadget");
    }

    ~PairwiseMultiSetGadget() {
        delete[] a_combine;
        delete[] b_combine;
        delete multiSetGadget;
    }

    void generate_r1cs_constraints() {

        // combined = coef * a_1 + a_2
        for (int i = 0; i < n_original; ++i) {
            add_r1cs(coef, a_1[i], a_combine[i] - a_2[i]);
        }

        for (int i = 0; i < n_multiset; ++i) {
            add_r1cs(coef, b_1[i], b_combine[i] - b_2[i]);
        }

        multiSetGadget->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        auto &x = eval(coef);

        for (int i = 0; i < n_original; ++i) {
            eval(a_combine[i]) = eval(a_1[i]) * x + eval(a_2[i]);
        }

        for (int i = 0; i < n_multiset; ++i) {
            eval(b_combine[i]) = eval(b_1[i]) * x + eval(b_2[i]);
        }

        multiSetGadget->generate_r1cs_witness();
    }
};

// 1 if x <= y, -1 otherwise, assume bit_decomposition[0] is the big-endian
// assuming bit decomposition check of 32 bits of x, y,
// and their difference are already checked outside the scope
template<typename FieldT>
class ComparisonGadget : public gadget<FieldT> {
public:
    const pb_variable <FieldT> &comparison_result;
    const pb_variable <FieldT> &diff;
    const pb_variable <FieldT> &x, &y;

    ComparisonGadget(protoboard <FieldT> &pb, pb_variable <FieldT> &x_, pb_variable <FieldT> &y_,
                     pb_variable <FieldT> &comparison_result_, pb_variable <FieldT> &diff_,
                     const std::string &annotation = "")
            : gadget<FieldT>(pb, annotation), x(x_), y(y_), comparison_result(comparison_result_), diff(diff_) {
    }

    ~ComparisonGadget() {}

    void generate_r1cs_constraints() {
        add_r1cs(2 * comparison_result - 1, y - x, diff);
    }

    void generate_r1cs_witness() {}

};

// a naive xor hash to hash 2n bits into n bits
template<typename FieldT>
class NaiveHashGadget : public gadget<FieldT> {
private:
    pb_variable <FieldT> *input, *output;
    int n_bits;
public:
    NaiveHashGadget(protoboard <FieldT> &pb, pb_variable <FieldT> *input_, pb_variable <FieldT> *output_, int n_bits_,
                    const std::string &annotation = "") : gadget<FieldT>(pb, annotation) {
        n_bits = n_bits_;
        input = input_;
        output = output_;
    }

    void generate_r1cs_constraints() {
        for (int i = 0; i < n_bits; ++i) {
            auto &x = input[i], &y = input[i + n_bits], &z = output[i];
            add_r1cs(x - y, x - y, z); // z = x ^ y
        }
    }

    void generate_r1cs_witness() {
        // there is nothing to do here.
        return;
    }
};

// assume big-endian
template<typename FieldT>
class DecompositionCheckGadget : public gadget<FieldT> {
private:
    pb_variable <FieldT> *vars, *decompositions;
    int n_vars, n_bit_per_var;
public:
    DecompositionCheckGadget(protoboard <FieldT> &pb, pb_variable <FieldT> *vars_,
                             pb_variable <FieldT> *decompositions_,
                             int n_vars_, int n_bit_per_var_, const std::string &annotation = "")
            : gadget<FieldT>(pb, annotation) {
        vars = vars_;
        decompositions = decompositions_;
        n_vars = n_vars_;
        n_bit_per_var = n_bit_per_var_;
    }

    void generate_r1cs_constraints() {
        // check summation
        for (int i = 0; i < n_vars; ++i) {
            int base = i * n_bit_per_var;
            auto sum = linear_combination<FieldT>(decompositions[base + n_bit_per_var - 1]);
            for (int j = n_bit_per_var - 2; j >= 0; --j) {
                sum = sum + decompositions[base + j] * FieldT(1ULL << (n_bit_per_var - j - 1));
            }
            add_r1cs(sum, 1, vars[i]);
        }

        // check 0 or 1
        for (int i = 0; i < n_vars * n_bit_per_var; ++i) {
            add_r1cs(decompositions[i], 1 - decompositions[i], 0);
        }
    }

    void generate_r1cs_witness() {
        // nothing to do here assuming decomposition is calculated outside, maybe it's better to put it here
        return;
    }
};


template<typename FieldT>
class ArgmaxGadget : public gadget<FieldT> {
private:
    int n_bits_per_number;
    int n_vars;
    pb_variable <FieldT> *values;
    pb_variable <FieldT> *max_index; // one-hot

    pb_variable <FieldT> max_value;
    pb_variable <FieldT> *max_value_decompositions;
    pb_variable <FieldT> *values_times_index;
    pb_variable <FieldT> *value_decompositions;

    pb_variable <FieldT> *place_holder;

    DecompositionCheckGadget<FieldT> *decompositionCheckGadget;
    DecompositionCheckGadget<FieldT> *decompositionCheckGadget1;

public:
    ArgmaxGadget(protoboard <FieldT> &pb, pb_variable <FieldT> *values_, pb_variable <FieldT> *max_index_,
                 int n_vars_, const std::string &annotation = "")
            : gadget<FieldT>(pb, annotation) {
        n_vars = n_vars_;
        values = values_;
        max_index = max_index_;
        n_bits_per_number = log(n_vars) + 1;

        _init_pb_array(pb, value_decompositions, n_vars * n_bits_per_number,
                       annotation + std::string("value_decompositions"));
        _init_pb_array(pb, values_times_index, n_vars, annotation + std::string("values_times_index"));

        max_value.allocate(pb, annotation + std::string("max_value"));
        _init_pb_array(pb, max_value_decompositions, n_bits_per_number, std::string("max_value_decompositions"));

        _init_pb_array(pb, place_holder, n_vars * n_bits_per_number * 2, std::string("placeholder"));

        decompositionCheckGadget = new DecompositionCheckGadget<FieldT>(pb, values_, value_decompositions, n_vars,
                                                                        n_bits_per_number,
                                                                        annotation + std::string("argmax_gadget"));
        decompositionCheckGadget1 = new DecompositionCheckGadget<FieldT>(pb, &max_value, max_value_decompositions, 1,
                                                                         n_bits_per_number,
                                                                         annotation + std::string("argmax_gadget1"));
    }

    void generate_r1cs_constraints() {
        decompositionCheckGadget->generate_r1cs_constraints();
        decompositionCheckGadget1->generate_r1cs_constraints();

        auto sum = linear_combination<FieldT>();
        for (int i = 0; i < n_vars; ++i) {
            add_r1cs(max_index[i], 1 - max_index[i], 0);
            sum = sum + max_index[i];
        }
        add_r1cs(sum, 1, 1);

        sum = linear_combination<FieldT>();
        for (int i = 0; i < n_vars; ++i) {
            add_r1cs(values[i], max_index[i], values_times_index[i]);
            sum = sum + values_times_index[i];
        }
        add_r1cs(max_value, 1, sum);

        // check less than or equal
        for (int i = 0; i < n_vars; ++i) {
            // less than or equal(values[i], max_value);
            for (int j = 0; j < n_bits_per_number; ++j) {
                auto &x = place_holder[i * n_bits_per_number + j], &y = place_holder[(i + n_vars) * n_bits_per_number +
                                                                                     j];
                add_r1cs(x, 1, x); // placeholder
                add_r1cs(y, 1, y);
            }
        }

    }

    void generate_r1cs_witness() {
        decompositionCheckGadget->generate_r1cs_witness();
        decompositionCheckGadget1->generate_r1cs_witness();
        return;
    }
};


template<typename FieldT>
class MajorityGadget : public gadget<FieldT> {
private:
    int n_vars;
    pb_variable <FieldT> *values, value_majority;

    pb_variable <FieldT> *equal; // equal[i][j] = 1 iff values[i] == values[j]
    pb_variable <FieldT> *counts; // counts how many times a class appear
    pb_variable <FieldT> *max_index; // one-hot representation of the position of the max count

    ArgmaxGadget<FieldT> *argmaxGadget;

public:
    MajorityGadget(protoboard <FieldT> &pb, pb_variable <FieldT> *values_, pb_variable <FieldT> value_majority_,
                   int n_vars_, const std::string &annotation = "")
            : gadget<FieldT>(pb, annotation) {
        n_vars = n_vars_;
        values = values_;
        value_majority = value_majority_;

        _init_pb_array(pb, counts, n_vars, annotation + std::string("counts"));
        _init_pb_array(pb, max_index, n_vars, annotation + std::string("max_index"));
        _init_pb_array(pb, equal, n_vars * n_vars / 2, annotation + std::string("equal"));

        argmaxGadget = new ArgmaxGadget<FieldT>(pb, values, max_index, n_vars,
                                                annotation + std::string("argmaxGadget"));
    }

    void generate_r1cs_constraints() {
        for (int i = 0; i < n_vars; ++i) {
            auto sum = linear_combination<FieldT>();
            for (int j = 0; j < n_vars; ++j) {
                if (i < j) {
                    add_r1cs(equal[j], values[i] - values[j], 0);
                }
                sum = sum + equal[j];
            }
            add_r1cs(counts[i], 1, sum);
        }

        argmaxGadget->generate_r1cs_constraints();

    }

    void generate_r1cs_witness() {
        // nothing to do here
        return;
    }

};

template<typename FieldT>
class LinearCombinationGadget : public gadget<FieldT> {
private:
    int n_terms;
    pb_variable <FieldT> *terms;
    pb_variable <FieldT> *values, *coef;
    pb_variable <FieldT> &result;
public:
    LinearCombinationGadget(protoboard <FieldT> &pb, pb_variable <FieldT> *values_, pb_variable <FieldT> *coef_,
                            pb_variable <FieldT> &result_,
                            int n_terms_, const std::string &annotation = "")
            : gadget<FieldT>(pb, annotation), result(result_) {
        n_terms = n_terms_;
        values = values_;
        coef = coef_;
        _init_pb_array(this->pb, terms, n_terms, annotation + "terms");
    }

    void generate_r1cs_constraints() {
        for (int i = 0; i < n_terms; ++i) {
            add_r1cs(values[i], coef[i], terms[i]);
        }
        auto sum = linear_combination<FieldT>();
        for (int i = 0; i < n_terms; ++i) {
            sum = sum + terms[i];
        }
        add_r1cs(sum, 1, result);
    }

    void generate_r1cs_witness() {
        for (int i = 0; i < n_terms; ++i) {
            eval(terms[i]) = eval(values[i]) * eval(coef[i]);
        }

        FieldT sum = FieldT::zero();
        for (int i = 0; i < n_terms; ++i) {
            sum = sum + eval(terms[i]);
        }
        eval(result) = sum;
    }
};

template<typename FieldT>
class EqualityCheckGadget : public gadget<FieldT> {
private:
    int n_bits;
    pb_variable <FieldT> &x, &y, &result;
    pb_variable <FieldT> *x_dec, *y_dec; // bit decomposition
    pb_variable <FieldT> *bit_equal; // equality check of each bit
    pb_variable <FieldT> *aggr_equal; // aggregate the result from bit equal

    DecompositionCheckGadget<FieldT> *decompositionCheckGadgets;

public:
    EqualityCheckGadget(protoboard <FieldT> &pb, pb_variable <FieldT> &x_, pb_variable <FieldT> &y_,
                        pb_variable <FieldT> &result_,
                        int n_bits_ = 32, const std::string &annotation = "") :
            gadget<FieldT>(pb, annotation), n_bits(n_bits_), x(x_), y(y_), result(result_) {

        decompositionCheckGadgets = (DecompositionCheckGadget<FieldT> *) malloc(sizeof(DecompositionCheckGadget<FieldT>) * 2);

        _init_pb_array(this->pb, x_dec, n_bits, annotation + "x_dec");
        _init_pb_array(this->pb, y_dec, n_bits, annotation + "y_dec");
        _init_pb_array(this->pb, bit_equal, n_bits, annotation + "bit_equal");
        _init_pb_array(this->pb, aggr_equal, n_bits - 1, annotation + "aggr_equal");

        new(decompositionCheckGadgets + 0) DecompositionCheckGadget<FieldT>(pb, &x, x_dec, 1, n_bits, annotation + "decompositionCheckGadgets0");
        new(decompositionCheckGadgets + 1) DecompositionCheckGadget<FieldT>(pb, &y, y_dec, 1, n_bits, annotation + "decompositionCheckGadgets1");
    }

    void generate_r1cs_constraints() {
        decompositionCheckGadgets[0].generate_r1cs_constraints();
        decompositionCheckGadgets[1].generate_r1cs_constraints();
        for (int i = 0; i < n_bits; ++i) {
            add_r1cs(2 * x_dec[i], y_dec[i], x_dec[i] + y_dec[i] + bit_equal[i] - 1); // z_i = x_i == y_i
        }
        add_r1cs(bit_equal[0], bit_equal[1], aggr_equal[0]);
        for (int i = 1; i < n_bits - 1; ++i) {
            add_r1cs(aggr_equal[i - 1], bit_equal[i + 1], aggr_equal[i]);
        }
        add_r1cs(aggr_equal[n_bits - 2], 1, result);
    }

    void generate_r1cs_witness(unsigned x, unsigned y) {
        for (int i = 0; i < n_bits; ++i) {
            eval(x_dec[i]) = (x >> (n_bits - 1 - i)) & 1U;
            eval(y_dec[i]) = (y >> (n_bits - 1 - i)) & 1U;
            eval(bit_equal[i]) = eval(x_dec[i]) == eval(y_dec[i]);
        }
        eval(aggr_equal[0]) = eval(bit_equal[0]) * eval(bit_equal[1]);
        for (int i = 1; i < n_bits - 1; ++i) {
            eval(aggr_equal[i]) = eval(aggr_equal[i - 1]) * eval(bit_equal[i + 1]);
        }
    }

    ~EqualityCheckGadget() {

    }
};

#endif //ZKDT_TOOL_GADGETS_H
