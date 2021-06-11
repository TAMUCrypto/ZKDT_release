//
// Created by zhiyong on 3/12/20.
//

#ifndef ZKDT_GADGET_H
#define ZKDT_GADGET_H

#include <libsnark/gadgetlib1/gadget.hpp>
#include <cstring>
#include <iostream>
#include <algorithm>
#include <cmath>

#include "DT/DT.h"
#include "gadgets/swifft.h"
#include "gadgets/common.h"
#include "gadgets/tool_gadgets.h"
#include <vector>

using namespace libsnark;

#define add_r1cs(x, y, z) this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x, y, z))
#define eval(x) this->pb.val(x)


template<typename FieldT>
class DTPathGadget : public gadget<FieldT> {

private:

    pb_variable <FieldT> zero_var;

    // public input
    pb_variable <FieldT> *raw_vars;
    pb_variable <FieldT> *raw_index;
    pb_variable <FieldT> coef, challenge_point, target_class_label;
    pb_variable <FieldT> *commitment_in_bits;

    // extended witness: permutation
    pb_variable <FieldT> *permuted_vars;
    pb_variable <FieldT> *permuted_index;

    // secret: v1, v2, ... vh
    pb_variable <FieldT> *node_id;
    pb_variable <FieldT> *variable_id;
    pb_variable <FieldT> *threshold;
    pb_variable <FieldT> *l_node_id;
    pb_variable <FieldT> *r_node_id;
    pb_variable <FieldT> class_label;

    //extended witness: bit decompositions
    pb_variable <FieldT> *permuted_vars_decomposition;

    pb_variable <FieldT> *node_id_decomposition;
    pb_variable <FieldT> *variable_id_decomposition;
    pb_variable <FieldT> *threshold_decomposition;
    pb_variable <FieldT> *l_node_id_decomposition;
    pb_variable <FieldT> *r_node_id_decomposition;

    pb_variable <FieldT> *class_label_decomposition;

    // helper variables
    //PairwisePermutationGadget<FieldT> *pairwisePermutationGadget;
    PairwiseMultiSetGadget <FieldT> *pairwiseMultiSetGadget;
    pb_variable <FieldT> *frequency_in_bits;

    ComparisonGadget <FieldT> *comparisonGadgets;
    pb_variable <FieldT> *comparison_results;
    pb_variable <FieldT> *diff;
    pb_variable <FieldT> *diff_decomposition;

    // every layer has 2 hashes, the first hashes two children hashes,
    // the second hashes the first hash output and information in current node
    SwifftGadget <FieldT> *swifftGadget;
    pb_variable <FieldT> *siblings;
    pb_variable <FieldT> *hash_outputs_1;
    pb_variable <FieldT> *hash_outputs_2;

    // these are not allocated in pb, they will be assigned other variables before use
    pb_variable <FieldT> *hash_inputs_1;
    pb_variable <FieldT> *hash_inputs_2;

    // decomposition used for hashes
    DecompositionCheckGadget <FieldT> *decompositionCheckGadgets;

    void _init_pb_vars() {
        auto &prefix = this->annotation_prefix;

        zero_var.allocate(this->pb, prefix + std::string("zero_var"));

        // raw_vars, raw_index, coef, challenge_point, commitment_in_bits
        _init_pb_array(this->pb, raw_vars, n_vars, prefix + std::string("raw_vars"));
        _init_pb_array(this->pb, raw_index, n_vars, prefix + std::string("raw_index"));
        coef.allocate(this->pb, prefix + std::string("coef"));
        challenge_point.allocate(this->pb, prefix + std::string("challenge_point"));
        _init_pb_array(this->pb, commitment_in_bits, _hash_output_size, prefix + std::string("commitment_in_bits"));

        // permuted_vars, permuted_index
        _init_pb_array(this->pb, permuted_vars, path_length - 1, prefix + std::string("permuted_vars"));
        _init_pb_array(this->pb, permuted_index, path_length - 1, prefix + std::string("permuted_index"));

        // node_id, threshold, l_node_id, r_node_id, class_label
        _init_pb_array(this->pb, node_id, path_length, prefix + std::string("node_id"));
        _init_pb_array(this->pb, variable_id, path_length - 1, prefix + std::string("variable_id"));
        _init_pb_array(this->pb, threshold, path_length - 1, prefix + std::string("threshold"));
        _init_pb_array(this->pb, l_node_id, path_length - 1, prefix + std::string("l_node_id"));
        _init_pb_array(this->pb, r_node_id, path_length - 1, prefix + std::string("r_node_id"));
        class_label.allocate(this->pb, prefix + std::string("class_label"));
        target_class_label.allocate(this->pb, prefix + std::string("target_class_label"));

        // permuted_vars_decomposition
        // node_id_decomposition, threshold_decomposition, l_node_id_decomposition, r_node_id_decomposition
        _init_pb_array(this->pb, permuted_vars_decomposition, (path_length - 1) * 32,
                       prefix + std::string("permuted_vars_decomposition"));
        _init_pb_array(this->pb, node_id_decomposition, path_length * 32,
                       prefix + std::string("node_id_decomposition"));
        _init_pb_array(this->pb, variable_id_decomposition, (path_length - 1) * 32,
                       prefix + std::string("variable_id_decomposition"));
        _init_pb_array(this->pb, threshold_decomposition, (path_length - 1) * 32,
                       prefix + std::string("threshold_decomposition"));
        _init_pb_array(this->pb, l_node_id_decomposition, (path_length - 1) * 32,
                       prefix + std::string("l_node_id_decomposition"));
        _init_pb_array(this->pb, r_node_id_decomposition, (path_length - 1) * 32,
                       prefix + std::string("r_node_id_decomposition"));
        _init_pb_array(this->pb, class_label_decomposition, 32, prefix + std::string("class_label_decomposition"));

        _init_pb_array(this->pb, frequency_in_bits, n_vars * _n_frequency_bits,
                       prefix + std::string("frequency_in_bits"));

        // comparison_results, hash_inputs, hash_outputs
        _init_pb_array(this->pb, comparison_results, path_length - 1, prefix + std::string("comparison_results"));
        _init_pb_array(this->pb, diff, path_length - 1, prefix + std::string("diff"));
        _init_pb_array(this->pb, diff_decomposition, (path_length - 1) * 32,
                       prefix + std::string("diff_decomposition"));
        _init_pb_array(this->pb, siblings, (path_length - 1) * _hash_output_size, prefix + std::string("siblings"));
        _init_pb_array(this->pb, hash_outputs_1, (path_length - 1) * _hash_output_size,
                       prefix + std::string("hash_outputs_1"));
        _init_pb_array(this->pb, hash_outputs_2, (path_length - 1) * _hash_output_size,
                       prefix + std::string("hash_outputs_2"));

        hash_inputs_1 = new pb_variable<FieldT>[(path_length - 1) * _hash_input_size];
        hash_inputs_2 = new pb_variable<FieldT>[(path_length - 1) * _hash_input_size];
    }

    void _decompose(unsigned value, pb_variable <FieldT> *bits) {
        for (int i = 0; i < 32; ++i) {
            eval(bits[i]) = (value >> (31 - i)) & 1U;
        }
    }

    void _multiset_generate_r1cs_constraints() {
        pairwiseMultiSetGadget->generate_r1cs_constraints();
    }

    void _multiset_generate_r1cs_witness() {
        for (int i = 0; i < path_length - 1; ++i) {
            unsigned _index = ((DTInternalNode *) path[i])->variable_id;
            eval(permuted_index[i]) = _index;
            eval(permuted_vars[i]) = values[_index];
            _decompose(values[_index], permuted_vars_decomposition + 32 * i);
        }

        for (int i = 0; i < n_vars; ++i) {
            for (int j = 0; j < _n_frequency_bits; ++j) {
                eval(frequency_in_bits[i * _n_frequency_bits + j]) =
                        (_variable_count[i] >> (_n_frequency_bits - j - 1)) & 1U;
            }
        }

        pairwiseMultiSetGadget->generate_r1cs_witness();
    }

    void _bit_decomposition_generate_r1cs_constraints() {
        for (int i = 0; i < 8; ++i) {
            decompositionCheckGadgets[i].generate_r1cs_constraints();
        }
    }

    void _bit_decomposition_generate_r1cs_witness() {
        for (int i = 0; i < 8; ++i) {
            decompositionCheckGadgets[i].generate_r1cs_witness();
        }
    }

    void _dt_prediction_generate_r1cs_constraints() {
        for (int i = 0; i < path_length - 1; ++i) {
            comparisonGadgets[i].generate_r1cs_constraints();
            add_r1cs(permuted_index[i], 1, variable_id[i]);
            add_r1cs(comparison_results[i], l_node_id[i] - r_node_id[i], node_id[i + 1] - r_node_id[i]);
            // 1 (v_{i+1}.node_id - v_{i}.l_node_id) + 0 (v_{i+1}.node_id - v_{i}.r_node_id) = 0;
        }
        add_r1cs(class_label, 1, target_class_label);
    }

    void _dt_prediction_generate_r1cs_witness() {
        for (int i = 0; i < path_length - 1; ++i) {
            eval(comparison_results[i]) = path[i + 1]->is_left();
            unsigned x = values[((DTInternalNode *)path[i])->variable_id], y = ((DTInternalNode *)path[i])->threshold;
            unsigned d = (x <= y) ? (y - x): (x - y);
            _decompose(d, diff_decomposition + 32 * i);
            eval(diff[i]) = d;
        }

        for (int i = 0; i < path_length - 1; ++i) {
            comparisonGadgets[i].generate_r1cs_witness();
        }
    }

    void _assign(pb_variable <FieldT> *a, pb_variable <FieldT> *b) {
        for (int i = 0; i < 32; ++i) {
           a[i] = b[i];
        }
    }

    void _zero_var_assign(pb_variable <FieldT> *a, int start = 0) {
        for (int i = start; i < _hash_output_size; ++i) {
            a[i] = zero_var;
        }
    }

    void _hash_generate_r1cs_constraints() {
        for (int i = 0; i < (path_length - 1) * _hash_output_size; ++i) {
            auto &x = siblings[i];
            add_r1cs(x, (1 - x), 0);
        }

        bool is_left = path[path_length - 1]->is_left();
        int base = is_left ? 0 : _hash_output_size;

        _zero_var_assign(hash_inputs_1 + base, 64);
        _assign(hash_inputs_1 + base, class_label_decomposition);
        _assign(hash_inputs_1 + base + 32, node_id_decomposition + 32 * (path_length - 1));

        for (int i = 0; i < path_length - 1; ++i) {
            is_left = path[path_length - 1 - i]->is_left();
            base = is_left ? 0 : _hash_output_size;

            if (i > 0) {
                for (int j = 0; j < _hash_output_size; ++j) {
                    hash_inputs_1[i * _hash_input_size + base + j] = hash_outputs_2[(i - 1) * _hash_output_size + j];
                }
            }

            // fill in sibling hashes
            for (int j = 0; j < _hash_output_size; ++j) {
                hash_inputs_1[i * _hash_input_size + _hash_output_size - base + j] = siblings[i * _hash_output_size +
                                                                                              j];
            }

            // fill in inputs for the second hash
            for (int j = 0; j < _hash_output_size; ++j) {
                hash_inputs_2[i * _hash_input_size + j] = hash_outputs_1[i * _hash_output_size + j];
            }


            int base_hash = i * _hash_input_size + _hash_output_size;
            int base_node = (path_length - 2 - i) * 32;
            _zero_var_assign(hash_inputs_2 + base_hash, 160);
            _assign(hash_inputs_2 + base_hash + 0 * 32,
                                 variable_id_decomposition + base_node);
            _assign(hash_inputs_2 + base_hash + 1 * 32,
                                 threshold_decomposition + base_node);
            _assign(hash_inputs_2 + base_hash + 2 * 32,
                                 node_id_decomposition + base_node);
            _assign(hash_inputs_2 + base_hash + 3 * 32,
                                 l_node_id_decomposition + base_node);
            _assign(hash_inputs_2 + base_hash + 4 * 32,
                                 r_node_id_decomposition + base_node);

        }

        for (int i = 0; i < 2 * (path_length - 1); ++i) {
            swifftGadget[i].generate_r1cs_constraints();
        }

        for (int j = 0; j < _hash_output_size; ++j) {
            add_r1cs(hash_outputs_2[(path_length - 2) * _hash_output_size + j], 1, commitment_in_bits[j]);
        }

    }

    void _hash_generate_r1cs_witness() {
        for (int i = 0; i < path_length - 1; ++i) {
            DTNode *current = path[path_length - 1 - i];
            DTNode *sibling = current->sibling();
            DTInternalNode *parent = (DTInternalNode *) current->parent;

            for (int j = 0; j < _hash_output_size; ++j) {
                eval(siblings[i * _hash_output_size + j]) = sibling->hash[j];
                eval(hash_outputs_1[i * _hash_output_size + j]) = parent->first_hash[j];
                eval(hash_outputs_2[i * _hash_output_size + j]) = parent->hash[j];
            }

            for (int j = 0; j < 2; ++j) {
                swifftGadget[i * 2 + j].generate_r1cs_witness(parent->intermediate_linear_combination[j]);
            }
        }

    }

    void _general_generate_r1cs_witness() {
        eval(zero_var) = 0;

        for (int i = 0; i < n_vars; ++i) {
            eval(raw_vars[i]) = values[i];
            eval(raw_index[i]) = i;
        }

        for (int i = 0; i < path_length - 1; ++i) {
            DTInternalNode *node = (DTInternalNode *) path[i];
            eval(node_id[i]) = node->node_id;
            eval(variable_id[i]) = node->variable_id;
            eval(threshold[i]) = node->threshold;
            eval(l_node_id[i]) = node->l->node_id;
            eval(r_node_id[i]) = node->r->node_id;

            _decompose(node->node_id, node_id_decomposition + 32 * i);
            _decompose(node->variable_id, variable_id_decomposition + 32 * i);
            _decompose(node->threshold, threshold_decomposition + 32 * i);
            _decompose(node->l->node_id, l_node_id_decomposition + 32 * i);
            _decompose(node->r->node_id, r_node_id_decomposition + 32 * i);
        }

        eval(node_id[path_length - 1]) = ((DTLeaf *) path[path_length - 1])->node_id;
        eval(class_label) = ((DTLeaf *) path[path_length - 1])->class_id;

        _decompose(((DTLeaf *) path[path_length - 1])->node_id, node_id_decomposition + (path_length - 1) * 32);
        _decompose(((DTLeaf *) path[path_length - 1])->class_id, class_label_decomposition);

        for (int i = 0; i < _hash_output_size; ++i) {
            eval(commitment_in_bits[i]) = path[0]->hash[i];
        }
    }

    unsigned *_variable_count;
    unsigned _n_frequency_bits;

    void _set_frequency_bits() {
        _variable_count = new unsigned[n_vars];
        memset(_variable_count, 0, sizeof(unsigned) * n_vars);
        for (DTNode *node : path) {
            if (!node->is_leaf) {
                _variable_count[((DTInternalNode *) node)->variable_id]++;
            }
        }
        unsigned max_occurence = *std::max_element(_variable_count, _variable_count + n_vars);
        _n_frequency_bits = log(max_occurence) / log(2) + 1;
    }

public:

    DT &dt;
    std::vector<unsigned int> &values;
    std::vector<DTNode *> path;
    int n_vars, path_length;

    DTPathGadget(protoboard <FieldT> &pb, DT &dt_, std::vector<unsigned int> &values_, unsigned int target_class_,
                 FieldT &coef_, FieldT &challenge_point_, const std::string &annotation = "")
            : gadget<FieldT>(pb, annotation), dt(dt_), values(values_) {
        path = dt.predict(values_);
        n_vars = values.size();
        path_length = path.size();

        _set_frequency_bits();
        _init_pb_vars();

        // assign some public inputs and randomness here.
        pb.val(coef) = coef_;
        pb.val(challenge_point) = challenge_point_;
        pb.val(target_class_label) = target_class_;

        /*pairwisePermutationGadget = new PairwisePermutationGadget<FieldT>(pb, raw_index, raw_vars, permuted_index,
                                                                          permuted_vars, coef, challenge_point,
                                                                          n_vars);
        */
        pairwiseMultiSetGadget = new PairwiseMultiSetGadget<FieldT>(pb, raw_index, raw_vars, permuted_index,
                                                                    permuted_vars,
                                                                    frequency_in_bits, coef, challenge_point, n_vars,
                                                                    path_length - 1, _n_frequency_bits,
                                                                    "pairwise_multiset_gadget");

        comparisonGadgets = (ComparisonGadget <FieldT> *) malloc(
                sizeof(ComparisonGadget < FieldT > ) * (path_length - 1));
        for (int i = 0; i < path_length - 1; ++i) {
            auto gadget_name = annotation + std::string("comparison_gadget_") + std::to_string(i);
            new(comparisonGadgets + i) ComparisonGadget<FieldT>(pb, permuted_vars[i],
                                                                threshold[i],
                                                                comparison_results[i], diff[i], gadget_name);
        }

        swifftGadget = (SwifftGadget <FieldT> *) malloc(sizeof(SwifftGadget < FieldT > ) * (path_length - 1) * 2);
        for (int i = 0; i < (path_length - 1); ++i) {
            auto gadget_name = annotation + std::string("hash_gadget_") + std::to_string(i);
            new(swifftGadget + i * 2) SwifftGadget<FieldT>(pb, hash_inputs_1 + i * _hash_input_size,
                                                           hash_outputs_1 + i * _hash_output_size,
                                                           gadget_name + "first");
            new(swifftGadget + i * 2 + 1) SwifftGadget<FieldT>(pb, hash_inputs_2 + i * _hash_input_size,
                                                               hash_outputs_2 + i * _hash_output_size,
                                                               gadget_name + "second");
        }

        decompositionCheckGadgets = (DecompositionCheckGadget <FieldT> *) malloc(
                sizeof(DecompositionCheckGadget < FieldT > ) * 8);
        new(decompositionCheckGadgets + 0) DecompositionCheckGadget<FieldT>(pb, permuted_vars,
                                                                            permuted_vars_decomposition,
                                                                            path_length - 1, 32,
                                                                            "decomposition_check_gadget_0");

        new(decompositionCheckGadgets + 1) DecompositionCheckGadget<FieldT>(pb, variable_id, variable_id_decomposition,
                                                                            path_length - 1, 32,
                                                                            "decomposition_check_gadget_1");
        new(decompositionCheckGadgets + 2) DecompositionCheckGadget<FieldT>(pb, node_id, node_id_decomposition,
                                                                            path_length, 32,
                                                                            "decomposition_check_gadget_2");
        new(decompositionCheckGadgets + 3) DecompositionCheckGadget<FieldT>(pb, threshold, threshold_decomposition,
                                                                            path_length - 1, 32,
                                                                            "decomposition_check_gadget_3");
        new(decompositionCheckGadgets + 4) DecompositionCheckGadget<FieldT>(pb, l_node_id, l_node_id_decomposition,
                                                                            path_length - 1, 32,
                                                                            "decomposition_check_gadget_4");
        new(decompositionCheckGadgets + 5) DecompositionCheckGadget<FieldT>(pb, r_node_id, r_node_id_decomposition,
                                                                            path_length - 1, 32,
                                                                            "decomposition_check_gadget_5");

        new(decompositionCheckGadgets + 6) DecompositionCheckGadget<FieldT>(pb, &class_label, class_label_decomposition,
                                                                            1, 32, "decomposition_check_gadget_6");
        new(decompositionCheckGadgets + 7) DecompositionCheckGadget<FieldT>(pb, diff, diff_decomposition,
                                                                            path_length - 1, 32,
                                                                            "decomposition_check_gadget_7");
    }

    ~DTPathGadget() {

        delete[] raw_vars;
        delete[] raw_index;
        delete[] commitment_in_bits;

        // extended witness: permutation
        delete[] permuted_vars;
        delete[] permuted_index;

        // secret: v1, v2, ... vh
        delete[] node_id;
        delete[] variable_id;
        delete[] threshold;
        delete[] l_node_id;
        delete[] r_node_id;

        //extended witness: bit decompositions
        delete[] permuted_vars_decomposition;
        delete[] node_id_decomposition;
        delete[] variable_id_decomposition;
        delete[] threshold_decomposition;
        delete[] l_node_id_decomposition;
        delete[] r_node_id_decomposition;
        delete[] class_label_decomposition;

        // helper variables
        delete pairwiseMultiSetGadget;
        delete[] _variable_count;
        delete[] frequency_in_bits;

        for (int i = 0; i < path_length - 1; ++i) {
            (comparisonGadgets + i)->~ComparisonGadget();
        }
        free(comparisonGadgets);

        delete[] comparison_results;

        for (int i = 0; i < 2 * (path_length - 1); ++i) {
            (swifftGadget + i)->~SwifftGadget();
        }
        free(swifftGadget);

        delete[] siblings;
        delete[] hash_inputs_1;
        delete[] hash_inputs_2;
        delete[] hash_outputs_1;
        delete[] hash_outputs_2;

        for (int i = 0; i < 8; ++i) {
            (decompositionCheckGadgets + i)->~DecompositionCheckGadget();
        }
        free(decompositionCheckGadgets);
    }

    void generate_r1cs_constraints() {
        this->_multiset_generate_r1cs_constraints();
        this->_bit_decomposition_generate_r1cs_constraints();
        this->_dt_prediction_generate_r1cs_constraints();
        this->_hash_generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        this->_general_generate_r1cs_witness();
        this->_multiset_generate_r1cs_witness();
        this->_bit_decomposition_generate_r1cs_witness();
        this->_dt_prediction_generate_r1cs_witness();
        this->_hash_generate_r1cs_witness();
    }
};

#endif //ZKDT_GADGET_H

