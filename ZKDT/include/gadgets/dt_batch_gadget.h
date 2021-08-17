#ifndef ZKDT_DT_BATCH_GADGET_H
#define ZKDT_DT_BATCH_GADGET_H

#include "DT/DT.h"
#include "gadgets/common.h"
#include "gadgets/tool_gadgets.h"
#include "gadgets/swifft.h"


template<typename FieldT>
class PathPredictionGadget : public gadget<FieldT> {

public:

    // public input
    pb_variable <FieldT> *raw_vars;
    pb_variable <FieldT> *raw_index;
    pb_variable <FieldT> coef, challenge_point, target_class_label;

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

    // helper variables
    PairwiseMultiSetGadget <FieldT> *pairwiseMultiSetGadget;
    pb_variable <FieldT> *frequency_in_bits;

    ComparisonGadget <FieldT> *comparisonGadgets;
    pb_variable <FieldT> *comparison_results;
    pb_variable <FieldT> *diff;
    pb_variable <FieldT> *diff_decomposition;

    DecompositionCheckGadget <FieldT> *decompositionCheckGadgets;

    void _init_pb_vars() {
        auto &prefix = this->annotation_prefix;

        // raw_vars, raw_index, coef, challenge_point, commitment_in_bits
        _init_pb_array(this->pb, raw_vars, n_vars, prefix + std::string("raw_vars"));
        _init_pb_array(this->pb, raw_index, n_vars, prefix + std::string("raw_index"));

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

        _init_pb_array(this->pb, frequency_in_bits, n_vars * _n_frequency_bits,
                       prefix + std::string("frequency_in_bits"));

        // comparison_results, hash_inputs, hash_outputs
        _init_pb_array(this->pb, comparison_results, path_length - 1, prefix + std::string("comparison_results"));
        _init_pb_array(this->pb, diff, path_length - 1, prefix + std::string("diff"));
        _init_pb_array(this->pb, diff_decomposition, (path_length - 1) * 32,
                       prefix + std::string("diff_decomposition"));
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
        decompositionCheckGadgets[0].generate_r1cs_constraints();
    }

    void _bit_decomposition_generate_r1cs_witness() {
        decompositionCheckGadgets[0].generate_r1cs_witness();
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
            unsigned x = values[((DTInternalNode *) path[i])->variable_id], y = ((DTInternalNode *) path[i])->threshold;
            unsigned d = (x <= y) ? (y - x) : (x - y);
            _decompose(d, diff_decomposition + 32 * i);
            eval(diff[i]) = d;
        }

        for (int i = 0; i < path_length - 1; ++i) {
            comparisonGadgets[i].generate_r1cs_witness();
        }
    }

    void _general_generate_r1cs_witness() {
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
        }

        eval(node_id[path_length - 1]) = ((DTLeaf *) path[path_length - 1])->node_id;
        eval(class_label) = ((DTLeaf *) path[path_length - 1])->class_id;
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

    PathPredictionGadget(protoboard <FieldT> &pb, DT &dt_, std::vector<unsigned int> &values_,
                         unsigned int target_class_,
                         pb_variable <FieldT> &coef_, pb_variable <FieldT> &challenge_point_,
                         const std::string &annotation = "")
            : gadget<FieldT>(pb, annotation), dt(dt_), values(values_) {
        path = dt.predict(values_);
        n_vars = values.size();
        path_length = path.size();

        _set_frequency_bits();
        _init_pb_vars();

        // assign some public inputs and randomness here.
        coef = coef_;
        challenge_point = challenge_point_;
        pb.val(target_class_label) = target_class_;

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

        decompositionCheckGadgets = new DecompositionCheckGadget<FieldT>(pb, diff, diff_decomposition,
                                                                         path_length - 1, 32,
                                                                         "decomposition_check_gadget");
    }

    ~PathPredictionGadget() {

        delete[] raw_vars;
        delete[] raw_index;

        // extended witness: permutation
        delete[] permuted_vars;
        delete[] permuted_index;

        // secret: v1, v2, ... vh
        delete[] node_id;
        delete[] variable_id;
        delete[] threshold;
        delete[] l_node_id;
        delete[] r_node_id;

        // helper variables
        delete pairwiseMultiSetGadget;
        delete[] _variable_count;
        delete[] frequency_in_bits;

        for (int i = 0; i < path_length - 1; ++i) {
            (comparisonGadgets + i)->~ComparisonGadget();
        }
        free(comparisonGadgets);

        delete[] comparison_results;

        for (int i = 0; i < 8; ++i) {
            (decompositionCheckGadgets + i)->~DecompositionCheckGadget();
        }
        free(decompositionCheckGadgets);
    }

    void generate_r1cs_constraints() {
        this->_multiset_generate_r1cs_constraints();
        this->_bit_decomposition_generate_r1cs_constraints();
        this->_dt_prediction_generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        this->_general_generate_r1cs_witness();
        this->_multiset_generate_r1cs_witness();
        this->_bit_decomposition_generate_r1cs_witness();
        this->_dt_prediction_generate_r1cs_witness();
    }
};


template<typename FieldT>
class DTBatchGadget : public gadget<FieldT> {
    const static unsigned N_BITS_NODE_ATTR = 32;
private:
    std::map<unsigned, unsigned> leaf_id_index;
    std::map<unsigned, unsigned> non_leaf_id_index;

    pb_variable <FieldT> *node_id;
    pb_variable <FieldT> *variable_id;
    pb_variable <FieldT> *threshold;
    pb_variable <FieldT> *l_node_id;
    pb_variable <FieldT> *r_node_id;
    pb_variable <FieldT> *class_label;

    pb_variable <FieldT> *node_id_decomposition;
    pb_variable <FieldT> *variable_id_decomposition;
    pb_variable <FieldT> *threshold_decomposition;
    pb_variable <FieldT> *l_node_id_decomposition;
    pb_variable <FieldT> *r_node_id_decomposition;
    pb_variable <FieldT> *class_label_decomposition;

    pb_variable <FieldT> *hash_inputs_1;
    pb_variable <FieldT> *hash_inputs_2;
    pb_variable <FieldT> *hash_outputs_1;
    pb_variable <FieldT> *hash_outputs_2;

    pb_variable <FieldT> *commitment;

    pb_variable <FieldT> zero_var;

    pb_variable <FieldT> coef, challenge_point;

    pb_variable <FieldT> *coef_array;

    pb_variable <FieldT> **tree_nodes_values;
    pb_variable <FieldT> *tree_nodes_terms;
    pb_variable <FieldT> **path_nodes_values;
    pb_variable <FieldT> *path_nodes_terms;

    unsigned n_frequency_bits;
    std::vector<unsigned> nodes_count;
    pb_variable <FieldT> *frequency_in_bits;

private:
    DecompositionCheckGadget <FieldT> *decompositionCheckGadgets;
    SwifftGadget <FieldT> *swifftGadget;
    PathPredictionGadget<FieldT> *pathPredictionGadget;
    LinearCombinationGadget <FieldT> *treeLinearCombinationGadget;
    LinearCombinationGadget <FieldT> *pathLinearCombinationGadget;
    MultiSetGadget <FieldT> *multisetGadget;


private:

    void _init_id_map() {
        std::vector < DTNode * > nodes = dt.get_all_nodes();
        unsigned non_leaf_count = 0, leaf_count = 0;
        for (DTNode *node : nodes) {
            if (node->is_leaf) {
                leaf_id_index[node->node_id] = leaf_count++;
            } else {
                non_leaf_id_index[node->node_id] = non_leaf_count++;
            }
        }
    }

    void _count() {
        nodes_count.resize(dt.n_nodes, 0);
        for (auto &path_nodes: all_paths) {
            for (auto &node: path_nodes) {
                unsigned index;
                if (node->is_leaf) {
                    index = leaf_id_index[node->node_id] + dt.root->non_leaf_size;
                } else {
                    index = non_leaf_id_index[node->node_id];
                }
                nodes_count[index]++;
            }
        }
        n_frequency_bits = log(all_paths.size()) / log(2) + 1;
    }

    void _init_pb_vars() {

        std::string prefix = this->annotation_prefix;
        zero_var.allocate(this->pb, prefix + "zero_var");
        coef.allocate(this->pb, prefix + "coef");
        challenge_point.allocate(this->pb, prefix + "challenge_point");

        _init_pb_array(this->pb, node_id, dt.n_nodes, prefix + "node_id");
        _init_pb_array(this->pb, variable_id, dt.root->non_leaf_size, prefix + "variable_id");
        _init_pb_array(this->pb, threshold, dt.root->non_leaf_size, prefix + "threshold");
        _init_pb_array(this->pb, l_node_id, dt.root->non_leaf_size, prefix + "l_node_id");
        _init_pb_array(this->pb, r_node_id, dt.root->non_leaf_size, prefix + "r_node_id");
        _init_pb_array(this->pb, class_label, dt.n_nodes - dt.root->non_leaf_size, prefix + "class_label");

        // no need to allocate inputs, because they are placeholders, and are assigned other variables
        hash_inputs_1 = new pb_variable<FieldT>[dt.root->non_leaf_size * _hash_input_size];
        hash_inputs_2 = new pb_variable<FieldT>[dt.root->non_leaf_size * _hash_input_size];
        _init_pb_array(this->pb, hash_outputs_1, dt.root->non_leaf_size * _hash_output_size, prefix + "hash_outputs_1");
        _init_pb_array(this->pb, hash_outputs_2, dt.root->non_leaf_size * _hash_output_size, prefix + "hash_outputs_2");
        _init_pb_array(this->pb, commitment, _hash_output_size, prefix + "commitment");

        _init_pb_array(this->pb, node_id_decomposition, dt.n_nodes * N_BITS_NODE_ATTR,
                       prefix + "node_id_decomposition");
        _init_pb_array(this->pb, variable_id_decomposition, dt.root->non_leaf_size * N_BITS_NODE_ATTR,
                       prefix + "variable_id_decomposition");
        _init_pb_array(this->pb, threshold_decomposition, dt.root->non_leaf_size * N_BITS_NODE_ATTR,
                       prefix + "threshold_decomposition");
        _init_pb_array(this->pb, l_node_id_decomposition, dt.root->non_leaf_size * N_BITS_NODE_ATTR,
                       prefix + "l_node_id_decomposition");
        _init_pb_array(this->pb, r_node_id_decomposition, dt.root->non_leaf_size * N_BITS_NODE_ATTR,
                       prefix + "r_node_id_decomposition");
        _init_pb_array(this->pb, class_label_decomposition, (dt.n_nodes - dt.root->non_leaf_size) * N_BITS_NODE_ATTR,
                       prefix + "class_label_decomposition");

        _init_pb_array(this->pb, coef_array, dt.n_nodes, prefix + "coef_array");

        tree_nodes_values = new pb_variable <FieldT> *[dt.n_nodes];
        path_nodes_values = new pb_variable <FieldT> *[n_path_nodes];
        _init_pb_array(this->pb, tree_nodes_terms, dt.n_nodes, prefix + "tree_nodes_terms");
        _init_pb_array(this->pb, path_nodes_terms, n_path_nodes, prefix + "path_nodes_terms");

        _init_pb_array(this->pb, frequency_in_bits, n_frequency_bits * dt.n_nodes, prefix + "frequency_in_bits");
    }

    void _init_sub_gadgets() {

        std::string prefix = this->annotation_prefix;

        auto &pb = this->pb;
        decompositionCheckGadgets = (DecompositionCheckGadget <FieldT> *) malloc(
                sizeof(DecompositionCheckGadget < FieldT > ) * 6);

        for (int i = 0; i < 6; ++i) {
            new(decompositionCheckGadgets + 0) DecompositionCheckGadget<FieldT>(pb, node_id, node_id_decomposition,
                                                                                dt.n_nodes, N_BITS_NODE_ATTR,
                                                                                prefix +
                                                                                "decomposition_check_gadget_0");
            new(decompositionCheckGadgets + 1) DecompositionCheckGadget<FieldT>(pb, variable_id,
                                                                                variable_id_decomposition,
                                                                                dt.root->non_leaf_size,
                                                                                N_BITS_NODE_ATTR,
                                                                                prefix +
                                                                                "decomposition_check_gadget_1");
            new(decompositionCheckGadgets + 2) DecompositionCheckGadget<FieldT>(pb, threshold, threshold_decomposition,
                                                                                dt.root->non_leaf_size,
                                                                                N_BITS_NODE_ATTR,
                                                                                prefix +
                                                                                "decomposition_check_gadget_2");
            new(decompositionCheckGadgets + 3) DecompositionCheckGadget<FieldT>(pb, l_node_id, l_node_id_decomposition,
                                                                                dt.root->non_leaf_size,
                                                                                N_BITS_NODE_ATTR,
                                                                                prefix +
                                                                                "decomposition_check_gadget_3");
            new(decompositionCheckGadgets + 4) DecompositionCheckGadget<FieldT>(pb, r_node_id, r_node_id_decomposition,
                                                                                dt.root->non_leaf_size,
                                                                                N_BITS_NODE_ATTR,
                                                                                prefix +
                                                                                "decomposition_check_gadget_4");
            new(decompositionCheckGadgets + 5) DecompositionCheckGadget<FieldT>(pb, class_label,
                                                                                class_label_decomposition,
                                                                                dt.n_nodes - dt.root->non_leaf_size,
                                                                                N_BITS_NODE_ATTR,
                                                                                prefix +
                                                                                "decomposition_check_gadget_5");
        }

        swifftGadget = (SwifftGadget <FieldT> *) malloc(sizeof(SwifftGadget < FieldT > ) * dt.root->non_leaf_size * 2);
        for (int i = 0; i < dt.root->non_leaf_size; ++i) {
            auto gadget_name = prefix + std::string("hash_gadget_") + std::to_string(i);
            new(swifftGadget + i * 2) SwifftGadget<FieldT>(pb, hash_inputs_1 + i * _hash_input_size,
                                                           hash_outputs_1 + i * _hash_output_size,
                                                           gadget_name + "first");
            new(swifftGadget + i * 2 + 1) SwifftGadget<FieldT>(pb, hash_inputs_2 + i * _hash_input_size,
                                                               hash_outputs_2 + i * _hash_output_size,
                                                               gadget_name + "second");
        }

        pathPredictionGadget = (PathPredictionGadget<FieldT> *) malloc(
                sizeof(PathPredictionGadget<FieldT>) * data.size());

        for (int i = 0; i < data.size(); ++i) {
            std::vector<unsigned> &single_data = data[i];
            new(pathPredictionGadget + i) PathPredictionGadget<FieldT>(this->pb, dt, single_data,
                                                                       ((DTLeaf *) all_paths[i].back())->class_id,
                                                                       coef, challenge_point, this->annotation_prefix +
                                                                                              "path_prediction_gadget" +
                                                                                              std::to_string(i));
        }

        unsigned index, length;
        treeLinearCombinationGadget =
                (LinearCombinationGadget <FieldT> *) malloc(sizeof(LinearCombinationGadget < FieldT > ) * dt.n_nodes);
        for (index = 0; index < dt.n_nodes; ++index) {
            if (index < dt.root->non_leaf_size) {
                tree_nodes_values[index] = new pb_variable<FieldT>[5];

                tree_nodes_values[index][0] = node_id[index];
                tree_nodes_values[index][1] = variable_id[index];
                tree_nodes_values[index][2] = threshold[index];
                tree_nodes_values[index][3] = l_node_id[index];
                tree_nodes_values[index][4] = r_node_id[index];

                length = 5;
            } else {
                tree_nodes_values[index] = new pb_variable<FieldT>[2];
                tree_nodes_values[index][0] = class_label[index - dt.root->non_leaf_size];
                tree_nodes_values[index][1] = node_id[index];
                length = 2;
            }

            new(treeLinearCombinationGadget + index) LinearCombinationGadget<FieldT>(this->pb, tree_nodes_values[index],
                                                                                     coef_array,
                                                                                     tree_nodes_terms[index], length,
                                                                                     this->annotation_prefix +
                                                                                     "tree_linear_combination_gadgets" +
                                                                                     std::to_string(index));
        }

        pathLinearCombinationGadget =
                (LinearCombinationGadget <FieldT> *) malloc(sizeof(LinearCombinationGadget < FieldT > ) * n_path_nodes);
        index = 0;
        for (int i = 0; i < all_paths.size(); ++i) {
            for (int j = 0; j < all_paths[i].size(); ++j) {
                if (j == all_paths[i].size() - 1) {
                    path_nodes_values[index] = new pb_variable<FieldT>[2];
                    path_nodes_values[index][0] = pathPredictionGadget[i].class_label;
                    path_nodes_values[index][1] = pathPredictionGadget[i].node_id[j];
                    length = 2;
                } else {
                    path_nodes_values[index] = new pb_variable<FieldT>[5];

                    path_nodes_values[index][0] = pathPredictionGadget[i].node_id[j];
                    path_nodes_values[index][1] = pathPredictionGadget[i].variable_id[j];
                    path_nodes_values[index][2] = pathPredictionGadget[i].threshold[j];
                    path_nodes_values[index][3] = pathPredictionGadget[i].l_node_id[j];
                    path_nodes_values[index][4] = pathPredictionGadget[i].r_node_id[j];
                    length = 5;
                }
                new(pathLinearCombinationGadget + index) LinearCombinationGadget<FieldT>(this->pb,
                                                                                         path_nodes_values[index],
                                                                                         coef_array,
                                                                                         path_nodes_terms[index],
                                                                                         length,
                                                                                         this->annotation_prefix +
                                                                                         "path_linear_combination_gadgets" +
                                                                                         std::to_string(index));
                index++;
            }
        }

        multisetGadget = new MultiSetGadget<FieldT>(this->pb, tree_nodes_terms, path_nodes_terms,
                                                    frequency_in_bits, dt.n_nodes, n_path_nodes, n_frequency_bits,
                                                    challenge_point, prefix + "multisetGadget");
    }


private:

    void _decompose(unsigned value, pb_variable <FieldT> *bits) {
        for (int i = 0; i < N_BITS_NODE_ATTR; ++i) {
            eval(bits[i]) = (value >> (N_BITS_NODE_ATTR - 1 - i)) & 1U;
        }
    }

    void _general_witness() {
        std::vector < DTNode * > nodes = dt.get_all_nodes();
        for (DTNode *node: nodes) {
            if (node->is_leaf) {
                unsigned index = leaf_id_index[node->node_id];
                DTLeaf *leaf = ((DTLeaf *) node);

                eval(class_label[index]) = leaf->class_id;
                eval(node_id[dt.root->non_leaf_size + index]) = leaf->node_id;
                // move these to sub gadgets...
                _decompose(leaf->class_id, class_label_decomposition + N_BITS_NODE_ATTR * index);
                _decompose(leaf->node_id, node_id_decomposition + N_BITS_NODE_ATTR * (dt.root->non_leaf_size + index));

            } else {
                unsigned index = non_leaf_id_index[node->node_id];

                DTInternalNode *internalNode = (DTInternalNode *) node;
                eval(node_id[index]) = internalNode->node_id;
                eval(variable_id[index]) = internalNode->variable_id;
                eval(threshold[index]) = internalNode->threshold;
                eval(l_node_id[index]) = internalNode->l->node_id;
                eval(r_node_id[index]) = internalNode->r->node_id;

                // move these to sub gadgets...
                _decompose(internalNode->node_id, node_id_decomposition + index * N_BITS_NODE_ATTR);
                _decompose(internalNode->variable_id, variable_id_decomposition + +index * N_BITS_NODE_ATTR);
                _decompose(internalNode->threshold, threshold_decomposition + index * N_BITS_NODE_ATTR);
                _decompose(internalNode->l->node_id, l_node_id_decomposition + index * N_BITS_NODE_ATTR);
                _decompose(internalNode->r->node_id, r_node_id_decomposition + index * N_BITS_NODE_ATTR);
            }
        }

    }

    void _decomposition_constraints() {
        for (int i = 0; i < 6; ++i) {
            decompositionCheckGadgets[i].generate_r1cs_constraints();
        }
    }

    void _decomposition_witness() {
        for (int i = 0; i < 6; ++i) {
            decompositionCheckGadgets[i].generate_r1cs_witness();
        }
    }

    void _copy(pb_variable <FieldT> *target, pb_variable <FieldT> *source, unsigned size = N_BITS_NODE_ATTR) {
        for (int i = 0; i < size; ++i) {
            target[i] = source[i];
        }
    }

    void _zero_var_assign(pb_variable <FieldT> *a, int start = 0) {
        for (int i = start; i < _hash_output_size; ++i) {
            a[i] = zero_var;
        }
    }

    void _fill_in_input_1(pb_variable <FieldT> *inputs, DTNode *node) {
        if (node->is_leaf) {
            DTLeaf *leaf = (DTLeaf *) node;
            unsigned index = leaf_id_index[node->node_id];

            _copy(inputs, class_label_decomposition + index * N_BITS_NODE_ATTR);
            _copy(inputs + N_BITS_NODE_ATTR,
                  node_id_decomposition + (dt.root->non_leaf_size + index) * N_BITS_NODE_ATTR);
            _zero_var_assign(inputs, N_BITS_NODE_ATTR * 2);

        } else {
            DTInternalNode *internalNode = (DTInternalNode *) node;
            unsigned index = non_leaf_id_index[node->node_id];
            _copy(inputs, hash_outputs_2 + index * _hash_output_size, _hash_output_size);
        }
    }

    void _fill_in_input_2(pb_variable <FieldT> *inputs, DTInternalNode *internalNode) {
        unsigned index = non_leaf_id_index[internalNode->node_id];

        _copy(inputs, hash_outputs_1 + index * _hash_output_size, _hash_output_size);

        inputs = inputs + _hash_output_size;
        _copy(inputs, variable_id_decomposition + index * N_BITS_NODE_ATTR);
        _copy(inputs + N_BITS_NODE_ATTR, threshold_decomposition + index * N_BITS_NODE_ATTR);
        _copy(inputs + N_BITS_NODE_ATTR * 2, node_id_decomposition + index * N_BITS_NODE_ATTR);
        _copy(inputs + N_BITS_NODE_ATTR * 3, l_node_id_decomposition + index * N_BITS_NODE_ATTR);
        _copy(inputs + N_BITS_NODE_ATTR * 4, r_node_id_decomposition + index * N_BITS_NODE_ATTR);

        _zero_var_assign(inputs, N_BITS_NODE_ATTR * 5);

    }

    void _hash_constraints() {
        std::vector < DTNode * > nodes = dt.get_all_nodes();
        for (DTNode *node : nodes) {
            if (!node->is_leaf) {
                DTInternalNode *internalNode = (DTInternalNode *) node;
                unsigned index = non_leaf_id_index[internalNode->node_id];

                _fill_in_input_1(hash_inputs_1 + _hash_input_size * index, internalNode->l);
                _fill_in_input_1(hash_inputs_1 + _hash_input_size * index + _hash_output_size, internalNode->r);
                _fill_in_input_2(hash_inputs_2 + _hash_input_size * index, internalNode);
                swifftGadget[index * 2].generate_r1cs_constraints();
                swifftGadget[index * 2 + 1].generate_r1cs_constraints();
            }
        }

        unsigned root_index = non_leaf_id_index[dt.root->node_id];
        for (int i = 0; i < _hash_output_size; ++i) {
            add_r1cs(hash_outputs_2[root_index * _hash_output_size + i], 1, commitment[i]);
        }
    }

    void _fill_in_output_1(pb_variable <FieldT> *output, DTInternalNode *internalNode) {
        for (int i = 0; i < _hash_output_size; ++i) {
            eval(output[i]) = internalNode->first_hash[i];
        }
    }

    void _fill_in_output_2(pb_variable <FieldT> *output, DTInternalNode *internalNode) {
        for (int i = 0; i < _hash_output_size; ++i) {
            eval(output[i]) = internalNode->hash[i];
        }
    }

    void _hash_witness() {
        eval(zero_var) = 0;
        std::vector < DTNode * > nodes = dt.get_all_nodes();
        for (DTNode *node : nodes) {
            if (!node->is_leaf) {
                DTInternalNode *internalNode = (DTInternalNode *) node;
                unsigned index = non_leaf_id_index[internalNode->node_id];

                _fill_in_output_1(hash_outputs_1 + index * _hash_output_size, internalNode);
                _fill_in_output_2(hash_outputs_2 + index * _hash_output_size, internalNode);

                swifftGadget[index * 2].generate_r1cs_witness(internalNode->intermediate_linear_combination[0]);
                swifftGadget[index * 2 + 1].generate_r1cs_witness(internalNode->intermediate_linear_combination[1]);
            }
        }

        unsigned root_index = non_leaf_id_index[dt.root->node_id];
        for (int i = 0; i < _hash_output_size; ++i) {
            eval(commitment[i]) = dt.root->hash[i];
        }
    }

    void _path_constraints() {
        for (int i = 0; i < data.size(); ++i) {
            pathPredictionGadget[i].generate_r1cs_constraints();
        }
    }

    void _path_witness() {
        for (int i = 0; i < data.size(); ++i) {
            pathPredictionGadget[i].generate_r1cs_witness();
        }
    }

    void _nodes_multiset_constraints() {
        add_r1cs(coef_array[0], 1, coef);

        for (int i = 0; i < dt.n_nodes - 1; ++i) {
            add_r1cs(coef_array[i], coef, coef_array[i + 1]);
        }

        for (int i = 0; i < dt.n_nodes; ++i) {
            treeLinearCombinationGadget[i].generate_r1cs_constraints();
        }

        for (int i = 0; i < n_path_nodes; ++i) {
            pathLinearCombinationGadget[i].generate_r1cs_constraints();
        }

        multisetGadget->generate_r1cs_constraints();
    }

    void _nodes_multiset_witness() {
        eval(coef_array[0]) = eval(coef);
        for (int i = 0; i < dt.n_nodes - 1; ++i) {
            eval(coef_array[i + 1]) = eval(coef) * eval(coef_array[i]);
        }

        for (int i = 0; i < dt.n_nodes; ++i) {
            treeLinearCombinationGadget[i].generate_r1cs_witness();
        }

        for (int i = 0; i < n_path_nodes; ++i) {
            pathLinearCombinationGadget[i].generate_r1cs_witness();
        }

        for (int i = 0; i < dt.n_nodes; ++i) {
            for (int j = 0; j < n_frequency_bits; ++j) {
                eval(frequency_in_bits[i * n_frequency_bits + j]) =
                        (nodes_count[i] >> (n_frequency_bits - j - 1)) & 1U;
            }
        }

        multisetGadget->generate_r1cs_witness();
    }

public:

    unsigned n_path_nodes;
    DT &dt;
    std::vector <std::vector<unsigned>> data;
    std::vector <std::vector<DTNode *>> all_paths;

    DTBatchGadget(protoboard <FieldT> &pb, DT &dt_, std::vector <std::vector<unsigned>> &data_,
            std::vector <unsigned> labels, unsigned n_correct,
            FieldT &coef_,
                  FieldT &challenge_point_, const std::string &annotation = "")
            : gadget<FieldT>(pb, annotation), dt(dt_), data(data_) {

        n_path_nodes = 0;
        for (int i = 0; i < data.size(); ++i) {
            std::vector<unsigned> &single_data = data[i];
            std::vector < DTNode * > path_nodes = dt.predict(single_data);
            n_path_nodes += path_nodes.size();
            all_paths.push_back(path_nodes);
        }
        _init_id_map();
        _count();

        _init_pb_vars();
        _init_sub_gadgets();

        eval(coef) = coef_;
        eval(challenge_point) = challenge_point_;
    }

    void generate_r1cs_constraints() {
        _decomposition_constraints();
        _hash_constraints();
        _path_constraints();
        _nodes_multiset_constraints();
    }

    void generate_r1cs_witness() {
        _general_witness();
        _decomposition_witness();
        _hash_witness();
        _path_witness();
        _nodes_multiset_witness();
    }
};


#endif //ZKDT_DT_BATCH_GADGET_H
