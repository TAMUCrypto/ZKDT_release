//
// Created by zhiyong on 3/12/20.
//

#ifndef ZKDT_DT_H
#define ZKDT_DT_H

#include <vector>
#include <cassert>
#include <cstring>
#include <cstdio>
#include "hash.h"

const int _hash_input_size = swifft::SWIFFT_INPUT_SIZE;
const int _hash_output_size = swifft::SWIFFT_OUTPUT_SIZE;
const int _hash_input_size_in_bytes = _hash_input_size >> 3;
const int _hash_output_size_in_bytes = _hash_output_size >> 3;
const int _l = swifft::SWIFFT_N;

unsigned _tool_array[_hash_input_size];

class DTNode {
public:
    bool is_leaf;
    unsigned int node_id;
    DTNode *l, *r, *parent;

    unsigned hash[_hash_output_size];
    unsigned height, size, non_leaf_size;

    // this field is used when building the tree
    bool r_visited;

    DTNode(bool is_leaf_, unsigned int node_id_) {
        is_leaf = is_leaf_;
        node_id = node_id_;
        l = r = parent = nullptr;
        r_visited = false;
        height = 0;
    }

    DTNode *sibling() {
        if (parent == nullptr) return nullptr;
        if (this == parent->l) {
            return parent->r;
        } else {
            return parent->l;
        }
    }

    bool is_left() {
        if (parent == nullptr) {
            return false;
        } else {
            return parent->l == this;
        }
    }

    ~DTNode() {
        delete l;
        delete r;
    }
};

// assume all comparisons are '<='
class DTInternalNode : public DTNode {
public:
    unsigned variable_id;
    unsigned threshold;
    unsigned first_hash[_hash_output_size];
    unsigned intermediate_linear_combination[2][_l];

    DTInternalNode(unsigned int node_id_, unsigned int variable_id_, unsigned int threshold_) : DTNode(false,
                                                                                                       node_id_) {
        variable_id = variable_id_;
        threshold = threshold_;
    }

};

class DTLeaf : public DTNode {
public:
    unsigned int class_id;

    DTLeaf(unsigned int node_id_, unsigned int class_id_) : DTNode(true, node_id_) {
        class_id = class_id_;
    }
};

class DT {
public:
    void _fill_in_bits(unsigned *loc, unsigned value) {
        for (int i = 0; i < 32; ++i) {
            loc[i] = (value >> (31 - i)) & 1U;
        }
    }

    void _calculate_hash_value(DTNode *node) {
        if (node == nullptr) {
            throw std::runtime_error("error in calculating hash");
        }
        if (node->is_leaf) {
            memset(node->hash, 0, _hash_output_size * sizeof(unsigned));
            _fill_in_bits(node->hash, ((DTLeaf *) node)->class_id);
            _fill_in_bits(node->hash + 32, ((DTLeaf *) node)->node_id);
        } else {
            _calculate_hash_value(node->l);
            _calculate_hash_value(node->r);
            memcpy(_tool_array, node->l->hash, _hash_output_size * sizeof(unsigned));
            memcpy(_tool_array + _hash_output_size, node->r->hash, _hash_output_size * sizeof(unsigned));
            swifft::hash(_tool_array, ((DTInternalNode *) node)->first_hash, ((DTInternalNode *) node)->intermediate_linear_combination[0]);

            unsigned tmp[_hash_output_size];
            memset(tmp, 0, _hash_output_size * sizeof(unsigned));
            _fill_in_bits(tmp, ((DTInternalNode *) node)->variable_id);
            _fill_in_bits(tmp + 32, ((DTInternalNode *) node)->threshold);
            _fill_in_bits(tmp + 32 * 2, ((DTInternalNode *) node)->node_id);
            _fill_in_bits(tmp + 32 * 3, ((DTInternalNode *) node)->l->node_id);
            _fill_in_bits(tmp + 32 * 4, ((DTInternalNode *) node)->r->node_id);

            memcpy(_tool_array, ((DTInternalNode *) node)->first_hash, _hash_output_size * sizeof(unsigned));
            memcpy(_tool_array + _hash_output_size, tmp, _hash_output_size * sizeof(unsigned));

            swifft::hash(_tool_array, node->hash, ((DTInternalNode *) node)->intermediate_linear_combination[1]);
        }
    }

    void _get_depth_and_size(DTNode* node) {
        assert(node != nullptr);
        if (node->is_leaf) {
            node->height = 1;
            node->size = 1;
            node->non_leaf_size = 0;
        } else {
            _get_depth_and_size(node->l);
            _get_depth_and_size(node->r);
            node->height = std::max(node->l->height, node->r->height) + 1;
            node->size = node->l->size + node->r->size + 1;
            node->non_leaf_size = node->l->non_leaf_size + node->r->non_leaf_size + 1;
        }
    }

    void _fill_in_nodes(std::vector<DTNode *> &nodes, DTNode *node) {
        nodes[node->node_id] = node;
        if (!node->is_leaf) {
            _fill_in_nodes(nodes, node->l);
            _fill_in_nodes(nodes, node->r);
        }
    }

public:
    unsigned int n_nodes;
    DTNode *root;

    DT() {
        root = nullptr;
        n_nodes = 0;
    };

    ~DT() { delete root; }

    DTNode *add_internal_root(unsigned int variable_id, unsigned int threshold) {
        root = new DTInternalNode(n_nodes++, variable_id, threshold);
        return root;
    }

    DTNode *add_leaf_root(unsigned int class_id) {
        root = new DTLeaf(n_nodes++, class_id);
        return root;
    }

    DTNode *add_internal_node(DTNode *node, bool is_left, unsigned int variable_id, unsigned int value) {
        if (is_left) {
            node->l = new DTInternalNode(n_nodes++, variable_id, value);
            node->l->parent = node;
            return node->l;
        } else {
            node->r = new DTInternalNode(n_nodes++, variable_id, value);
            node->r->parent = node;
            return node->r;
        }
    }

    DTNode *add_leaf_node(DTNode *node, bool is_left, unsigned int class_id) {
        if (is_left) {
            node->l = new DTLeaf(n_nodes++, class_id);
            node->l->parent = node;
            return node->l;
        } else {
            node->r = new DTLeaf(n_nodes++, class_id);
            node->r->parent = node;
            return node->r;
        }
    }

    void gather_statistics() {
        if (root == nullptr) return;
        _calculate_hash_value(root);
        _get_depth_and_size(root);
    }

    void print_dt(DTNode *node, int depth = 0) {
        std::cout << std::string(4 * depth, ' ');
        if (!node->is_leaf) {
            std::cout << "node id: " << node->node_id << ' ' << "variable_id: "
                      << ((DTInternalNode *) node)->variable_id << ' '
                      << " threshold: " << ((DTInternalNode *) node)->threshold << std::endl;
        } else {
            std::cout << "node id: " << node->node_id << ' ' << "class_id: " << ((DTLeaf *) node)->class_id
                      << std::endl;
        }

        if (node->l != nullptr) {
            print_dt(node->l, depth + 1);
        }
        if (node->r != nullptr) {
            print_dt(node->r, depth + 1);
        }
        return;
    }

    std::vector<DTNode *> predict(std::vector<unsigned int> &values) {
        std::vector < DTNode * > path;

        DTNode *current_node = root;
        path.push_back(root);

        while (!current_node->is_leaf) {
            if (values[((DTInternalNode *) current_node)->variable_id] <=
                ((DTInternalNode *) current_node)->threshold) {
                current_node = current_node->l;
            } else {
                current_node = current_node->r;
            }
            path.push_back(current_node);
        }
        return path;
    }

    std::vector<DTNode *> get_all_nodes() {
        std::vector<DTNode *> nodes;
        nodes.resize(n_nodes);
        _fill_in_nodes(nodes, root);
        return nodes;
    }
};


DT* single_chain_dt(unsigned length, unsigned default_threshold=100) {
    DT* dt = new DT();
    DTNode* node = dt->add_internal_root(0, 100);
    for (unsigned i = 1; i < length; ++i) {
        dt->add_internal_node(node, true, i, default_threshold);
        dt->add_leaf_node(node, false, rand() % length);
        node = node->l;
    }
    dt->add_leaf_node(node, true, rand() % length);
    dt->add_leaf_node(node, false, rand() % length);
    return dt;
}

DT* full_binary_dt(unsigned depth, unsigned default_threshold) {
    DT* dt = new DT();
    DTNode* root = dt->add_internal_root(0, default_threshold);

    std::vector<DTNode*> nodes[2];
    unsigned current = 0;

    nodes[0].push_back(root);

    for (unsigned i = 1; i < depth; ++i) {
        current ^= 1;
        nodes[current].clear();
        for (DTNode* node : nodes[current ^ 1]) {
            nodes[current].push_back(dt->add_internal_node(node, true, i, default_threshold));
            nodes[current].push_back(dt->add_internal_node(node, false, i, default_threshold));
        }
    }

    for (DTNode* node: nodes[current]) {
        dt->add_leaf_node(node, true, rand() % depth);
        dt->add_leaf_node(node, false, rand() % depth);
    }

    return dt;
}

#endif //ZKDT_DT_H
