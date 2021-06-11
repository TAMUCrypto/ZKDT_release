#include <iostream>
#include <algorithm>
#include <stdexcept>
#include <cstdlib>
#include <numeric>

#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include "gadgets/dt_path_gadget.h"
#include "DT/DT.h"
#include "hash.h"
#include "DT/compile.h"
#include "gadgets/swifft.h"

using namespace libsnark;

// the size of a r1cs scales almost linearly with the depth parameters
// in this synthetic example, we require that n_vars >= depth
template<class FieldT>
void test_synthetic_dt_path(int depth = 100) {
    std::cout << "Generate R1CS for synthetic DT: " << std::endl;
    std::cout << "Depth: " << depth << std::endl;

    int n_vars = depth + 1;
    DT *dt = single_chain_dt(depth);
    dt->gather_statistics();

    std::vector<unsigned> values;
    for (int j = 0; j < n_vars; ++j) {
        unsigned x = rand() % 100;
        values.push_back(x);
    }
    std::vector < DTNode * > path = dt->predict(values);
    unsigned target_label = ((DTLeaf *) path[path.size() - 1])->class_id;

    protoboard <FieldT> pb;
    FieldT coef = FieldT(), challenge_point = FieldT();
    DTPathGadget <FieldT> dtPathGadget = DTPathGadget<FieldT>(pb, *dt, values, target_label, coef, challenge_point,
                                                              "dt_path_gadget");
    dtPathGadget.generate_r1cs_constraints();
    dtPathGadget.generate_r1cs_witness();
    std::cout << "N_constraints: " << pb.num_constraints() << std::endl;
    std::cout << "N_variables: " << pb.num_variables() << std::endl;
    std::cout << "Satisfied?: " << pb.is_satisfied() << std::endl;
}

unsigned target_batch_size = 500;

void parse_line(const std::string& line, std::vector<unsigned>& sample, unsigned n_values, unsigned multi) {
    sample.clear();
    float v;
    std::stringstream ss(line);
    for (int i = 0; i < n_values; ++i) {
        ss >> v;
        v = v * multi;
        sample.push_back((unsigned) v);
        if (ss.peek() == ',') {
            ss.ignore();
        }
    }
}

void read_dataset(const std::string& filename, std::vector<std::vector<unsigned>>& data, unsigned multi) {
    std::ifstream f (filename);
    std::string line;

    if (f.is_open()) {
        // how many values do we have?
        unsigned n_values = 0;
        std::getline(f, line);
        for (int i = 0; i < line.size(); ++i) {
            if (line[i] == ',') {
                n_values++;
            }
        }

        unsigned n_lines = 0;
        data.push_back(std::vector<unsigned>());
        parse_line(line, data[n_lines++], n_values, multi);

        while (std::getline(f, line)) {
            if (line.size() < 5) {
                continue;
            }
            data.push_back(std::vector<unsigned>());
            parse_line(line, data[n_lines++], n_values, multi);
            if (n_lines == target_batch_size) {
                break;
            }
        }

        f.close();
    } else {
        throw std::runtime_error("Can not open data file");
    }
}

template <class FieldT>
void test_real_dt_path() {
    unsigned selector = 3;// [0, 1, 2, 3, 4, 5]

    std::cout << "Generate R1CS for ";
    std::string names[6] = {"Iris", "Wine", "Abalone", "Forest", "Breast-cancer-wisconsin", "Spambase"};
    std::cout << names[selector] << std::endl;

    DT *dt;
    std::vector <std::vector<unsigned>> data;

    switch (selector) {
        case 0:
            dt = _read_dt_from_file("../Model/Iris_dt.txt");
            read_dataset("../Model/iris.data", data, 100);
            break;
        case 1:
            dt = _read_dt_from_file("../Model/wine_dt.txt");
            read_dataset("../Model/wine.data", data, 10000);
            break;
        case 2:
            dt = _read_dt_from_file("../Model/Abalone_dt.txt");
            read_dataset("../Model/abalone.data", data, 10000);
            break;
        case 3:
            dt = _read_dt_from_file("../Model/Forest_dt.txt");
            read_dataset("../Model/covtype.data", data, 100);
            break;
        case 4:
            dt = _read_dt_from_file("../Model/breast-cancer-wisconsin_dt.txt");
            read_dataset("../Model/breast-cancer-wisconsin.data", data, 1);
            break;
        case 5:
            dt = _read_dt_from_file("../Model/spambase_dt.txt");
            read_dataset("../Model/spambase.data", data, 1000);
            break;
    }

    std::cout << "attribute size: " << data[0].size() << std::endl;

    dt->gather_statistics();
    std::vector < DTNode * > path = dt->predict(data[0]);
    unsigned target_label = ((DTLeaf *) path[path.size() - 1])->class_id;

    std::cout << "Tree height: " << dt->root->height << std::endl;
    std::cout << "Tree size: " << dt->root->size << std::endl;
    std::cout << "Non-leaf size: " << dt->root->non_leaf_size << std::endl;

    protoboard <FieldT> pb;
    FieldT coef = rand(), challenge_point = rand();
    DTPathGadget <FieldT> dtPathGadget = DTPathGadget<FieldT>(pb, *dt, data[0], target_label, coef, challenge_point,
                                                                 "dt_batch_gadget");
    dtPathGadget.generate_r1cs_constraints();
    dtPathGadget.generate_r1cs_witness();
    std::cout << "N_constraints: " << pb.num_constraints() << std::endl;
    std::cout << "N_variables: " << pb.num_variables() << std::endl;
    std::cout << "Satisfied?: " << pb.is_satisfied() << std::endl;
}


int main() {
    default_r1cs_gg_ppzksnark_pp::init_public_params();
    swifft::init_swifft();

    test_synthetic_dt_path<libff::Fr<default_r1cs_gg_ppzksnark_pp>>();
    test_real_dt_path<libff::Fr<default_r1cs_gg_ppzksnark_pp>>();
}