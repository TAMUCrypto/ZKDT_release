//
// Created by zhiyong on 4/14/20.
//

#ifndef ZKDT_COMMON_H
#define ZKDT_COMMON_H

#include <libsnark/gadgetlib1/gadget.hpp>

using namespace libsnark;

#define add_r1cs(x, y, z) this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x, y, z))
#define eval(x) this->pb.val(x)

template<typename FieldT>
void _init_pb_array(protoboard <FieldT> &pb, pb_variable <FieldT> *&array, int length, std::string &&name) {
    array = new pb_variable<FieldT>[length];
    for (int i = 0; i < length; ++i) {
        array[i].allocate(pb, name + std::string("_") + std::to_string(i));
    }
}


#endif //ZKDT_COMMON_H
