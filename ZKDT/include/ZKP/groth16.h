#ifndef ZKDT_RELEASE_GROTH16_H
#define ZKDT_RELEASE_GROTH16_H

#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/examples/run_r1cs_gg_ppzksnark.hpp>

using namespace libsnark;

// mostly a wrapper of the Groth16 implementation from libsnark
template<typename ppT>
bool run_r1cs_gg_ppzksnark(const protoboard<libff::Fr<ppT>> &pb, const std::string& name="")
{
    printf("Generating Keys");
    r1cs_gg_ppzksnark_keypair<ppT> keypair = r1cs_gg_ppzksnark_generator<ppT>(pb.get_constraint_system());
    printf("Done.");

    printf("Preprocess verification key");
    r1cs_gg_ppzksnark_processed_verification_key<ppT> pvk = r1cs_gg_ppzksnark_verifier_process_vk<ppT>(keypair.vk);
    printf("Done.");

    printf("R1CS GG-ppzkSNARK Prover");
    r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
    printf("Proof generated.");

    printf("R1CS GG-ppzkSNARK Verifier");
    const bool ans = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, pb.primary_input(), proof);
    printf("\n");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

    if (name != "") {
        std::cout << "Saving proof" << std::endl;
        std::ofstream out(name);
        out << proof;
        out.close();
    }

    return ans;
}


#endif //ZKDT_RELEASE_GROTH16_H
