#define DEBUG

#include "../depends/twisted_elgamal/twisted_elgamal.hpp"
#include "../depends/bulletproofs/aggregate_bulletproof.hpp"
#include "../depends/sigma/sigma_proof.hpp"
#include "../depends/signiture/signiture.hpp"

void generate_random_instance_witness(Bullet_PP &pp, 
                                      Bullet_Instance &instance, 
                                      Bullet_Witness &witness,
                                      BIGNUM* &m,
                                      BIGNUM* &beta, 
                                      bool STATEMENT_FLAG)
{
    if(STATEMENT_FLAG == true) cout << "generate a true statement pair" << endl; 
    else cout << "generate a random statement (false with overwhelming probability)" << endl; 
    BIGNUM *exp = BN_new(); 
    BN_set_word(exp, pp.RANGE_LEN);

    BIGNUM *BN_range_size = BN_new(); 
    BN_mod_exp(BN_range_size, BN_2, exp, order, bn_ctx); 
    cout << "range = [" << 0 << "," << BN_bn2hex(BN_range_size) <<")"<<endl; 
    for(auto i = 0; i < pp.AGG_NUM; i++)
    {
        BN_copy(witness.r[i], beta);
        BN_copy(witness.v[i], m); 
        BN_print(witness.r[i], "witness.r");
        BN_print(witness.v[i], "witness.v");
        if (STATEMENT_FLAG == true){
            BN_mod(witness.v[i], witness.v[i], BN_range_size, bn_ctx);  
        }
        EC_POINT_mul(group, instance.C[i], witness.r[i], pp.h, witness.v[i], bn_ctx); 
    }
    cout << "random instance generation finished" << endl; 
}

void generate_sigma_random_instance_witness(Sigma_PP &pp, 
                                Sigma_Instance &instance, 
                                Sigma_Witness &witness, 
                                BIGNUM* &m,
                                BIGNUM* &beta,
                                Twisted_ElGamal_CT &CT,
                                EC_POINT* &pk,
                                EC_POINT* &R,
                                EC_POINT* &A,
                                bool flag)
{
    SplitLine_print('-');  

    witness.r = beta;
    witness.v = m; 

    EC_POINT_copy(instance.twited_ek, pk);
    EC_POINT_copy(instance.R, R);
    EC_POINT_copy(instance.A, A);
    
    EC_POINT_copy(instance.U, CT.Y); 
    EC_POINT_copy(instance.V, CT.X);  
}

void test_escrow_protocol()
{
    SplitLine_print('-'); 

    Signiture_PP signiture;
    Signiture_PP_new(signiture);    
    Signiture_Setup(signiture);
    Signiture_Instance signiture_instance; 
    Signiture_Instance_new(signiture_instance);
    Signiture_Result signiture_result;
    Signiture_Result_new(signiture_result);

    cout << "generate the random message m >>>" << endl;
    BIGNUM *m = BN_new(); 
    BN_random(m); 
    BN_print(m, "m");

    cout << "generate the signiture key pair >>>" << endl;
    Signiture_KeyGen(signiture, signiture_instance);

    cout << "generate the signiture of m >>>" << endl;
    Signiture_Sign(signiture, signiture_instance, m, signiture_result);
    Signiture_Verify(signiture, signiture_instance, m, signiture_result);

    cout << "begin the twisted elgamal encryption >>>" << endl;  
    Twisted_ElGamal_PP pp_tt; 
    Twisted_ElGamal_PP_new(pp_tt);
    size_t MSG_LEN = 32; 
    size_t TUNNING = 7; 
    size_t DEC_THREAD_NUM = 4;
    size_t IO_THREAD_NUM = 4;      
    Twisted_ElGamal_Setup(pp_tt, MSG_LEN, TUNNING, DEC_THREAD_NUM, IO_THREAD_NUM);
    Twisted_ElGamal_Initialize(pp_tt); 

    Twisted_ElGamal_KP keypair;
    Twisted_ElGamal_KP_new(keypair); 
    Twisted_ElGamal_KeyGen(pp_tt, keypair); 

    Twisted_ElGamal_CT CT; 
    Twisted_ElGamal_CT_new(CT); 

   
    BIGNUM *m_prime = BN_new();

    /* explict random r */
    SplitLine_print('-'); 
    cout << "begin the explict random r >>>" << endl; 
    
    //BN_mod(signiture_result.s, signiture_result.s, pp_tt.BN_MSG_SIZE, bn_ctx);
    BN_print(signiture_result.s, "signiture_result.s"); 
    BIGNUM *beta = BN_new(); 
    BN_random(beta);
    BN_print(beta, "beta");
    Twisted_ElGamal_Enc(pp_tt, keypair.pk, signiture_result.s, beta, CT);
    //Twisted_ElGamal_Parallel_Dec(pp_tt, keypair.sk, CT, m_prime); 
    //BN_print(m_prime, "signiture_result.s'");

      
    size_t RANGE_LEN = 32; // range size
    size_t AGG_NUM = 1;
    Bullet_PP pp; 
    Bullet_PP_new(pp, RANGE_LEN, AGG_NUM);  
    Bullet_Setup(pp, RANGE_LEN, AGG_NUM);

    Bullet_Instance instance; 
    Bullet_Witness witness; 
    Bullet_Proof proof; 

    Bullet_Instance_new(pp, instance); 
    Bullet_Witness_new(pp, witness); 
    Bullet_Proof_new(proof); 

    
    
    auto start_time = chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Bullet_Prove(pp, instance, witness, transcript_str, proof);
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "proof generation takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    start_time = chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Bullet_Verify(pp, instance, transcript_str, proof);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "proof verification takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    

    Sigma_PP sigma;
    Sigma_PP_new(sigma);    
    Sigma_Setup(sigma, pp_tt.h);
    Sigma_Instance sigma_instance; 
    Sigma_Instance_new(sigma_instance); 
    Sigma_Witness sigma_witness; 
    Sigma_Witness_new(sigma_witness); 
    Sigma_Proof sigma_proof; 
    Sigma_Proof_new(sigma_proof); 


    generate_random_instance_witness(pp, instance, witness, signiture_result.s, beta, true); 
    
    string transcript_str; 
    
    string sigma_transcript_str; 
    
    generate_sigma_random_instance_witness(sigma, sigma_instance, sigma_witness, signiture_result.s, beta, CT, keypair.pk, signiture_result.R, signiture_result.A, true); 
    auto sigma_start_time = chrono::steady_clock::now(); // start to count the time

    cout << "generate the bullet proof >>>" << endl;
    
    transcript_str = ""; 
    Bullet_Prove(pp, instance, witness, transcript_str, proof);

    cout << "generate the sigma proof >>>" << endl; 
    sigma_transcript_str = ""; 
    Sigma_Prove(sigma, sigma_instance, sigma_witness, sigma_transcript_str, sigma_proof); 

    auto sigma_end_time = chrono::steady_clock::now(); // end to count the time
    auto sigma_running_time = sigma_end_time - sigma_start_time;
    cout << "proof generation takes time = " 
    << chrono::duration <double, milli> (sigma_running_time).count() << " ms" << endl;

    sigma_start_time = chrono::steady_clock::now(); // start to count the time
    sigma_transcript_str = ""; 
    Sigma_Verify(sigma, sigma_instance, sigma_transcript_str, sigma_proof);
    sigma_end_time = chrono::steady_clock::now(); // end to count the time
    sigma_running_time = sigma_end_time - sigma_start_time;
    cout << "proof verification takes time = " 
    << chrono::duration <double, milli> (sigma_running_time).count() << " ms" << endl;

    Signiture_PP_free(signiture);
    Signiture_Instance_free(signiture_instance);
    Signiture_Result_free(signiture_result);

    Sigma_PP_free(sigma); 
    Sigma_Instance_free(sigma_instance);
    //Sigma_Witness_free(sigma_witness);
    Sigma_Proof_free(sigma_proof); 
    
    Twisted_ElGamal_PP_free(pp_tt); 
    Twisted_ElGamal_KP_free(keypair); 
    Twisted_ElGamal_CT_free(CT); 
    //BN_free(pp_tt.BN_MSG_SIZE); 

    Bullet_PP_free(pp); 
    Bullet_Instance_free(instance); 
    Bullet_Witness_free(witness); 
    Bullet_Proof_free(proof); 

    BN_free(m);
    BN_free(m_prime); 
    BN_free(beta);
}


int main()
{  
    // curve id = NID_secp256k1
    global_initialize(NID_secp256k1);    
    // global_initialize(NID_secp256k1); 
    test_escrow_protocol();
    global_finalize();
    
    return 0; 
}



