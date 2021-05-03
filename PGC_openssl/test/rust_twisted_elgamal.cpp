#include "../depends/twisted_elgamal/rust_twisted_elgamal.hpp"

extern "C"{
    void Rust_global_initialize(){
        global_initialize(NID_secp256k1);
    }
}

extern "C"{
    Twisted_ElGamal_PP *Rust_Twisted_ElGamal_PP_new(){
        return Twisted_ElGamal_PP_new();
    }
}

extern "C"{
    void Rust_Twisted_ElGamal_PP_SetUp_Init(Twisted_ElGamal_PP *pp){
        SplitLine_print('-'); 
        //cout << "begin the basic correctness test >>>" << endl;     
        size_t MSG_LEN = 32; 
        size_t TUNNING = 7; 
        size_t DEC_THREAD_NUM = 4;
        size_t IO_THREAD_NUM = 4;      
        Twisted_ElGamal_Setup(pp, MSG_LEN, TUNNING, DEC_THREAD_NUM, IO_THREAD_NUM);
        Twisted_ElGamal_Initialize(*pp);
    }
}

extern "C"{
    void Rust_Twisted_ElGamal_PP_KeyGen(Twisted_ElGamal_PP *pp, EC_POINT* pk, BIGNUM* sk){
        Twisted_ElGamal_KP keypair;
        Twisted_ElGamal_KP_new(keypair); 
        Twisted_ElGamal_KeyGen(*pp, keypair);
        EC_POINT_copy(pk, keypair.pk);
        BN_copy(sk, keypair.sk);
        Twisted_ElGamal_KP_free(keypair);
    }
}

extern "C" {
    void Rust_Twisted_ElGamal_Enc(Twisted_ElGamal_PP *pp, EC_POINT* pk, BIGNUM *m, BIGNUM *beta_ret, EC_POINT* X, EC_POINT* Y)
    {
        Twisted_ElGamal_CT CT; 
        Twisted_ElGamal_CT_new(CT); 

        //BIGNUM *m = BN_new(); 
        //BIGNUM *m_prime = BN_new();

        /* random test */ 
        SplitLine_print('-'); 
        //cout << "begin the random test >>>" << endl; 
        //BN_random(m); 
        BN_mod(m, m, pp->BN_MSG_SIZE, bn_ctx);
        BN_print(m, "m"); 
        BIGNUM *beta = BN_new(); 
        BN_random(beta);
        BN_print(beta, "beta");
        Twisted_ElGamal_Enc(pp, pk, m, beta, CT);
        BN_copy(beta_ret, beta); 

        //EC_POINT_copy(pk_ret, keypair.pk);
        EC_POINT_copy(X, CT.X);
        EC_POINT_copy(Y, CT.Y);
        //Twisted_ElGamal_Parallel_Dec(pp, keypair.sk, CT, m_prime); 
        
        Twisted_ElGamal_CT_free(CT); 
         
    }
}

extern "C"{
    void Rust_Twisted_ElGamal_Parallel_Dec(Twisted_ElGamal_PP *pp, EC_POINT* X, EC_POINT* Y, BIGNUM* sk, BIGNUM* recovery_m){
        Twisted_ElGamal_CT CT; 
        Twisted_ElGamal_CT_new(CT); 
        SplitLine_print('-');
        EC_POINT_copy(CT.X, X);
        EC_POINT_copy(CT.Y, Y);
        Twisted_ElGamal_Parallel_Dec(*pp, sk, CT, recovery_m); 
        BN_print(recovery_m, "recovery_m");
        
        Twisted_ElGamal_CT_free(CT); 
    }
}

extern "C"{
    void Rust_Twisted_ElGamal_HomoAdd(
        Twisted_ElGamal_PP *pp, 
        EC_POINT* X1,
        EC_POINT* Y1, 
        EC_POINT* X2,
        EC_POINT* Y2,
        EC_POINT* X_ret,
        EC_POINT* Y_ret
    ){
        Twisted_ElGamal_CT CT1; 
        Twisted_ElGamal_CT_new(CT1); 
        //SplitLine_print('-');
        EC_POINT_copy(CT1.X, X1);
        EC_POINT_copy(CT1.Y, Y1);

        Twisted_ElGamal_CT CT2; 
        Twisted_ElGamal_CT_new(CT2);

        EC_POINT_copy(CT2.X, X2);
        EC_POINT_copy(CT2.Y, Y2);

        Twisted_ElGamal_CT CT_ret; 
        Twisted_ElGamal_CT_new(CT_ret);

        Twisted_ElGamal_HomoAdd(CT_ret, CT1, CT2);
        EC_POINT_copy(X_ret, CT_ret.X);
        EC_POINT_copy(Y_ret, CT_ret.Y);
        
        Twisted_ElGamal_CT_free(CT1);
        Twisted_ElGamal_CT_free(CT2); 
        Twisted_ElGamal_CT_free(CT_ret);
    }
}

extern "C"{
    void Rust_Twisted_ElGamal_HomoSub(
        Twisted_ElGamal_PP *pp, 
        EC_POINT* X1,
        EC_POINT* Y1, 
        EC_POINT* X2,
        EC_POINT* Y2,
        EC_POINT* X_ret,
        EC_POINT* Y_ret
    ){
        Twisted_ElGamal_CT CT1; 
        Twisted_ElGamal_CT_new(CT1); 
        //SplitLine_print('-');
        EC_POINT_copy(CT1.X, X1);
        EC_POINT_copy(CT1.Y, Y1);

        Twisted_ElGamal_CT CT2; 
        Twisted_ElGamal_CT_new(CT2);

        EC_POINT_copy(CT2.X, X2);
        EC_POINT_copy(CT2.Y, Y2);

        Twisted_ElGamal_CT CT_ret; 
        Twisted_ElGamal_CT_new(CT_ret);

        Twisted_ElGamal_HomoSub(CT_ret, CT1, CT2);
        EC_POINT_copy(X_ret, CT_ret.X);
        EC_POINT_copy(Y_ret, CT_ret.Y);
        
        Twisted_ElGamal_CT_free(CT1);
        Twisted_ElGamal_CT_free(CT2); 
        Twisted_ElGamal_CT_free(CT_ret);
    }
}

extern "C"{
    void Rust_Twisted_ElGamal_PP_free(Twisted_ElGamal_PP *pp){
        Twisted_ElGamal_PP_free(pp);
    }
}

extern "C"{
    void Rust_global_finalize(){
        global_finalize();
    }
}

/*
int main()
{  
    // curve id = NID_secp256k1
    Rust_global_initialize();    
    // global_initialize(NID_secp256k1); 
    EC_POINT *pk = EC_POINT_new(group);
    BIGNUM *sk = BN_new();
    Rust_Twisted_ElGamal_Enc(pk, sk);
    Rust_global_finalize();
    
    return 0; 
}*/
