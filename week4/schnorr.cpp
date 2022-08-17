#include <iostream>
#include <string>
#include <openssl/bn.h>
#include <malloc.h>
#include <random>
#include <iomanip>
#include <openssl/sha.h>
#include <cstring>

#define LENGTH 6
using namespace std;

typedef unsigned char U8;
typedef unsigned int U32;

void BN_Square_Multi(BIGNUM *z, BIGNUM *x, BIGNUM *a, BIGNUM *n) {
    BN_CTX *ctx = BN_CTX_new();

    BN_one(z);

    BIGNUM *temp = BN_new();
    BN_zero(temp);
    if( BN_cmp(a, temp) == 0 ) {
        BN_free(temp);
        return;
    }

    int length = BN_num_bits( a );
    BN_copy(temp, x);
    if( BN_is_bit_set( a, 0 ) ) {
        BN_copy(z, temp);
    }

    for( int i = 1; i < length; i++ ) {
        BN_mod_mul(temp, temp, temp, n, ctx);
        if( BN_is_bit_set( a, i ) ) {
            BN_mod_mul(z, z, temp, n, ctx);
        }
    }

    BN_free(temp);
    BN_CTX_free(ctx);
}
void Find_safe_prime_generator(BIGNUM *g, BIGNUM *p) {
    // p = 2*q + 1
    int i;
    BN_CTX * ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM * q = BN_CTX_get(ctx);
    BIGNUM * tmp = BN_CTX_get(ctx);
    BIGNUM * h[2];
    h[0] = BN_CTX_get(ctx);
    BN_set_word(g, 2);
    BN_set_word(h[0], 2);
    BN_copy(tmp, p);
    BN_sub_word(tmp, 1);//tmp = p - 1
    BN_div(q, NULL, tmp, g, ctx);//q = (p - 1)/2
    //(p-1) = 2 * q    
    h[1] = q;
    while (BN_cmp(g, p) != 0)
    {
        for (i = 0; i < 2; i++)
        {
            BN_mod_exp(tmp, g, h[i], p, ctx);
            if (BN_is_one(tmp)) break;
        }
        if (i == 2)
            break;
        BN_add_word(g, 1);
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}
class BN_Ext_Euclid {
    BIGNUM *d;
    BIGNUM *x;
    BIGNUM *y;
public:
    BN_Ext_Euclid( ){
        this->d = BN_new(); this->x = BN_new(); this->y = BN_new();
    }
    ~BN_Ext_Euclid( ) {
        BN_free(d);
        BN_free(x);
        BN_free(y);
    }
    BIGNUM* getD( ) {
        return d;
    }
    BIGNUM* getX( ) {
        return x;
    }
    BIGNUM* getY( ) {
        return y;
    }

    void algorithm(BIGNUM *olda, BIGNUM *oldb) {
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BN_copy(a, olda);
        BN_copy(b, oldb);
        BN_CTX *ctx = BN_CTX_new();
        if( BN_is_zero(b) ) {
            BN_copy(d, a);
            BN_one(x);
            BN_zero(y);
        }
        else { 
            BIGNUM *x1 = BN_new();     BN_zero(x1);
            BIGNUM *x2 = BN_new();     BN_one(x2);
            BIGNUM *y1 = BN_new();     BN_one(y1);
            BIGNUM *y2 = BN_new();     BN_zero(y2);
            BIGNUM *zero = BN_new();   BN_zero(zero);

            BIGNUM *q = BN_new();
            BIGNUM *r = BN_new();
            BIGNUM *qx1 = BN_new();
            BIGNUM *qy1 = BN_new();


            while( BN_cmp(b, zero) == 1 ) {
                BN_div(q, r, a, b, ctx);
                BN_mul(qx1, q, x1, ctx);
                BN_sub(x, x2, qx1);
                BN_mul(qy1, q, y1, ctx);
                BN_sub(y, y2, qy1);

                BN_copy(a, b);
                BN_copy(b, r);
                BN_copy(x2, x1);
                BN_copy(x1, x);
                BN_copy(y2, y1);
                BN_copy(y1, y);
            }
            BN_copy(d, a);
            BN_copy(x, x2);
            BN_copy(y, y2);

            BN_free(x1);
            BN_free(x2);
            BN_free(y1);
            BN_free(y2);
            BN_free(zero);
            BN_free(q);
            BN_free(r);
            BN_free(qx1);
            BN_free(qy1);
        }
        BN_CTX_free(ctx);
    }
};



class Schnorr {
    BIGNUM *p;
    BIGNUM *g;
    BIGNUM *x;
    BIGNUM *y;

    U8** sig;

    int len1;
    int len2;
public:
    Schnorr( ) {
        p = BN_new(); g = BN_new(); x = BN_new(); y = BN_new();
        BN_generate_prime_ex(p, 1024, 1, NULL, NULL, NULL);
        cout << "Complete the select of safe prime" << endl;
        Find_safe_prime_generator(g, p);
        cout << "Complete the select of generator" << endl;
        BN_rand_range(x, p);
        BN_Square_Multi(y, g, x, p);
    }
    ~Schnorr( ) {
        BN_free(p);
	    BN_free(g);
	    BN_free(x);
	    BN_free(y);

        free(sig[0]);
        free(sig[1]);
        free(sig);
    }

    U8** getSig( ) {
        return sig;
    }
    int getLen1( ) {
        return len1;
    }
    int getLen2( ) {
        return len2;
    }
 
    void Sign(U8* msg) {
        BN_CTX *ctx = BN_CTX_new();
        sig = (U8**) malloc(sizeof(U8*) * 2);
        for(int i=0; i<2; i++) sig[i] = (U8*) malloc(sizeof(U8) * 1024);

        BIGNUM *r = BN_new(); BIGNUM *R = BN_new(); BIGNUM *tmp = BN_new();
        BIGNUM *c = BN_new(); BIGNUM *z = BN_new(); BIGNUM *p_sub = BN_new();
        
        // TODO START   //////////////////////////////////////////////////////////////////////////////
        BN_rand_range(r, p); // r = random value in Zp group
        BN_Square_Multi(R, g, r, p); // R = g^r mod p

        U8 digest[SHA256_DIGEST_LENGTH] = {0};
        U8 *r_ = (U8*) calloc(BN_num_bytes(R), sizeof(U8));
        SHA256_CTX hs = {0};
        SHA256_Init(&hs);
        BN_bn2bin(R,r_);
        SHA256_Update(&hs, msg, strlen((char*)msg));
        SHA256_Update(&hs, r_, BN_num_bytes(R));
        SHA256_Final(digest, &hs);
        BN_bin2bn(digest, SHA256_DIGEST_LENGTH, c); // c = H(m||R)
        
        BN_sub(p_sub, p, BN_value_one());
        BN_mul(tmp, x, digest, ctx); // xc
        // BN_mod_add(z, , tmp, p_sub); // z = (r + xc) mod p-1
        // TODO END     //////////////////////////////////////////////////////////////////////////////

        len1 = BN_bn2bin(c, sig[0]);
        len2 = BN_bn2bin(z, sig[1]);

        BN_free(r); BN_free(R);
        BN_free(c); BN_free(z);
        BN_CTX_free(ctx);
    }
    int Verify(U8** sig, U8* msg) {
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *c0 = BN_bin2bn(sig[0], len1, NULL);
        BIGNUM *c1 = BN_bin2bn(sig[1], len2, NULL);

        BIGNUM *g_exp_c1 = BN_new();
        BIGNUM *y_exp_c0 = BN_new(); BIGNUM *y_exp_c0_inv = BN_new();
        BIGNUM *R_prime = BN_new();

        BIGNUM *c_prime = BN_new();

        BN_Ext_Euclid ExtendedEuclidean = BN_Ext_Euclid();
        // TODO START   //////////////////////////////////////////////////////////////////////////////
        BIGNUM *g_z = BN_NEW(); BIGNUM *y_c = BN_NEW(); 
        BN_Square_Multi(g_exp_c1, g, z, p);// g^z
        BN_Square_Multi(y_exp_c0, y, c, p);// y^c
        do {ExtendedEuclidean.algorithm(y_exp_c0, p);}
        while (BN_is_one(ExtendedEuclidean.getD()) != 1);
        BN_copy(y_exp_c0_inv, ExtendedEuclidean.getX()); // (y^c)'s inverse
        BN_mul(R_prime, g_exp_c1, y_exp_c0_inv, ctx);// R' = (g^z) * inv(y^c)

        U8 digest[SHA256_DIGEST_LENGTH] = {0};
        U8 *r_prime_ = (U8*) calloc(BN_num_bytes(R), sizeof(U8));
        SHA256_CTX hs = {0};
        SHA256_Init(&hs);
        BN_bn2bin(R_prime,r_prime_);
        SHA256_Update(&hs, msg, strlen((char*)msg));
        SHA256_Update(&hs, r_prime_, BN_num_bytes(R));
        SHA256_Final(digest, &hs);
        BN_bin2bn(digest, SHA256_DIGEST_LENGTH, c); // c' = H(m||R')
        // TODO END     //////////////////////////////////////////////////////////////////////////////

        if(BN_cmp(c0, c_prime) == 0) {
            BN_free(c0); BN_free(c1);
            BN_free(g_exp_c1);
            BN_free(y_exp_c0); BN_free(y_exp_c0_inv);
            BN_free(R_prime);
            BN_free(c_prime);
            BN_CTX_free(ctx);
            return 1;
        } else {
            BN_free(c0); BN_free(c1);
            BN_free(g_exp_c1);
            BN_free(y_exp_c0); BN_free(y_exp_c0_inv);
            BN_free(R_prime);
            BN_free(c_prime);
            BN_CTX_free(ctx);
            return 0;
        }
    }   
};

int main(){
    U8 msg[LENGTH] = "hello";
    int len;
    Schnorr schnorr = Schnorr();

    cout << "msg\t: " << msg << endl;

    schnorr.Sign(msg);
    U8** sig = schnorr.getSig();

    cout << "C1\t: ";
    for(int i=0; i<schnorr.getLen1( ); i++) {
        cout << setfill('0') << setw(2) << right << hex << (uint)sig[0][i];
    }
    cout << endl << "C2\t: ";
    for(int i=0; i<schnorr.getLen2( ); i++) {
        cout << setfill('0') << setw(2) << right << hex << (uint)sig[1][i];
    }
    cout << endl;

    int result = schnorr.Verify(sig, msg);
    if(result == 1) cout << "Verify Success" << endl;
    else cout << "Verify Fail" << endl;

    return 0;
}