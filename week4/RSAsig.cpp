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



class RSAsig {
    BIGNUM *N;
    BIGNUM *e;
    BIGNUM *d;

    U8* sig;
public:
    RSAsig( ) {
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *p = BN_new(); BIGNUM *q = BN_new(); BIGNUM *phi = BN_new();
        N = BN_new(); e = BN_new(); d = BN_new();
        BN_Ext_Euclid ExtendedEuclidean = BN_Ext_Euclid( );
        BN_set_word(e, 3);

        BIGNUM *one = BN_new(); BIGNUM *tmp = BN_new(); BN_one(one);
        do {
            BN_generate_prime_ex(p, 1024, 0, NULL, NULL, NULL);
            BN_generate_prime_ex(q, 1024, 0, NULL, NULL, NULL);
            
            BN_mul(N, p, q, ctx); // N = p*q
            BN_sub(tmp, p, one); BN_sub(phi, q, one);
            BN_mul(phi, phi, tmp, ctx); // phi(N) = (p-1)(q-1)
            ExtendedEuclidean.algorithm(e, phi);
        }
        while (BN_is_one(ExtendedEuclidean.getD()) != 1);
        BN_mod(d, ExtendedEuclidean.getX(), phi, ctx);
        if(BN_is_negative(d)==1){
            BN_add(d, d, phi); // d = e^{-1} mod Phi(N)
        }

        BN_free(p);
	    BN_free(q);
        BN_free(phi);
        BN_CTX_free(ctx);
    }
    ~RSAsig( ) {
        BN_free(N);
	    BN_free(e);
	    BN_free(d);

        free(sig);
    }

    U8* getSig( ) {
        return sig;
    }
 
    int Sign(U8* msg) {
        sig = (U8*) malloc(sizeof(U8*) * 1024 * 2 / 8);

        BIGNUM *m = BN_bin2bn(msg, LENGTH, NULL);
        BIGNUM *s = BN_new();
        BIGNUM *hash = BN_new();

        U8 digest[SHA256_DIGEST_LENGTH]={0};
        SHA256(msg, strlen((char*)msg), digest);
        BN_bin2bn(digest, SHA256_DIGEST_LENGTH, hash);
        
        BN_Square_Multi(s, hash, d, N); // s = hash^d mod N
        int length = BN_bn2bin(s, sig);

        BN_free(m);
        BN_free(s); BN_free(hash);
        return length;
    }
    int Verify(U8* sig, U8* msg, int len) {
        BIGNUM *s = BN_bin2bn(sig, len, NULL);
        BIGNUM *hash_from_sig = BN_new();
        BIGNUM *hash_from_msg = BN_new();

        BN_Square_Multi(hash_from_sig, s, e, N); // h' = s^e mod N
        U8 digest[SHA256_DIGEST_LENGTH] = {0};
        SHA256(msg, strlen((char*)msg), digest);
        BN_bin2bn(digest, SHA256_DIGEST_LENGTH, hash_from_msg);

        if (BN_cmp(hash_from_sig, hash_from_msg)==0){
            return 1;
        }
        else return 0;

        if(BN_cmp(hash_from_sig, hash_from_msg) == 0) {
            BN_free(s);
            BN_free(hash_from_sig); BN_free(hash_from_msg);
            return 1;
        } else {
            BN_free(s);
            BN_free(hash_from_sig); BN_free(hash_from_msg);
            return 0;
        }
    }   
};

int main(){
    U8 msg[LENGTH] = "hello";
    int len;
    RSAsig rsaSig = RSAsig();

    cout << "msg\t: " << msg << endl;

    len = rsaSig.Sign(msg);
    U8* sig = rsaSig.getSig();

    cout << "signature\t: ";
    for(int i=0; i<len; i++) {
        cout << setfill('0') << setw(2) << right << hex << (uint)sig[i];
    }
    cout << endl;

    int result = rsaSig.Verify(sig, msg, len);
    if(result == 1) cout << "Verify Success" << endl;
    else cout << "Verify Fail" << endl;

    return 0;
}