#include <iostream>
#include <string>
#include <openssl/bn.h>
#include <malloc.h>
#include <random>
#include <iomanip>

#define LENGTH 16

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



class Elgamal {
    BIGNUM *d;
    BIGNUM *x;
    BIGNUM *y;

	BIGNUM *priv;

    U8** cipher;
    U8* msg;

    int len1;
    int len2;
    int len3;
public:
    Elgamal( ) {
        d = BN_new(); x = BN_new(); y = BN_new();
        priv = BN_new();
        //Setup 
        BN_generate_prime_ex(d, LENGTH * 8, 1, NULL, NULL, NULL); //1024
        cout << "Complete the select of safe prime" << endl;
        Find_safe_prime_generator(x, d);
        cout << "Complete the select of generator" << endl;
        BN_rand_range(priv, d);
        BN_Square_Multi(y, x, priv, d);
        cout << "d\t: " << BN_bn2hex(d) << "\t" << BN_bn2dec(d) << "\n";
        cout << "x\t: " << BN_bn2hex(x) << "\t" << BN_bn2dec(x) << "\n";
        cout << "priv\t: " << BN_bn2hex(priv) << "\t" << BN_bn2dec(priv) << "\n";
        cout << "y\t: " << BN_bn2hex(y) << "\t" << BN_bn2dec(y) << "\n";
    }
    ~Elgamal( ) {
        BN_free(d);
	    BN_free(x);
	    BN_free(y);
        BN_free(priv);

        free(cipher[0]);
        free(cipher[1]);
        free(cipher);
        free(msg);
    }

    U8** getCipher( ) {
        return cipher;
    }
    U8* getMsg( ) {
        return msg;
    }
    int getLen1( ) {
        return len1;
    }
    int getLen2( ) {
        return len2;
    }
    int getLen3( ) {
        return len3;
    }

    void Enc(U8* msg) {
        BN_CTX *ctx = BN_CTX_new();
        cipher = (U8**)malloc(sizeof(U8*) * 2);
        for(int i = 0; i < 2; i++)
            cipher[i] = (U8 *)malloc(LENGTH * sizeof(U8));

        BIGNUM *r = BN_new();
        BIGNUM *m = BN_bin2bn(msg, LENGTH, NULL);
        BIGNUM *c0 = BN_new();
        BIGNUM *c1 = BN_new();
        BIGNUM *tmp = BN_new();

        cout << "msg\t: " << BN_bn2hex(m) << "\t" << BN_bn2dec(m) << "\n";
        cout << endl;
        // TODO START   //////////////////////////////////////////////////////////////////////////////

        BN_rand_range(r, d);
        BN_Square_Multi(c0, x, r, d);
        BN_Square_Multi(tmp, y, r, d); BN_mod_mul(c1, tmp, m, d, ctx);

        // TODO END     //////////////////////////////////////////////////////////////////////////////

        len1 = BN_bn2bin(c0, cipher[0]);
        len2 = BN_bn2bin(c1, cipher[1]);

        BN_free(r);
        BN_free(m);
        BN_free(c0);
        BN_free(c1);
        BN_CTX_free(ctx);
    }
    void Dec( U8** cipher ) {
        BN_CTX *ctx = BN_CTX_new();
	    msg = (U8*)malloc(LENGTH * sizeof(U8));

        BIGNUM *c0 = BN_bin2bn(cipher[0], len1, NULL);
        BIGNUM *c1 = BN_bin2bn(cipher[1], len2, NULL);

        BIGNUM *c0_exp_priv = BN_new();
        BIGNUM *inv = BN_new();
        BIGNUM *result = BN_new();

        BN_Ext_Euclid ExtendedEuclidean = BN_Ext_Euclid( );
        // TODO START   //////////////////////////////////////////////////////////////////////////////

        BN_Square_Multi(c0_exp_priv, c0, priv, d);
        ExtendedEuclidean.algorithm(d, c0_exp_priv);
        BN_copy(inv, ExtendedEuclidean.getY());

        // TODO END     //////////////////////////////////////////////////////////////////////////////
        BN_mod_mul(result, c1, inv, d, ctx);
        len3 = BN_bn2bin(result, msg);

        BN_free(c0);
        BN_free(c1);
        BN_free(c0_exp_priv);
        BN_free(inv);
        BN_free(result);
        BN_CTX_free(ctx);
    }   
};
int main(){
    U8 msg[LENGTH] = "HELLOWORLD";
    Elgamal CLASS_Elgamal = Elgamal( );

    cout << "msg\t: " << msg << endl;

    CLASS_Elgamal.Enc( msg );
    U8** cipher = CLASS_Elgamal.getCipher( );

    cout << "C1\t: ";
    for(int i=0; i<CLASS_Elgamal.getLen1( ); i++) {
        cout << setfill('0') << setw(2) << right << hex << (uint)cipher[0][i];
    }
    cout << endl << "C2\t: ";
    for(int i=0; i<CLASS_Elgamal.getLen2( ); i++) {
        cout << setfill('0') << setw(2) << right << hex << (uint)cipher[1][i];
    }

    CLASS_Elgamal.Dec( cipher );
    U8* dec = CLASS_Elgamal.getMsg( );
    cout << endl << "Dec\t: ";
    for(int i=0; i<CLASS_Elgamal.getLen3( ); i++)
        cout << dec[i];
    cout << endl;

    return 0;
}