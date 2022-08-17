#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <json-c/json.h>
#define PK2_new() BN_dxy_new(2)
#define PK2_free(a) BN_dxy_free(a, 2)
#define SK2_new() BN_dxy_new(2)
#define SK2_free(a) BN_dxy_free(a, 2)
#define CT2_new() BN_dxy_new(2)
#define CT2_free(a) BN_dxy_free(a, 2)
#define PK3_new() BN_dxy_new(3)
#define PK3_free(a) BN_dxy_free(a, 3)
#define SK3_new() BN_dxy_new(3)
#define SK3_free(a) BN_dxy_free(a, 3)
#define DXY_new() BN_dxy_new(3)
#define DXY_free(a) BN_dxy_free(a, 3)
typedef unsigned char U8;
static struct sockaddr_in client_addr;
static int client_fd, n, n2, state = 1;
static char recv_data[6000];

typedef struct
{
	union{
		BIGNUM *p;
		BIGNUM *d;
		BIGNUM *N;
		BIGNUM *C0;
	};
	union{
		BIGNUM *y;
		BIGNUM *key;
		BIGNUM *C1;
	};
	union{
		BIGNUM *g;
		BIGNUM *x;
	};
}BN_dxy;
typedef BN_dxy PK;
typedef BN_dxy SK;
typedef BN_dxy CT;

BN_dxy * BN_dxy_new(int element)
{
	BN_dxy * dxy = (BN_dxy *)calloc(1, sizeof(BN_dxy));
	if(element >=1)	dxy->d = BN_new(); 
	if(element >=2)	dxy->y = BN_new();
	if(element >=3)	dxy->x = BN_new();
	return dxy;
}
void BN_dxy_free(BN_dxy * dxy, int element)
{
	if(element >=1)	BN_free(dxy->d);
	if(element >=2)	BN_free(dxy->y);
	if(element >=3)	BN_free(dxy->x);
	free(dxy);
}
void BN_Square_Multi(BIGNUM * z,BIGNUM *x, BIGNUM *a, BIGNUM *n, BN_CTX * bn_ctx)
{
///////////
	BN_one(z); // z = 1, x^a mod n
    for (int i = BN_num_bits(a)-1; i >= 0; i--){
        BN_mod_mul(z, z, z, n, bn_ctx);
        if (BN_is_bit_set(a, i) == 1){
            BN_mod_mul(z, z, x, n, bn_ctx);
        }
    }
}
void Find_safe_prime_generator(BIGNUM *g, BIGNUM *p)
{
	// p = 2*q + 1
	int i;
	BN_CTX * ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	BIGNUM * q = BN_CTX_get(ctx);
	BIGNUM * tmp = BN_CTX_get(ctx);
	BIGNUM * h[2];
	h[0] = BN_CTX_get(ctx);
	BN_set_word(g,2);
	BN_set_word(h[0],2);
	BN_copy(tmp, p);
	BN_sub_word(tmp,1);//tmp = p - 1
	BN_div(q,NULL,tmp,g,ctx);//q = (p - 1)/2
	//(p-1) = 2 * q    
	h[1] = q; 
	while(BN_cmp(g,p) != 0)
	{
		for(i=0; i<2; i++)
		{	
			BN_mod_exp(tmp, g, h[i],p,ctx);
			if(BN_is_one(tmp)) break;
		}
		if(i == 2)
			break;
		BN_add_word(g,1);
	}
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
}
void DH_setup(PK * pub, SK * priv)
{
	BN_CTX * bn_ctx = BN_CTX_new();
	BN_generate_prime_ex(pub->p,1024,1,NULL,NULL,NULL);
	//printf("Complete the select of safe prime\n");
	Find_safe_prime_generator(pub->g,pub->p);
	BN_copy(priv->p, pub->p);
	BN_copy(priv->g, pub->g);
	//printf("Complete the select of generator\n");
	BN_rand_range(priv->key,pub->p);
	BN_Square_Multi(pub->key, pub->g, priv->key, pub->p, bn_ctx);
	BN_CTX_free(bn_ctx);
}

int main(int argc, char *argv[])
{
	char *IP = argv[1];
	in_port_t PORT = atoi(argv[2]);

	if (argc != 3)
	{
		printf("Useage : ./client [IP] [PORT]\n");
		exit(0);
	}

	client_fd = socket(PF_INET, SOCK_STREAM, 0);

	client_addr.sin_addr.s_addr = inet_addr(IP);
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(PORT);

	if (connect(client_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)) == -1)
	{
		printf("Can't Connect\n");
		close(client_fd);
		return -1;
	}

	PK* pub = PK3_new();
	SK* priv = SK3_new();

	DH_setup(pub, priv);
	BN_CTX* bn_ctx = BN_CTX_new();

	/* code */
    json_object *send_obj = json_object_new_object();
	json_object_object_add(send_obj, "order", json_object_new_string("DHKEY"));
	json_object_object_add(send_obj, "P", json_object_new_string(BN_bn2hex(pub->p)));
	json_object_object_add(send_obj, "G", json_object_new_string(BN_bn2hex(pub->g)));
	json_object_object_add(send_obj, "GX", json_object_new_string(BN_bn2hex(priv->key)));
    const char *send_data = json_object_to_json_string(send_obj);
    if ((n = send(client_fd, send_data, strlen(send_data)+1, 0)) == -1) {
		printf("send fail \n");
		return 0;
	}

    json_object *token =  json_tokener_parse(recv_data);
	json_object *find1 = json_object_object_get(token, "P");
	json_object *find2 = json_object_object_get(token, "G");
	json_object *find3 = json_object_object_get(token, "GX");
	const char *P = json_object_get_string(find1);
	const char *G = json_object_get_string(find2);
	const char *GX = json_object_get_string(find3);
	BN_hex2bn(&pub->p, P); BN_hex2bn(&pub->g, G); BN_hex2bn(&priv->key, GX);
	BN_rand_range(&priv->key, p); // cl_x <- Z_p
	BN_mod_exp(key, &pub->g, GX, p, bn_ctx); // cl_GX = g^sv_x


			
	close(client_fd);
	PK3_free(pub); SK3_free(priv);
	BN_CTX_free(bn_ctx);

	return 0;
}