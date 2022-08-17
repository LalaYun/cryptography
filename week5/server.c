#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <json-c/json.h>

static struct sockaddr_in server_addr, client_addr;
static int server_fd, client_fd, n, n2;
static char recv_data[6000];
static char chat_data[6000];

int main(int argc, char *argv[]) {
	int len;
	char temp[20];
	BIGNUM *sv_x = BN_new();
	BIGNUM *p = BN_new();
	BIGNUM *g = BN_new();
	BIGNUM *gx = BN_new();
	BIGNUM *key = BN_new();
	BN_CTX *ctx = BN_CTX_new();

	if (argc != 2) {
		printf("Usage:%s <port>\n", argv[0]);
		exit(1);
	}

	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		printf("Server can not open socket\n");
		exit(0);
	}

	memset(&server_addr, 0, sizeof(server_addr));

	server_addr.sin_family = AF_INET;

	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	server_addr.sin_port = htons(atoi(argv[1]));

	if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		printf("Server can not bind local address\n");
		exit(0);
	}

	if (listen(server_fd, 5) < 0) {
		printf("Server can not listen connect\n");
		exit(0);
	}

	memset(recv_data, 0, sizeof(recv_data));
	len = sizeof(client_addr);
	printf("===[PORT] : %s=====\n", argv[0]);
	printf("Server waiting connection request\n");



	client_fd = accept(server_fd, (struct sockaddr *)&client_addr, (socklen_t *)&len);

	if (client_fd < 0) {
		printf("Server accept failed\n");
		exit(0);
	}

	inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, temp, sizeof(temp));
	printf("%s client connect\n", temp);

	printf("\n%s(%d) entered\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

	memset(recv_data, 0, sizeof(recv_data));
	if ((n = recv(client_fd, recv_data, sizeof(recv_data), 0)) == -1){
		printf("recv error\n");
		return 0;
	}
	printf("recv data : %s\n", recv_data);

	memset(recv_data, 0, sizeof(recv_data));
	if ((n = recv(client_fd, recv_data, sizeof(recv_data), 0)) == -1){
		printf("recv error\n");
		return 0;
	}
	
	json_object *token =  json_tokener_parse(recv_data);
	json_object *find1 = json_object_object_get(token, "P");
	json_object *find2 = json_object_object_get(token, "G");
	json_object *find3 = json_object_object_get(token, "GX");
	const char *P = json_object_get_string(find1);
	const char *G = json_object_get_string(find2);
	const char *GX = json_object_get_string(find3);
	BN_hex2bn(&p, P); BN_hex2bn(&g, G); BN_hex2bn(&gx, GX);
	BN_rand_range(sv_x, p); // sv_x <- Z_p
	BN_mod_exp(key, g, sv_x, p, ctx); // sv_GX = g^sv_x

	json_object *send_obj = json_object_new_object();
	json_object_object_add(send_obj, "order", json_object_new_string("DHKEY"));
	json_object_object_add(send_obj, "P", json_object_new_string(BN_bn2hex(p)));
	json_object_object_add(send_obj, "G", json_object_new_string(BN_bn2hex(g)));
	json_object_object_add(send_obj, "GX", json_object_new_string(BN_bn2hex(key)));
	const char *send_data = json_object_to_json_string(send_obj);
	printf("sended : %s\n", send_data);

	if ((n = send(client_fd, send_data, strlen(send_data)+1, 0)) == -1) {
		printf("send fail \n");
		return 0;
	}
	BN_mod_exp(key, gx, sv_x, p, ctx);
	printf("DH key exchange result : %s\n", BN_bn2hex(key));

	BN_CTX_free(ctx); 
	BN_free(sv_x); BN_free(p); BN_free(g); BN_free(gx); BN_free(key);
	close(client_fd);

	close(server_fd);

	return 0;
}