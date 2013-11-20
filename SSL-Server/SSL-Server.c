//SSL-Server.c
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

int OpenListener(int port) {
	int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		perror("can't bind port");
		abort();
	}
	if ( listen(sd, 10) != 0 )
	{
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}

SSL_CTX* InitServerCTX(void) {
	SSL_METHOD *method;
	SSL_CTX *ctx;
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	method = SSLv3_server_method();
	ctx = SSL_CTX_new(method);
	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}
/* { LoadCertificates start }*/
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {

	if (SSL_CTX_load_verify_locations(ctx, CertFile, KeyFile) != 1)
		ERR_print_errors_fp(stderr);

	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
		ERR_print_errors_fp(stderr);

	/* set the local certificate from CertFile */
	if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* verify private key */
	if (!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
}
/* { LoadCertificates end }*/

int main(int argc, char *argv[]) {
	SSL_CTX *ctx;
	int server;
	char* portnum = "5000";
	while (argc > 1) {
		if (strcasecmp(argv[1],"-port") == 0) {
			argv++;
			argc--;
			printf("Port Argument: %s\n", argv[1]);
			portnum = argv[1];
		} else {
			printf("Wrong Argument: %s\n", argv[1]);
		}
		argv++;
		argc--;
	}

	char CertFile[] = "mycert.pem";
	char KeyFile[] = "mycert.pem";

	SSL_library_init();

	printf("Starting server on port %s\n",portnum);

	ctx = InitServerCTX();
	LoadCertificates(ctx, CertFile, KeyFile);
	server = OpenListener(atoi(portnum));
	while (1)
	{
		char buf[1024];
		int bytes;
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);
		SSL *ssl;
/* { ReadMessage start }*/
		int client = accept(server, (struct sockaddr*)&addr, &len);
		printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);
		if ( SSL_accept(ssl) == -1 )
			ERR_print_errors_fp(stderr);
		else
		{
			bytes = SSL_read(ssl, buf, sizeof(buf));
			if ( bytes > 0 )
			{
				buf[bytes] = 0;
				printf("Client msg: \"%s\"\n", buf);
				SSL_write(ssl, buf, bytes);
			}
			else
				ERR_print_errors_fp(stderr);
		}
/* { ReadMessage end }*/
	}
	close(server);
	SSL_CTX_free(ctx);
}
