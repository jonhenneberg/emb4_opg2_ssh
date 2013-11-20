////SSL-Client.c
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int OpenConnection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}
/* { initctx start }*/
SSL_CTX* InitCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = SSLv3_client_method();
    ctx = SSL_CTX_new(method);
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
/* { initctx end }*/
void usage(void)
{
	printf("Usage:\n");
	printf(" -port <name>\n");
	printf(" -ip <name>\n");
	exit (8);
}

int main(int argc, char *argv[]) {
	int server;
	SSL *ssl;
	char buf[1024];
	/* { inputdef start }*/
	char msg[1024];
	/* { inputdef end }*/
	int bytes;
	char* hostname = "127.0.0.1";
	char* portnum = "5000";
	while (argc > 1) {
		if (strcasecmp(argv[1],"-ip") == 0) {
			argv++;
			argc--;
			printf("IP Argument: %s\n", argv[1]);
			hostname = argv[1];
		} else if (strcasecmp(argv[1],"-port") == 0) {
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

	printf("Connecting to %s:%s\n",hostname,portnum);
	/* { getinput start }*/
	printf("Please enter message:\n");
	fgets(msg,sizeof(msg),stdin);
	/* { getinput end }*/

	/* { ssl_send start }*/
	SSL_library_init();
	SSL_CTX *ctx;
	ctx = InitCTX();
	server = OpenConnection(hostname, atoi(portnum));
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, server);

	if ( SSL_connect(ssl) == -1 )
		ERR_print_errors_fp(stderr);
	else {
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		SSL_write(ssl, msg, strlen(msg));
		bytes = SSL_read(ssl, buf, sizeof(buf));
		buf[bytes] = 0;
		printf("Received: \"%s\"\n", buf);
		SSL_free(ssl);
	}
	close(server);
	SSL_CTX_free(ctx);
	/* { ssl_send end }*/

	return (0);
}
