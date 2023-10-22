/*
 * Title:  socks5 server v2 (nginx filter module)
 * Author: Shuichiro Endo
 */

//#define _DEBUG

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdio.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "socks5.h"
#include "ngx_http_socks5_module.h"
#include "serverkey.h"

#define BUFFER_SIZE 8192

#define HTTP_REQUEST_HEADER_SOCKS5_KEY "socks5"
#define HTTP_REQUEST_HEADER_SOCKS5_VALUE "socks5"
#define HTTP_REQUEST_HEADER_TVSEC_KEY "sec"		// recv/send tv_sec
#define HTTP_REQUEST_HEADER_TVUSEC_KEY "usec"	// recv/send tv_usec
#define HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY "forwardersec"		// forwarder tv_sec
#define HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY "forwarderusec"	// forwarder tv_usec

#define SOCKS5_CHECK_MESSAGE "socks5 ok"

static char authentication_method = 0x0;	// 0x0:No Authentication Required	0x2:Username/Password Authentication
static char username[256] = "socks5user";
static char password[256] = "supersecretpassword";

char cipher_suite_tls_1_2[1000] = "AESGCM+ECDSA:CHACHA20+ECDSA:+AES256";	// TLS1.2
char cipher_suite_tls_1_3[1000] = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";	// TLS1.3


static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_http_module_t ngx_http_socks5_module_ctx = {
	NULL,					/* preconfiguration */
	ngx_http_socks5_init,			/* postconfiguration */
	NULL,					/* create main configuration */
	NULL,					/* init main configuration */
	NULL,					/* create server configuration */
	NULL,					/* marge server configuration */
	NULL,					/* create location configuration */
	NULL					/* merge location configuration */
};

ngx_module_t ngx_http_socks5_module = {
	NGX_MODULE_V1,
	&ngx_http_socks5_module_ctx,		/* module context */
	NULL,					/* module directives */
	NGX_HTTP_MODULE,			/* module type */
	NULL,					/* init master */
	NULL,					/* init module */
	NULL,					/* init process */
	NULL,					/* init thread */
	NULL,					/* exit thread */
	NULL,					/* exit process */
	NULL,					/* exit master */
	NGX_MODULE_V1_PADDING
};


int encrypt_aes(ngx_http_request_t *r, unsigned char *plaintext, int plaintext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;
	int length;
	int ciphertext_length;
	int ret;
	
	ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL){
#ifdef _DEBUG
//		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] EVP_CIPHER_CTX_new error");
#endif
		return -1;
	}
	
	ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
	if(ret != 1){
#ifdef _DEBUG
//		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] EVP_EncryptInit_ex error");
#endif
		return -1;
	}
	
	ret = EVP_EncryptUpdate(ctx, ciphertext, &length, plaintext, plaintext_length);
	if(ret != 1){
#ifdef _DEBUG
//		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] EVP_EncryptUpdate error");
#endif
		return -1;
	}
	ciphertext_length = length;
	
	ret = EVP_EncryptFinal_ex(ctx, ciphertext+length, &length);
	if(ret != 1){
#ifdef _DEBUG
//		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] EVP_EncryptFinal_ex error");
#endif
		return -1;
	}
	ciphertext_length += length;
	
	EVP_CIPHER_CTX_free(ctx);
	
	return ciphertext_length;
}


int decrypt_aes(ngx_http_request_t *r, unsigned char *ciphertext, int ciphertext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int length;
	int plaintext_length;
	int ret;
	
	ctx = EVP_CIPHER_CTX_new();
	if(ctx == NULL){
#ifdef _DEBUG
//		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] EVP_CIPHER_CTX_new error");
#endif
		return -1;
	}
	
	ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
	if(ret != 1){
#ifdef _DEBUG
//		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] EVP_DecryptInit_ex error");
#endif
		return -1;
	}
	
	ret = EVP_DecryptUpdate(ctx, plaintext, &length, ciphertext, ciphertext_length);
	if(ret != 1){
#ifdef _DEBUG
//		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] EVP_DecryptUpdate error");
#endif
		return -1;
	}
	plaintext_length = length;
	
	ret = EVP_DecryptFinal_ex(ctx, plaintext+length, &length);
	if(ret != 1){
#ifdef _DEBUG
//		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] EVP_DecryptFinal_ex error");
#endif
		return -1;
	}
	plaintext_length += length;
	
	EVP_CIPHER_CTX_free(ctx);
	
	return plaintext_length;
}


void enable_blocking_socket(ngx_http_request_t *r, int sock)	// blocking
{
	int flags = 0;
	int ret = 0;

	flags = fcntl(sock, F_GETFL, 0);
	ret = fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
	usleep(5000);
	if(ret == -1){
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] enable_blocking_socket error:%d", errno);
#endif
	}

	return;
}


void disable_blocking_socket(ngx_http_request_t *r, int sock)	// non blocking
{
	int flags = 0;
	int ret = 0;

	flags = fcntl(sock, F_GETFL, 0);
	ret = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
	usleep(5000);
	if(ret == -1){
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] disable_blocking_socket error:%d", errno);
#endif
	}

	return;
}


void enable_blocking_bio(ngx_http_request_t *r, BIO *bio)	// blocking
{
	int ret = 0;
	long n = 0;	// blocking

	ret = BIO_set_nbio(bio, n);
	if(ret <= 1){
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] enable_blocking_bio error:%d", ret);
#endif
	}

	return;
}


void disable_blocking_bio(ngx_http_request_t *r, BIO *bio)	// non blocking
{
	int ret = 0;
	long n = 1;	// non blocking

	ret = BIO_set_nbio(bio, n);
	if(ret <= 1){
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] disable_blocking_bio error:%d\n", ret);
#endif
	}

	return;
}


int recv_data(ngx_http_request_t *r, int sock, void *buffer, int length, long tv_sec, long tv_usec)
{
	int rec = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	struct timeval start;
	struct timeval end;
	long t = 0;
	bzero(buffer, length+1);

	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error");
#endif
		return -1;
	}
	
	while(1){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error");
#endif
			return -1;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] recv_data_aes timeout");
#endif
			return -1;
		}
		
		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] recv_data select timeout");
#endif
			return -1;
		}
		
		if(FD_ISSET(sock, &readfds)){
			rec = recv(sock, buffer, length, 0);
			if(rec <= 0){
				if(errno == EINTR){
					continue;
				}else if(errno == EAGAIN){
					usleep(5000);
					continue;
				}else{
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] recv error:%d", errno);
#endif
					return -1;
				}
			}else{
				break;
			}
		}
	}
	
	return rec;
}


int recv_data_bio(ngx_http_request_t *r, int sock, BIO *bio, void *buffer, int length, long tv_sec, long tv_usec)
{
	int rec = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	struct timeval start;
	struct timeval end;
	long t = 0;
	bzero(buffer, length+1);


	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error");
#endif
		return -1;
	}

	while(1){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error");
#endif
			return -1;
		}

		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] recv_data_bio timeout");
#endif
			return -1;
		}

		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;

		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] recv_data_bio select timeout");
#endif
			return -1;
		}

		if(FD_ISSET(sock, &readfds)){
			rec = BIO_read(bio, buffer, length);
			if(rec <= 0){
				if(BIO_should_retry(bio)){
					continue;
				}else{
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] BIO_read error:%d", rec);
#endif
					return -1;
				}
			}else{
				break;
			}
		}
	}

	return rec;
}


int send_data(ngx_http_request_t *r, int sock, void *buffer, int length, long tv_sec, long tv_usec)
{
	int sen = 0;
	int send_length = 0;
	int len = length;
	fd_set writefds;
	int nfds = -1;
	struct timeval tv;
	struct timeval start;
	struct timeval end;
	long t = 0;

	
	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error");
#endif
		return -1;
	}
	
	while(len > 0){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error");
#endif
			return -1;
		}
		
		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] send_data timeout");
#endif
			return -1;
		}
		
		FD_ZERO(&writefds);
		FD_SET(sock, &writefds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, NULL, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] send_data select timeout.");
#endif
			return -1;
		}
		
		if(FD_ISSET(sock, &writefds)){
			sen = send(sock, (char *)buffer+send_length, len, 0);
			if(sen <= 0){
				if(errno == EINTR){
					continue;
				}else if(errno == EAGAIN){
					usleep(5000);
					continue;
				}else{
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] send error:%d", errno);
#endif
					return -1;
				}
			}
			send_length += sen;
			len -= sen;
		}
	}
	
	return length;
}


int send_data_bio(ngx_http_request_t *r, int sock, BIO *bio, void *buffer, int length, long tv_sec, long tv_usec)
{
	int sen = 0;
	int send_length = 0;
	int len = length;
	fd_set writefds;
	int nfds = -1;
	struct timeval tv;
	struct timeval start;
	struct timeval end;
	long t = 0;


	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error");
#endif
		return -1;
	}

	while(len > 0){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error");
#endif
			return -1;
		}

		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] send_data_bio timeout");
#endif
			return -1;
		}

		FD_ZERO(&writefds);
		FD_SET(sock, &writefds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;

		if(select(nfds, NULL, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] send_data_bio select timeout");
#endif
			return -1;
		}

		if(FD_ISSET(sock, &writefds)){
			sen = BIO_write(bio, (unsigned char *)buffer+send_length, len);
			if(sen <= 0){
				if(BIO_should_retry(bio)){
					continue;
				}else{
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] BIO_write error:%d", sen);
#endif
					return -1;
				}
			}

			send_length += sen;
			len -= sen;
		}
	}

	return length;
}


int forwarder_bio(ngx_http_request_t *r, int client_sock, BIO *client_bio, int target_sock, long tv_sec, long tv_usec)
{
	int rec,sen;
	int len = 0;
	int send_length = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	unsigned char *buffer = calloc(BUFFER_SIZE*2, sizeof(unsigned char));


	while(1){
		FD_ZERO(&readfds);
		FD_SET(client_sock, &readfds);
		FD_SET(target_sock, &readfds);
		nfds = (client_sock > target_sock ? client_sock : target_sock) + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;

		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] forwarder_bio select timeout");
#endif
			goto error;
		}

		if(FD_ISSET(client_sock, &readfds)){
			bzero(buffer, BUFFER_SIZE*2);

			rec = BIO_read(client_bio, buffer, BUFFER_SIZE);
			if(rec <= 0){
				if(BIO_should_retry(client_bio)){
					continue;
				}else{
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] forwarder_bio BIO_read error:%d", rec);
#endif
					goto error;
				}
			}else{
				len = rec;
				send_length = 0;

				while(len > 0){
					sen = send(target_sock, (unsigned char *)buffer+send_length, len, 0);
					if(sen <= 0){
						if(errno == EINTR){
							continue;
						}else if(errno == EAGAIN){
							usleep(5000);
							continue;
						}else{
#ifdef _DEBUG
							ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] forwarder_bio send error:%d", errno);
#endif
							goto error;
						}
					}
					send_length += sen;
					len -= sen;
				}
			}
		}

		if(FD_ISSET(target_sock, &readfds)){
			bzero(buffer, BUFFER_SIZE*2);

			rec = recv(target_sock, buffer, BUFFER_SIZE, 0);
			if(rec <= 0){
				if(errno == EINTR){
					continue;
				}else if(errno == EAGAIN){
					usleep(5000);
					continue;
				}else{
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] forwarder_bio recv error:%d", errno);
#endif
					goto error;
				}
			}else{
				len = rec;
				send_length = 0;

				while(len > 0){
					sen = BIO_write(client_bio, (unsigned char *)buffer+send_length, len);
					if(sen <= 0){
						if(BIO_should_retry(client_bio)){
							continue;
						}else{
#ifdef _DEBUG
							ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] forwarder_bio BIO_write error:%d", sen);
#endif
							goto error;
						}
					}
					send_length += sen;
					len -= sen;
				}
			}
		}
	}

	free(buffer);
	return 0;

error:
	free(buffer);
	return -1;
}


int send_socks_response_ipv4_bio(ngx_http_request_t *r, int client_sock, BIO *client_bio, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	struct socks_response_ipv4 *socks_response_ipv4 = (struct socks_response_ipv4 *)malloc(sizeof(struct socks_response_ipv4));
	
	socks_response_ipv4->ver = ver;		// protocol version
	socks_response_ipv4->req = req;		// Connection refused
	socks_response_ipv4->rsv = rsv;		// RESERVED
	socks_response_ipv4->atyp = atyp;	// IPv4
	bzero(socks_response_ipv4->bnd_addr, 4);	// BND.ADDR
	bzero(socks_response_ipv4->bnd_port, 2);	// BND.PORT

	sen = send_data_bio(r, client_sock, client_bio, socks_response_ipv4, sizeof(struct socks_response_ipv4), tv_sec, tv_usec);

	free(socks_response_ipv4);

	return sen;
}


int send_socks_response_ipv6_bio(ngx_http_request_t *r, int client_sock, BIO *client_bio, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	struct socks_response_ipv6 *socks_response_ipv6 = (struct socks_response_ipv6 *)malloc(sizeof(struct socks_response_ipv6));
	
	socks_response_ipv6->ver = ver;		// protocol version
	socks_response_ipv6->req = req;		// Connection refused
	socks_response_ipv6->rsv = rsv;		// RESERVED
	socks_response_ipv6->atyp = atyp;	// IPv6
	bzero(socks_response_ipv6->bnd_addr, 16);	// BND.ADDR
	bzero(socks_response_ipv6->bnd_port, 2);	// BND.PORT
	
	sen = send_data_bio(r, client_sock, client_bio, socks_response_ipv6, sizeof(struct socks_response_ipv6), tv_sec, tv_usec);
	
	free(socks_response_ipv6);

	return sen;
}


int bio_do_handshake_non_blocking(ngx_http_request_t *r, int sock, BIO *bio, long tv_sec, long tv_usec)
{
	fd_set readfds;
	fd_set writefds;
	int nfds = -1;
	struct timeval tv;
	struct timeval start;
	struct timeval end;
	long t = 0;
	long ret_long = 0;


	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error");
#endif
		return -1;
	}

	while(1){
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_SET(sock, &readfds);
		FD_SET(sock, &writefds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;

		if(select(nfds, &readfds, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] bio_do_handshake_non_blocking select timeout\n");
#endif
			return -1;
		}

		if(FD_ISSET(sock, &readfds) || FD_ISSET(sock, &writefds)){
			ret_long = BIO_do_handshake(bio);
			if(ret_long <= 0){
				if(BIO_should_retry(bio)){
					usleep(5000);
				}else{
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] BIO_should_retry error");
#endif
					return -1;
				}
			}else{
				break;
			}
		}

		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] gettimeofday error");
#endif
			return -1;
		}

		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] bio_do_handshake_non_blocking timeout");
#endif
			return -1;
		}
	}

	return 0;
}


int worker(ngx_http_request_t *r, void *ptr)
{
	struct worker_param *worker_param = (struct worker_param *)ptr;
	int client_sock = worker_param->client_sock;
	BIO *client_bio_socks5 = worker_param->client_bio_socks5;
	long tv_sec = worker_param->tv_sec;		// recv send
	long tv_usec = worker_param->tv_usec;		// recv send
	long forwarder_tv_sec = worker_param->forwarder_tv_sec;
	long forwarder_tv_usec = worker_param->forwarder_tv_usec;
	
	char *buffer = calloc(BUFFER_SIZE+1, sizeof(unsigned char));
	int sen = 0;
	int rec = sen;
	int err = 0;
	
	int target_sock = -1;

	
	// socks selection_request
#ifdef _DEBUG
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client -> server] Receive selection request");
#endif
	rec = recv_data_bio(r, client_sock, client_bio_socks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
	if(rec <= 0){
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client -> server] Receive selection request");
#endif
		goto error;
	}
#ifdef _DEBUG
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client -> server] Receive selection request:%d bytes", rec);
#endif
	struct selection_request *selection_request = (struct selection_request *)buffer;
	unsigned char method = 0xFF;
	for(int i=0; i<selection_request->nmethods; i++){
		if(selection_request->methods[i] == 0x0 || selection_request->methods[i] == 0x2){	// no authentication required or username/password
			method = selection_request->methods[i];
			break;
		}
	}
	if(method == 0xFF){
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client -> server] Selection request method error");
#endif
	}


	// socks selection_response
	struct selection_response *selection_response = (struct selection_response *)malloc(sizeof(struct selection_response));
	selection_response->ver = 0x5;		// socks version 5
	selection_response->method = method;	// no authentication required or username/password
	if(selection_request->ver != 0x5 || authentication_method != method){
		selection_response->method = 0xFF;
	}

	sen = send_data_bio(r, client_sock, client_bio_socks5, selection_response, sizeof(struct selection_response), tv_sec, tv_usec);
	if(sen <= 0){
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send selection response");
#endif
		free(selection_response);
		goto error;
	}

	free(selection_response);
#ifdef _DEBUG
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send selection response:%d bytes", sen);
#endif
	
	if(authentication_method != method){
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Authentication method error server:0x%x client:0x%x", authentication_method, method);
#endif
		goto error;
	}


	// socks username_password_authentication
	unsigned char ulen = 0;
	unsigned char plen = 0;
	char uname[256] = {0};
	char passwd[256] = {0};
	if(method == 0x2){
		// socks username_password_authentication_request
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client -> server] Receive username password authentication request");
#endif
		bzero(buffer, BUFFER_SIZE+1);
		rec = recv_data_bio(r, client_sock, client_bio_socks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
		if(rec <= 0){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client -> server] Receive username password authentication request");
#endif
			goto error;
		}
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client -> server] Receive username password authentication request:%d bytes", rec);
#endif
		struct username_password_authentication_request_tmp *username_password_authentication_request = (struct username_password_authentication_request_tmp *)buffer;

		ulen = username_password_authentication_request->ulen;
		memcpy(uname, &username_password_authentication_request->uname, ulen);
		memcpy(&plen, &username_password_authentication_request->uname + ulen, 1);
		memcpy(passwd, &username_password_authentication_request->uname + ulen + 1, plen);
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] uname:%s ulen:%d, passwd:%s plen:%d", uname, ulen, passwd, plen);
#endif


		// socks username_password_authentication_response
		struct username_password_authentication_response *username_password_authentication_response = (struct username_password_authentication_response *)malloc(sizeof(struct username_password_authentication_response));
		username_password_authentication_response->ver = 0x1;
		
		if(username_password_authentication_request->ver == 0x1 && !strncmp(uname, username, sizeof(username)) && !strncmp(passwd, password, sizeof(password))){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client -> server] Succeed username password authentication");
#endif
			username_password_authentication_response->status = 0x0;
			
			sen = send_data_bio(r, client_sock, client_bio_socks5, username_password_authentication_response, sizeof(struct username_password_authentication_response), tv_sec, tv_usec);
			if(sen <= 0){
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send username password authentication response");
#endif
				
				free(username_password_authentication_response);
				goto error;
			}
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send username password authentication response:%d bytes", sen);
#endif
			
			free(username_password_authentication_response);
		}else{
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client -> server] Fail username password authentication");
#endif
			username_password_authentication_response->status = 0xFF;
			
			sen = send_data_bio(r, client_sock, client_bio_socks5, username_password_authentication_response, sizeof(struct username_password_authentication_response), tv_sec, tv_usec);
			if(sen <= 0){
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send username password authentication response");
#endif
			}else{
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send username password authentication response:%d bytes", sen);
#endif
			}
			
			free(username_password_authentication_response);
			goto error;
		}
	}
	
	
	// socks socks_request
#ifdef _DEBUG
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client -> server] Receive socks request");
#endif
	bzero(buffer, BUFFER_SIZE+1);
	rec = recv_data_bio(r, client_sock, client_bio_socks5, buffer, BUFFER_SIZE, tv_sec, tv_usec);
	if(rec <= 0){
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client -> server] Receive socks request");
#endif
		goto error;
	}
#ifdef _DEBUG
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client -> server] Receive socks request:%d bytes", rec);
#endif
	
	struct socks_request *socks_request = (struct socks_request *)buffer;
	struct socks_request_ipv4 *socks_request_ipv4;
	struct socks_request_domainname *socks_request_domainname;
	struct socks_request_ipv6 *socks_request_ipv6;
	
	char atyp = socks_request->atyp;
	if(atyp != 0x1 && atyp != 0x3 && atyp != 0x4){
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Socks request atyp(%d) error", atyp);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented");
#endif

		// socks socks_response
		sen = send_socks_response_ipv4_bio(r, client_sock, client_bio_socks5, 0x5, 0x8, 0x0, 0x1, tv_sec, tv_usec);
		if(sen <= 0){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
		}

		goto error;
	}

	char cmd = socks_request->cmd;
	if(cmd != 0x1){	// CONNECT only
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Socks request cmd(%d) error", cmd);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented");
#endif

		// socks socks_response
		if(atyp == 0x1 || atyp == 0x3){	// IPv4
			sen = send_socks_response_ipv4_bio(r, client_sock, client_bio_socks5, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
		}else{	// IPv6
			sen = send_socks_response_ipv6_bio(r, client_sock, client_bio_socks5, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
		}
		if(sen <= 0){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
		}
		
		goto error;
	}

	struct sockaddr_in target_addr, *tmp_ipv4;		// IPv4
	memset(&target_addr, 0, sizeof(struct sockaddr_in));
	
	struct sockaddr_in6 target_addr6, *tmp_ipv6;	// IPv6
	memset(&target_addr6, 0, sizeof(struct sockaddr_in6));
	
	struct addrinfo hints, *target_host;
	memset(&hints, 0, sizeof(struct addrinfo));
	
	int family = 0;
	char domainname[256] = {0};
	u_short domainname_length = 0;
	char *colon;
	
	if(socks_request->atyp == 0x1){	// IPv4
		family = AF_INET;
		target_addr.sin_family = AF_INET;
		socks_request_ipv4 = (struct socks_request_ipv4 *)buffer;
		memcpy(&target_addr.sin_addr.s_addr, &socks_request_ipv4->dst_addr, 4);
		memcpy(&target_addr.sin_port, &socks_request_ipv4->dst_port, 2);
	}else if(socks_request->atyp == 0x3){	// domain name
		socks_request_domainname = (struct socks_request_domainname *)buffer;
		domainname_length = socks_request_domainname->dst_addr_len;
		memcpy(&domainname, &socks_request_domainname->dst_addr, domainname_length);
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Domainname:%s, Length:%d", domainname, domainname_length);
#endif

		colon = strstr(domainname, ":");	// check ipv6 address
		if(colon == NULL){	// ipv4 address or domainname
			hints.ai_family = AF_INET;	// IPv4
			if(getaddrinfo(domainname, NULL, &hints, &target_host) != 0){
				hints.ai_family = AF_INET6;	// IPv6
				if(getaddrinfo(domainname, NULL, &hints, &target_host) != 0){
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Cannot resolv the domain name:%s", (char *)domainname);
#endif
					
					// socks socks_response
					sen = send_socks_response_ipv4_bio(r, client_sock, client_bio_socks5, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					if(sen <= 0){
#ifdef _DEBUG
						ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
					}
					
					goto error;
				}
			}
		}else{	// ipv6 address
			hints.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(domainname, NULL, &hints, &target_host) != 0){
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Cannot resolv the domain name:%s", (char *)domainname);
#endif
				
				// socks socks_response
				sen = send_socks_response_ipv6_bio(r, client_sock, client_bio_socks5, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
				}

				goto error;
			}
		}
		
		if(target_host->ai_family == AF_INET){
			family = AF_INET;
			target_addr.sin_family = AF_INET;
			tmp_ipv4 = (struct sockaddr_in *)target_host->ai_addr;
			memcpy(&target_addr.sin_addr, &tmp_ipv4->sin_addr, sizeof(unsigned long));
			memcpy(&target_addr.sin_port, &socks_request_domainname->dst_addr[domainname_length], 2);
			freeaddrinfo(target_host);
		}else if(target_host->ai_family == AF_INET6){
			family = AF_INET6;
			target_addr6.sin6_family = AF_INET6;
			tmp_ipv6 = (struct sockaddr_in6 *)target_host->ai_addr;
			memcpy(&target_addr6.sin6_addr, &tmp_ipv6->sin6_addr, sizeof(struct in6_addr));
			memcpy(&target_addr6.sin6_port, &socks_request_domainname->dst_addr[domainname_length], 2);
			freeaddrinfo(target_host);
		}else{
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented");
#endif

			// socks socks_response
			sen = send_socks_response_ipv4_bio(r, client_sock, client_bio_socks5, 0x1, 0x5, 0x0, 0x1, tv_sec, tv_usec);
			if(sen <= 0){
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
			}
			
			freeaddrinfo(target_host);
			goto error;
		}
	}else if(socks_request->atyp == 0x4){	// IPv6
		family = AF_INET6;
		target_addr6.sin6_family = AF_INET6;
		socks_request_ipv6 = (struct socks_request_ipv6 *)buffer;
		memcpy(&target_addr6.sin6_addr, &socks_request_ipv6->dst_addr, 16);
		memcpy(&target_addr6.sin6_port, &socks_request_ipv6->dst_port, 2);
	}else {
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented");
#endif

		// socks socks_response
		sen = send_socks_response_ipv4_bio(r, client_sock, client_bio_socks5, 0x1, 0x5, 0x0, 0x1, tv_sec, tv_usec);
		if(sen <= 0){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
		}
		
		goto error;
	}


	// socks socks_response
	char target_addr6_string[INET6_ADDRSTRLEN+1] = {0};
	char *target_addr6_string_pointer = target_addr6_string;
	
	if(atyp == 0x1){	// IPv4
		if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:CONNECT");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [server -> target] Connecting ip:%s port:%d", inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port));
#endif
			target_sock = socket(AF_INET, SOCK_STREAM, 0);
			
			enable_blocking_socket(r, target_sock);	// blocking
			
			if((err = connect(target_sock, (struct sockaddr *)&target_addr, sizeof(target_addr))) < 0){
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [server <- target] Cannot connect errno:%d", err);
#endif
				
				sen = send_socks_response_ipv4_bio(r, client_sock, client_bio_socks5, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
				}else{
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
				}
				
				goto error;
			}

#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [server <- target] Connected ip:%s port:%d", inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port));
#endif
			
			sen = send_socks_response_ipv4_bio(r, client_sock, client_bio_socks5, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
			if(sen <= 0){
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
				goto error;
			}else{
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
			}
		}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:BIND");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented");
#endif

			sen = send_socks_response_ipv4_bio(r, client_sock, client_bio_socks5, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			if(sen <= 0){
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
			}else{
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
			}
			
			goto error;
		}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented");
#endif
			
			sen = send_socks_response_ipv4_bio(r, client_sock, client_bio_socks5, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			if(sen <= 0){
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
			}else{
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
			}
			
			goto error;
		}else{
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented");
#endif

			sen = send_socks_response_ipv4_bio(r, client_sock, client_bio_socks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			if(sen <= 0){
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
			}else{
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
			}
			
			goto error;
		}
	}else if(atyp == 0x3){	// domain name
		if(family == AF_INET){	// IPv4
			if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:CONNECT");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [server -> target] Connecting ip:%s port:%d", inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port));
#endif
				target_sock = socket(AF_INET, SOCK_STREAM, 0);
				
				enable_blocking_socket(r, target_sock);	// blocking
				
				if((err = connect(target_sock, (struct sockaddr *)&target_addr, sizeof(target_addr))) < 0){
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [server <- target] Cannot connect errno:%d", err);
#endif

					sen = send_socks_response_ipv4_bio(r, client_sock, client_bio_socks5, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					if(sen <= 0){
#ifdef _DEBUG
						ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
					}else{
#ifdef _DEBUG
						ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
					}
					
					goto error;
				}

#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [server <- target] Connected ip:%s port:%d", inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port));
#endif
				
				sen = send_socks_response_ipv4_bio(r, client_sock, client_bio_socks5, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
					
					goto error;
				}else{
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
				}
			}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:BIND");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented");
#endif
				
				sen = send_socks_response_ipv4_bio(r, client_sock, client_bio_socks5, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
				}else{
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
				}
				
				goto error;
			}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented");
#endif
				
				sen = send_socks_response_ipv4_bio(r, client_sock, client_bio_socks5, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
				}else{
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
				}
				
				goto error;
			}else{
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented");
#endif
				
				sen = send_socks_response_ipv4_bio(r, client_sock, client_bio_socks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
				}else{
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
				}
				
				goto error;
			}
		}else if(family == AF_INET6){	// IPv6
			inet_ntop(AF_INET6, &target_addr6.sin6_addr, target_addr6_string_pointer, INET6_ADDRSTRLEN);

			if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:CONNECT");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [server -> target] Connecting ip:%s port:%d", target_addr6_string_pointer, ntohs(target_addr6.sin6_port));
#endif
				target_sock = socket(AF_INET6, SOCK_STREAM, 0);

				enable_blocking_socket(r, target_sock);	// blocking
			
				if((err = connect(target_sock, (struct sockaddr *)&target_addr6, sizeof(target_addr6))) < 0){
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [server <- target] Cannot connect errno:%d", err);
#endif
					
					sen = send_socks_response_ipv6_bio(r, client_sock, client_bio_socks5, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
					if(sen <= 0){
#ifdef _DEBUG
						ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
					}else{
#ifdef _DEBUG
						ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
					}
					
					goto error;
				}

#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [server <- target] Connected ip:%s port:%d", target_addr6_string_pointer, ntohs(target_addr6.sin6_port));
#endif

				sen = send_socks_response_ipv6_bio(r, client_sock, client_bio_socks5, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
					
					goto error;
				}else{
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- target] Send socks response:%d bytes", sen);
#endif
				}
			}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:BIND");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented");
#endif
				
				sen = send_socks_response_ipv6_bio(r, client_sock, client_bio_socks5, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
				}else{
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
				}
				
				goto error;
			}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE");
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented");
#endif

				sen = send_socks_response_ipv6_bio(r, client_sock, client_bio_socks5, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
				}else{
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
				}
				
				goto error;
			}else{
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented");
#endif
				
				sen = send_socks_response_ipv4_bio(r, client_sock, client_bio_socks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
				}else{
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
				}
				
				goto error;
			}
		}else{
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented");
#endif
			
			sen = send_socks_response_ipv4_bio(r, client_sock, client_bio_socks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			if(sen <= 0){
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
			}else{
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
			}
			
			goto error;
		}
	}else if(atyp == 0x4){	// IPv6
		inet_ntop(AF_INET6, &target_addr6.sin6_addr, target_addr6_string_pointer, INET6_ADDRSTRLEN);

		if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:CONNECT");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [server -> target] Connecting ip:%s port:%d", target_addr6_string_pointer, ntohs(target_addr6.sin6_port));
#endif
			target_sock = socket(AF_INET6, SOCK_STREAM, 0);
			
			enable_blocking_socket(r, target_sock);	// blocking
			
			if((err = connect(target_sock, (struct sockaddr *)&target_addr6, sizeof(target_addr6))) < 0){
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [server -> target] Cannot connect errno:%d", err);
#endif
				
				sen = send_socks_response_ipv6_bio(r, client_sock, client_bio_socks5, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				if(sen <= 0){
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
				}else{
#ifdef _DEBUG
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
				}
				
				goto error;
			}

#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [server <- target] Connected ip:%s port:%d", target_addr6_string_pointer, ntohs(target_addr6.sin6_port));
#endif
			
			sen = send_socks_response_ipv6_bio(r, client_sock, client_bio_socks5, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
			if(sen <= 0){
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
				
				goto error;
			}else{
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
			}
		}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:BIND");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented");
#endif

			sen = send_socks_response_ipv6_bio(r, client_sock, client_bio_socks5, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			if(sen <= 0){
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
			}else{
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
			}
			
			goto error;
		}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented");
#endif
			
			sen = send_socks_response_ipv6_bio(r, client_sock, client_bio_socks5, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			if(sen <= 0){
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
			}else{
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
			}
			
			goto error;
		}else{
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented");
#endif
			
			sen = send_socks_response_ipv6_bio(r, client_sock, client_bio_socks5, 0x5, 0x1, 0x0, 0x4, tv_sec, tv_usec);
			if(sen <= 0){
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
			}else{
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
			}
			
			goto error;
		}
	}else{
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] Not implemented");
#endif
		
		sen = send_socks_response_ipv4_bio(r, client_sock, client_bio_socks5, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
		if(sen <= 0){
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send socks response");
#endif
		}else{
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send socks response:%d bytes", sen);
#endif
		}
		
		goto error;
	}

	
	// forwarder
#ifdef _DEBUG
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Forwarder");
#endif
	disable_blocking_socket(r, target_sock);
	err = forwarder_bio(r, client_sock, client_bio_socks5, target_sock, forwarder_tv_sec, forwarder_tv_usec);
	

#ifdef _DEBUG
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Worker exit");
#endif
	close_socket(target_sock);
	return 0;

error:
	if(target_sock != -1){
		close_socket(target_sock);
	}
	return -1;
}


void fini_ssl(ngx_http_request_t *r, struct ssl_param *param)
{
//	client_bio_http		:BIO_NOCLOSE
//	client_bio_socks5	:BIO_CLOSE

	if(param->client_bio_socks5 != NULL){
		BIO_free_all(param->client_bio_socks5);
	}else if(param->client_bio_http != NULL){
		BIO_free(param->client_bio_http);
	}

	if(param->client_ctx_socks5 != NULL){
		SSL_CTX_free(param->client_ctx_socks5);
	}
	
	return;
}


void close_socket(int sock)
{
	if(sock != -1){
		shutdown(sock, SHUT_RDWR);
		usleep(500);
		close(sock);
	}
	
	return;
}


static ngx_table_elt_t *search_headers_in(ngx_http_request_t *r, u_char *name, size_t len)
{
	ngx_list_part_t *part;
	ngx_table_elt_t *h;
	ngx_uint_t i;
	
	part = &r->headers_in.headers.part;
	h = part->elts;
	
	for(i = 0; ; i++){
		if(i >= part->nelts){
			if(part->next == NULL){
				break;
			}
			
			part = part->next;
			h = part->elts;
			i = 0;
		}
		
		if(len != h[i].key.len || ngx_strcasecmp(name, h[i].key.data) != 0){
			continue;
		}
		
		return &h[i];
	}
	
	return NULL;
}


static ngx_int_t ngx_http_socks5_header_filter(ngx_http_request_t *r)
{
	ngx_table_elt_t *h;
	int socks5_flag = 0;
	int client_sock = r->connection->fd;
	int ret = 0;
	long ret_l = 0;
	int err = 0;
	int sen = 0;
	
	ngx_ssl_connection_t *sc = NULL;
	SSL *client_ssl_http = NULL;
	BIO *client_bio_http = NULL;

	if(r->connection->ssl != NULL){	// HTTPS
		sc = r->connection->ssl;
		client_ssl_http = sc->connection;
		if(client_ssl_http == NULL){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] client_ssl_http is NULL");
#endif
			goto error;
		}
	}else{	// HTTP
		return ngx_http_next_header_filter(r);
	}

	SSL_CTX *client_ctx_socks5 = NULL;
	SSL *client_ssl_socks5 = NULL;
	BIO *client_bio_socks5 = NULL;
	
	struct worker_param worker_param;
	long tv_sec = 3;	// recv send
	long tv_usec = 0;	// recv send
	long forwarder_tv_sec = 3;
	long forwarder_tv_usec = 0;
	struct ssl_param ssl_param;
	ssl_param.client_bio_http = NULL;
	ssl_param.client_ctx_socks5 = NULL;
	ssl_param.client_ssl_socks5 = NULL;
	ssl_param.client_bio_socks5 = NULL;

	BIO *bio = NULL;
	EVP_PKEY *s_privatekey_socks5 = NULL;
	X509 *s_cert_socks5 = NULL;
	

	// search header
	h = search_headers_in(r, (u_char *)HTTP_REQUEST_HEADER_SOCKS5_KEY, (size_t)(strlen(HTTP_REQUEST_HEADER_SOCKS5_KEY)));
	if(h != NULL &&  ngx_strcasecmp(h->value.data, (u_char *)HTTP_REQUEST_HEADER_SOCKS5_VALUE) == 0){	// socks5
		socks5_flag = 1;
	}
	
	h = search_headers_in(r, (u_char *)HTTP_REQUEST_HEADER_TVSEC_KEY, (size_t)(strlen(HTTP_REQUEST_HEADER_TVSEC_KEY)));
	if(h != NULL){
		tv_sec = atol((char *)h->value.data);
	}
	
	h = search_headers_in(r, (u_char *)HTTP_REQUEST_HEADER_TVUSEC_KEY, (size_t)(strlen(HTTP_REQUEST_HEADER_TVUSEC_KEY)));
	if(h != NULL){
		tv_usec = atol((char *)h->value.data);
	}
	
	h = search_headers_in(r, (u_char *)HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY, (size_t)(strlen(HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY)));
	if(h != NULL){
		forwarder_tv_sec = atol((char *)h->value.data);
	}
	
	h = search_headers_in(r, (u_char *)HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY, (size_t)(strlen(HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY)));
	if(h != NULL){
		forwarder_tv_usec = atol((char *)h->value.data);
	}
	
	if(socks5_flag == 1){	// socks5
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Socks5 start");
#endif
		
		if(tv_sec < 0 || tv_sec > 60 || tv_usec < 0 || tv_usec > 1000000){
			tv_sec = 3;
			tv_usec = 0;
		}else if(tv_sec == 0 && tv_usec == 0){
			tv_sec = 3;
			tv_usec = 0;
		}
		
		if(forwarder_tv_sec < 0 || forwarder_tv_sec > 300 || forwarder_tv_usec < 0 || forwarder_tv_usec > 1000000){
			forwarder_tv_sec = 3;
			forwarder_tv_usec = 0;
		}else if(forwarder_tv_sec == 0 && forwarder_tv_usec == 0){
			forwarder_tv_sec = 3;
			forwarder_tv_usec = 0;
		}
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Timeout recv/send tv_sec:%l sec recv/send tv_usec:%l microsec", tv_sec, tv_usec);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] Timeout forwarder tv_sec:%l sec forwarder tv_usec:%l microsec", forwarder_tv_sec, forwarder_tv_usec);
#endif

		disable_blocking_socket(r, client_sock);	// non blocking

		client_bio_http = BIO_new(BIO_f_ssl());
		ssl_param.client_bio_http = client_bio_http;

		ret_l = BIO_set_ssl(client_bio_http, client_ssl_http, BIO_NOCLOSE);
		if(ret_l <= 0){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] BIO_set_ssl error");
#endif
			goto error;
		}

		// send SOCKS5_CHECK_MESSAGE to client
		sen = send_data_bio(r, client_sock, client_bio_http, SOCKS5_CHECK_MESSAGE, strlen(SOCKS5_CHECK_MESSAGE), tv_sec, tv_usec);
		if(sen <= 0){
#ifdef _DEBUG
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] Send SOCKS5_CHECK_MESSAGE error");
#endif
			goto error;
		}
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Send SOCKS5_CHECK_MESSAGE");
#endif

		// Socks5 over TLS
		// SSL Initialize
		OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);

		// SSL TLS connection
		client_ctx_socks5 = SSL_CTX_new(TLS_server_method());
		if(client_ctx_socks5 == NULL){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] SSL_CTX_new error");
#endif
			goto error;
		}
		ssl_param.client_ctx_socks5 = client_ctx_socks5;

		// server private key (Socks5 over TLS)
		bio = BIO_new(BIO_s_mem());
		BIO_write(bio, server_privatekey_socks5, strlen(server_privatekey_socks5));
		PEM_read_bio_PrivateKey(bio, &s_privatekey_socks5, NULL, NULL);
		BIO_free(bio);

		// server X509 certificate (Socks5 over TLS)
		bio = BIO_new(BIO_s_mem());
		BIO_write(bio, server_certificate_socks5, strlen(server_certificate_socks5));
		PEM_read_bio_X509(bio, &s_cert_socks5, NULL, NULL);
		BIO_free(bio);

		SSL_CTX_use_certificate(client_ctx_socks5, s_cert_socks5);
		SSL_CTX_use_PrivateKey(client_ctx_socks5, s_privatekey_socks5);
		err = SSL_CTX_check_private_key(client_ctx_socks5);
		if(err != 1){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] SSL_CTX_check_private_key error");
#endif
			goto error;
		}

//		SSL_CTX_set_mode(client_ctx_socks5, SSL_MODE_AUTO_RETRY);

		ret = SSL_CTX_set_min_proto_version(client_ctx_socks5, TLS1_2_VERSION);
		if(ret == 0){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] SSL_CTX_set_min_proto_version error");
#endif
			goto error;
		}

		ret = SSL_CTX_set_cipher_list(client_ctx_socks5, cipher_suite_tls_1_2);
		if(ret == 0){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] SSL_CTX_set_cipher_list error");
#endif
			goto error;
		}

		ret = SSL_CTX_set_ciphersuites(client_ctx_socks5, cipher_suite_tls_1_3);
		if(ret == 0){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] SSL_CTX_set_ciphersuites error");
#endif
			goto error;
		}

		client_bio_socks5 = BIO_new_ssl(client_ctx_socks5, 0);	// server mode
		if(client_bio_socks5 == NULL){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] BIO_new_ssl error");
#endif
			goto error;
		}
		ssl_param.client_bio_socks5 = client_bio_socks5;

		ret_l = BIO_get_ssl(client_bio_socks5, &client_ssl_socks5);
		if(ret_l <= 0){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] BIO_get_ssl error");
#endif
			goto error;
		}
		ssl_param.client_ssl_socks5 = client_ssl_socks5;

		client_bio_socks5 = BIO_push(client_bio_socks5, client_bio_http);

		// accept
#ifdef _DEBUG
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client -> server] Try Socks5 over TLS connection (BIO_do_handshake)");
#endif
		ret = bio_do_handshake_non_blocking(r, client_sock, client_bio_socks5, tv_sec, tv_usec);
		if(ret == -1){
#ifdef _DEBUG
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[E] [client <- server] BIO_do_handshake error");
#endif
			goto error;
		}
#ifdef _DEBUG

		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[I] [client <- server] Succeed Socks5 over TLS connection (BIO_do_handshake)");
#endif

		worker_param.client_sock = client_sock;
		worker_param.client_bio_socks5 = client_bio_socks5;
		worker_param.tv_sec = tv_sec;
		worker_param.tv_usec = tv_usec;
		worker_param.forwarder_tv_sec = forwarder_tv_sec;
		worker_param.forwarder_tv_usec = forwarder_tv_usec;
		
		ret = worker(r, &worker_param);
		
		fini_ssl(r, &ssl_param);
	}

	return ngx_http_next_header_filter(r);

error:
	fini_ssl(r, &ssl_param);
	return ngx_http_next_header_filter(r);
}


static ngx_int_t ngx_http_socks5_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
	return ngx_http_next_body_filter(r, in);
}


static ngx_int_t ngx_http_socks5_init(ngx_conf_t *cf)
{
	ngx_http_next_header_filter = ngx_http_top_header_filter;
	ngx_http_top_header_filter = ngx_http_socks5_header_filter;
	
	ngx_http_next_body_filter = ngx_http_top_body_filter;
	ngx_http_top_body_filter = ngx_http_socks5_body_filter;

	return NGX_OK;
}

