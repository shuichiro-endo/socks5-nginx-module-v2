/*
 * Title:  socks5 server header v2 (nginx module)
 * Author: Shuichiro Endo
 */

#define BUFFER_SIZE 8192

struct worker_param {
	int client_sock;
	BIO *client_bio_socks5;
	int tor_connection_flag;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
};

struct forwarder_bio_param {
	ngx_http_request_t *r;
	int client_sock;
	BIO *client_bio;
	int target_sock;
	long tv_sec;
	long tv_usec;
};

struct ssl_param {
	BIO *client_bio_http;
	SSL_CTX *client_ctx_socks5;
	SSL *client_ssl_socks5;
	BIO *client_bio_socks5;
};

struct username_password_authentication_request_tmp
{
	char ver;
	char ulen;
	char uname;
	// variable
};

struct send_recv_data_aes {
	unsigned char encrypt_data_length[16];
	unsigned char encrypt_data[BUFFER_SIZE*2];
};

struct ngx_ssl_connection_s {
    SSL *connection;
    SSL_CTX *session_ctx;
//	...
};

