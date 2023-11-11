/*
 * Title:  socks5 server header v2 (nginx module)
 * Author: Shuichiro Endo
 */

#define BUFFER_SIZE 8192

static ngx_table_elt_t *search_headers_in(ngx_http_request_t *r, u_char *name, size_t len);
static ngx_int_t ngx_http_socks5_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_socks5_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_socks5_init(ngx_conf_t *cf);

int encrypt_aes(ngx_http_request_t *r, unsigned char *plaintext, int plaintext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *ciphertext);
int decrypt_aes(ngx_http_request_t *r, unsigned char *ciphertext, int ciphertext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *plaintext);
void enable_blocking_socket(ngx_http_request_t *r, int sock);	// blocking
void disable_blocking_socket(ngx_http_request_t *r, int sock);	// non blocking
void enable_blocking_bio(ngx_http_request_t *r, BIO *bio);	// blocking
void disable_blocking_bio(ngx_http_request_t *r, BIO *bio);	// non blocking
int recv_data(ngx_http_request_t *r, int sock, void *buffer, int length, long tv_sec, long tv_usec);
int recv_data_bio(ngx_http_request_t *r, int sock, BIO *bio, void *buffer, int length, long tv_sec, long tv_usec);
int send_data(ngx_http_request_t *r, int sock, void *buffer, int length, long tv_sec, long tv_usec);
int send_data_bio(ngx_http_request_t *r, int sock, BIO *bio, void *buffer, int length, long tv_sec, long tv_usec);
int forwarder_bio(ngx_http_request_t *r, int client_sock, BIO *client_bio, int target_sock, long tv_sec, long tv_usec);
int send_socks_response_ipv4_bio(ngx_http_request_t *r, int client_sock, BIO *client_bio, char ver, char rep, char rsv, char atyp, long tv_sec, long tv_usec);
int send_socks_response_ipv6_bio(ngx_http_request_t *r, int client_sock, BIO *client_bio, char ver, char rep, char rsv, char atyp, long tv_sec, long tv_usec);
int do_socks5_handshake_tor_server(ngx_http_request_t *r, int tor_sock, char tor_dst_atyp, char tor_dst_addr_len, char *tor_dst_addr, char *tor_dst_port, long tv_sec, long tv_usec);
int bio_do_handshake_non_blocking(ngx_http_request_t *r, int sock, BIO *bio, long tv_sec, long tv_usec);
void close_socket(int sock);
int worker(ngx_http_request_t *r, void *ptr);

struct worker_param {
	int client_sock;
	BIO *client_bio_socks5;
	int tor_connection_flag;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
};

struct ssl_param {
	BIO *client_bio_http;
	SSL_CTX *client_ctx_socks5;
	SSL *client_ssl_socks5;
	BIO *client_bio_socks5;
};

void fini_ssl(ngx_http_request_t *r, struct ssl_param *param);

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
