/*
 * Title:  socks5 client header windows v2 (nginx module)
 * Author: Shuichiro Endo
 */

#define BUFFER_SIZE 8192

void print_bytes(unsigned char *input, int input_length);
int encrypt_aes(unsigned char *plaintext, int plaintext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *ciphertext);
int decrypt_aes(unsigned char *ciphertext, int ciphertext_length, unsigned char *aes_key, unsigned char *aes_iv, unsigned char *plaintext);
int encode_base64(const unsigned char *input, int length, unsigned char *output, int output_size);
int decode_base64(const unsigned char *input, int length, unsigned char *output, int output_size);
int get_md5_hash(const unsigned char *input, int input_length, unsigned char *output, int output_size);
int get_sha_256_hash(const unsigned char *input, int input_length, unsigned char *output, int output_size);
int get_sha_512_256_hash(const unsigned char *input, int input_length, unsigned char *output, int output_size);
int encrypt_des_ecb(unsigned char *plaintext, int plaintext_length, unsigned char *key, unsigned char *ciphertext);
int get_md4_hash(const unsigned char *input, int input_length, unsigned char *output, int output_size);
int get_hmac_md5(const unsigned char *input, int input_length, const unsigned char *key, int key_length, unsigned char *output, int output_size);
int get_upper_string(const char *input, int input_length, char *output);
int get_number_of_bytes_of_utf16_string(char *input);
int convert_utf8_to_utf16(const char *input, char *output, int output_size);
int get_av_pair_value(struct challenge_message *challenge_message, uint16_t av_id, unsigned char *data, int data_size);
int ntowfv2(const char *user, const char *password, const char *userdom, unsigned char *output, int output_size);
int lmowfv2(const char *user, const char *password, const char *userdom, unsigned char *output, int output_size);
int generate_response_ntlmv2(struct challenge_message *challenge_message, struct authenticate_message *authenticate_message);
int get_base64_kerberos_token(char *spn, char *b64_kerberos_token, int b64_kerberos_token_size);
void enable_blocking_socket(SOCKET sock);	// blocking
void disable_blocking_socket(SOCKET sock);	// non blocking
void enable_blocking_bio(BIO *bio);		// blocking
void disable_blocking_bio(BIO *bio);	// non blocking
int recv_data(SOCKET sock, void *buffer, int length, long tv_sec, long tv_usec);
int recv_data_bio(SOCKET sock, BIO *bio, void *buffer, int length, long tv_sec, long tv_usec);
int send_data(SOCKET sock, void *buffer, int length, long tv_sec, long tv_usec);
int send_data_bio(SOCKET sock, BIO *bio, void *buffer, int length, long tv_sec, long tv_usec);
int forwarder_bio(SOCKET client_sock, SOCKET target_sock, BIO *target_bio, long tv_sec, long tv_usec);
int ssl_connect_non_blocking(SOCKET sock, SSL *ssl, long tv_sec, long tv_usec);
int bio_do_handshake_non_blocking(SOCKET sock, BIO *bio, long tv_sec, long tv_usec);
void close_socket(SOCKET sock);
int forward_proxy_authentication_no(SOCKET forward_proxy_sock, char *target_domainname, char *target_port_number, long tv_sec, long tv_usec);
int forward_proxy_authentication_basic(SOCKET forward_proxy_sock, char *target_domainname, char *target_port_number, long tv_sec, long tv_usec);
int forward_proxy_authentication_digest(SOCKET forward_proxy_sock, char *target_domainname, char *target_port_number, long tv_sec, long tv_usec);
int forward_proxy_authentication_ntlmv2(SOCKET forward_proxy_sock, char *target_domainname, char *target_port_number, long tv_sec, long tv_usec);
int forward_proxy_authentication_spnego(SOCKET forward_proxy_sock, char *target_domainname, char *target_port_number, long tv_sec, long tv_usec);
int worker(void *ptr);
void worker_thread(void *ptr);
void usage(char *filename);
int getopt(int argc, char **argv, char *optstring);

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

int gettimeofday(timeval *tv, timezone *tz);

struct worker_param {
	SOCKET client_sock;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
};

struct ssl_param {
	SSL_CTX *target_ctx_http;
	SSL *target_ssl_http;
	BIO *target_bio_http;
	SSL_CTX *target_ctx_socks5;
	SSL *target_ssl_socks5;
	BIO *target_bio_socks5;
};

void finiSsl(ssl_param *param);

struct digest_parameters {
	char algorithm[10];			// MD5 or MD5-sess or SHA-256 or SHA-256-sess or SHA-512-256 or SHA-512-256-sess
	char username[256];			// forward proxy username
	char realm[100];
	char password[256];			// forward proxy password
	char a1[1000];				// username:realm:password or H(username:realm:password):nonce:cnonce
	char a1_hash[150];			// H(a1)
	char nonce[200];
	char nonce_prime[200];
	char nc[10];				// 00000001
	char cnonce[200];
	char cnonce_prime[200];
	char qop[10];				// auth or auth-int
	char entity_body[BUFFER_SIZE+1];
	char entity_body_hash[150];
	char stale[10];				// true or false
	char method[10];			// CONNECT
	char uri[500];
	char a2[1000];				// method:uri or method:uri:H(entity_body)
	char a2_hash[150];			// H(a2)
	char response[1000];		// H(A1):nonce:nc:cnonce:qop:H(A2)
	char response_hash[150];	// H(H(A1):nonce:nc:cnonce:qop:H(A2))
};

int get_http_header(const char *input, const char *key, char *output, int output_size);
int get_digest_values(const char *input, digest_parameters *param);
int get_digest_response(digest_parameters *param);

