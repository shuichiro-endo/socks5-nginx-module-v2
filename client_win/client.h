/*
 * Title:  socks5 client header windows v2 (nginx module)
 * Author: Shuichiro Endo
 */

#define BUFFER_SIZE 8192

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

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

