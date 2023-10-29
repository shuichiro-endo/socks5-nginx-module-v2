# socks5 client windows v2 (nginx module)

## Installation
### Install dependencies
- openssl
    1. download [openssl 3.0 version](https://www.openssl.org/source/)
    2. extract openssl-3.0.x.tar.gz
    3. install openssl. see openssl-3.0.x\NOTES-WINDOWS.md (Quick start)
- visual studio community (Desktop development with C++)
    1. install Desktop development with C++

Note: It takes a lot of time to install these.

### Install
1. download files
```
git clone https://github.com/shuichiro-endo/socks5-nginx-module-v2
```
2. run x64 Native Tools Command Prompt for VS 2022
3. set environment variable
```
set INCLUDE=%INCLUDE%;C:\Program Files\OpenSSL\include
set LIB=%LIB%;C:\Program Files\OpenSSL\lib
set LIBPATH=%LIBPATH%;C:\Program Files\OpenSSL\lib
```
4. copy ssl/tls server certificate (HTTPS, Socks5 over TLS) to the client directory
```
copy xxx.crt socks5-nginx-module-v2/client_win/server_https.crt
copy yyy.crt socks5-nginx-module-v2/client_win/server_socks5.crt
```
5. modify client.c file (if you change the certificate filename or directory path)
```
char server_certificate_filename_https[256] = "server_https.crt";	// server certificate filename (HTTPS)
char server_certificate_file_directory_path_https[256] = ".";	// server certificate file directory path (HTTPS)

char server_certificate_filename_socks5[256] = "server_socks5.crt";	// server certificate filename (Socks5 over TLS)
char server_certificate_file_directory_path_socks5[256] = ".";	// server certificate file directory path (Socks5 over TLS)
```
6. build
```
cd socks5-nginx-module-v2\client_win
compile.bat
```
7. copy openssl dll files (libcrypto-3-x64.dll, libssl-3-x64.dll) to the client directory
```
cd socks5-nginx-module-v2\client_win
copy "C:\Program Files\OpenSSL\bin\libcrypto-3-x64.dll" .
copy "C:\Program Files\OpenSSL\bin\libssl-3-x64.dll" .
```
