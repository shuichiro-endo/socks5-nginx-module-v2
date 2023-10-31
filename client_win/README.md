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

## Usage
1. run command prompt

2. change code page of command prompt (UTF-8)
```
chcp 65001
```

3. run my client
```
usage   : client.exe -h listen_ip -p listen_port -H target_socks5server_domainname -P target_socks5server_https_port
          [-A recv/send tv_sec(timeout 0-60 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-300 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]
          [-a forward proxy domainname] [-b forward proxy port] [-c forward proxy(1:http 2:https)]
          [-d forward proxy authentication(1:basic 2:digest 3:ntlmv2) 4:spnego(kerberos)]
          [-e forward proxy username] [-f forward proxy password] [-g forward proxy user domainname] [-i forward proxy workstationname] [-j forward proxy service principal name]
example : client.exe -h 127.0.0.1 -p 9050 -H 192.168.0.10 -P 443
        : client.exe -h 127.0.0.1 -p 9050 -H foobar.test -P 443
        : client.exe -h 127.0.0.1 -p 9050 -H foobar.test -P 443 -A 3 -B 0 -C 3 -D 0
        : client.exe -h 127.0.0.1 -p 9050 -H foobar.test -P 443 -a 127.0.0.1 -b 3128 -c 1
        : client.exe -h 127.0.0.1 -p 9050 -H foobar.test -P 443 -a 127.0.0.1 -b 3128 -c 1 -d 1 -e forward_proxy_user -f forward_proxy_password
        : client.exe -h 127.0.0.1 -p 9050 -H foobar.test -P 443 -a 127.0.0.1 -b 3128 -c 1 -d 2 -e forward_proxy_user -f forward_proxy_password
        : client.exe -h 127.0.0.1 -p 9050 -H foobar.test -P 443 -a 127.0.0.1 -b 3128 -c 1 -d 3 -e forward_proxy_user -f forward_proxy_password -g forward_proxy_user_domainname -i forward_proxy_workstationname
        : client.exe -h 127.0.0.1 -p 9050 -H foobar.test -P 443 -a 127.0.0.1 -b 3128 -c 1 -d 3 -e test01 -f p@ssw0rd -g test.local -i WORKSTATION -A 10
        : client.exe -h 127.0.0.1 -p 9050 -H foobar.test -P 443 -a 127.0.0.1 -b 3128 -c 1 -d 4 -j forward_proxy_service_principal_name
        : client.exe -h 127.0.0.1 -p 9050 -H foobar.test -P 443 -a 127.0.0.1 -b 3128 -c 1 -d 4 -j HTTP/proxy.test.local@TEST.LOCAL -A 10
```
