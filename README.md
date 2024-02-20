# socks5 nginx module v2

socks5 proxy(nginx module) and client with socks5 over tls

This module hides socks5 proxy in an http server.

This supports CONNECT of the socks5 command only. (BIND and UDP ASSOCIATE are not available.)

This is not compatible with [v1](https://github.com/shuichiro-endo/socks5-nginx-module).

## How it works
- no forward proxy
```mermaid
sequenceDiagram
    participant A as socks5 client
    participant B as my client
    participant C as nginx server (my socks5 module)
    participant D as destination server (web, ssh, tor, etc.)
    loop 
        A->>+B: connect (TCP)
        A->>+B: socks5 selection request (Socks5)
        B->>+C: SSL connect (TCP, HTTPS)
        B->>+C: HTTP GET Request (HTTPS)
        C->>C: check HTTP Request Header Key and Value (e.g. socks5: socks5)
        note right of C: if the key and value do not match, do nothing
        C-->>B: send SOCKS5_CHECK_MESSAGE (encrypt with TLS)
        B->>B: check SOCKS5_CHECK_MESSAGE
        B->>+C: SSL connect (Socks5 over TLS)
        C->>C: if socks5_over_tls_client_certificate_authentication_flag is 1(on), do client certificate authentication
        B->>+C: socks5 selection request (Socks5 over TLS)
        C-->>-B: socks5 selection response (Socks5 over TLS)
        B-->>-A: socks5 selection response (Socks5)
        alt socks5 server authentication method is username/password authentication
        A->>+B: socks5 username/password authentication request (Socks5)
        B->>+C: socks5 username/password authentication request (Socks5 over TLS)
        C->>C: check username and password
        C-->>-B: socks5 username/password authentication response (Socks5 over TLS)
        B-->>-A: socks5 username/password authentication response (Socks5)
        end
        A->>+B: socks5 socks request (Socks5)
        B->>+C: socks5 socks request (Socks5 over TLS)
        C->>+D: check connection (TCP)
        D-->>C: 
        C-->>-B: socks5 socks response (Socks5 over TLS)
        B-->>-A: socks5 socks response (Socks5)
        loop until communication ends (forwarder)
            A->>+B: request
            B->>+C: request (encrypt with TLS)
            C->>+D: request
            D-->>-C: response
            C-->>-B: response (encrypt with TLS)
            B-->>-A: response
        end
        D-->>-C:  
        C-->>-B: 
        C-->>-B: HTTP GET Response (HTTPS)
        C-->>-B: 
        B-->>-A: 
    end
```
- no forward proxy, tor connection
```mermaid
sequenceDiagram
    participant A as socks5 client
    participant B as my client
    participant C as nginx server (my socks5 module)
    participant D as tor client (e.g. 127.0.0.1:9050)
    participant E as tor ORs (entry <-> middle <-> exit)
    participant F as destination server (web, ssh, ...)
    loop
        A->>+B: connect (TCP)
        A->>+B: socks5 selection request (Socks5)
        B->>+C: SSL connect (TCP, HTTPS)
        B->>+C: HTTP GET Request (HTTPS)
        C->>C: check HTTP Request Header Key and Value (e.g. socks5: socks5)
        note right of C: if the key and value do not match, do nothing
        C-->>B: send SOCKS5_CHECK_MESSAGE (encrypt with TLS)
        B->>B: check SOCKS5_CHECK_MESSAGE
        B->>+C: SSL connect (Socks5 over TLS)
        C->>C: if socks5_over_tls_client_certificate_authentication_flag is 1(on), do client certificate authentication
        B->>+C: socks5 selection request (Socks5 over TLS)
        C-->>-B: socks5 selection response (Socks5 over TLS)
        B-->>-A: socks5 selection response (Socks5)
        alt socks5 server authentication method is username/password authentication
        A->>+B: socks5 username/password authentication request (Socks5)
        B->>+C: socks5 username/password authentication request (Socks5 over TLS)
        C->>C: check username and password
        C-->>-B: socks5 username/password authentication response (Socks5 over TLS)
        B-->>-A: socks5 username/password authentication response (Socks5)
        end
        A->>+B: socks5 socks request (Socks5)
        B->>+C: socks5 socks request (Socks5 over TLS)
        C->>+D: connection (TCP)
        C->>+D: socks5 selection request (Socks5)
        D-->>-C: socks5 selection response (Socks5)
        C->>+D: socks5 socks request (Socks5)
        D->>+E: check connection (encrypt with TLS)
        E->>+F: check connection (TCP)
        F-->>E: 
        E-->>D: 
        D-->>-C: socks5 socks response (Socks5)
        C-->>-B: socks5 socks response (Socks5 over TLS)
        B-->>-A: socks5 socks response (Socks5)
        loop until communication ends (forwarder)
            A->>+B: request
            B->>+C: request (encrypt with TLS)
            C->>+D: request
            D->>+E: request (encrypt with TLS)
            E->>+F: request
            F-->>-E: response
            E-->>-D: response (encrypt with TLS)
            D-->>-C: response
            C-->>-B: response (encrypt with TLS)
            B-->>-A: response
        end
        F-->>-E: 
        E-->>-D: 
        D-->>-C: 
        C-->>-B: 
        C-->>-B: HTTP GET Response (HTTPS)
        C-->>-B: 
        B-->>-A: 
    end
```
- forward proxy (http)
```mermaid
sequenceDiagram
    participant A as socks5 client
    participant B as my client
    participant C as forward proxy (squid, ...)
    participant D as nginx server (my socks5 module)
    participant E as destination server (web, ssh, tor, etc.)
    loop 
        A->>+B: connect (TCP)
        A->>+B: socks5 selection request (Socks5)
        B->>+C: HTTP CONNECT Request (TCP, HTTP)
        C->>C: User Authentication (no, basic, digest, ntlmv2, spnego(kerberos))
        C->>+D: check connection (TCP)
        D-->>C: 
        C-->>B: HTTP CONNECT Response Connection established (HTTP)
        note right of C: TCP Tunnel
        B->>+C: SSL connect (HTTPS)
        C->>+D: SSL connect (HTTPS)
        B->>+C: HTTP GET Request (HTTPS)
        C->>+D: HTTP GET Request (HTTPS)
        D->>D: check HTTP Request Header Key and Value (e.g. socks5: socks5)
        note right of D: if the key and value do not match, do nothing
        D-->>C: send SOCKS5_CHECK_MESSAGE (encrypt with TLS)
        C-->>B: send SOCKS5_CHECK_MESSAGE (encrypt with TLS)
        B->>B: check SOCKS5_CHECK_MESSAGE
        B->>+C: SSL connect (Socks5 over TLS)
        C->>+D: SSL connect (Socks5 over TLS)
        D->>D: if socks5_over_tls_client_certificate_authentication_flag is 1(on), do client certificate authentication
        B->>+C: socks5 selection request (Socks5 over TLS)
        C->>+D: socks5 selection request (Socks5 over TLS)
        D-->>-C: socks5 selection response (Socks5 over TLS)
        C-->>-B: socks5 selection response (Socks5 over TLS)
        B-->>-A: socks5 selection response (Socks5)
        alt socks5 server authentication method is username/password authentication
        A->>+B: socks5 username/password authentication request (Socks5)
        B->>+C: socks5 username/password authentication request (Socks5 over TLS)
        C->>+D: socks5 username/password authentication request (Socks5 over TLS)
        D->>D: check username and password
        D-->>-C: socks5 username/password authentication response (Socks5 over TLS)
        C-->>-B: socks5 username/password authentication response (Socks5 over TLS)
        B-->>-A: socks5 username/password authentication response (Socks5)
        end
        A->>+B: socks5 socks request (Socks5)
        B->>+C: socks5 socks request (Socks5 over TLS)
        C->>+D: socks5 socks request (Socks5 over TLS)
        D->>+E: check connection (TCP)
        E-->>D: 
        D-->>-C: socks5 socks response (Socks5 over TLS)
        C-->>-B: socks5 socks response (Socks5 over TLS)
        B-->>-A: socks5 socks response (Socks5)
        loop until communication ends (forwarder)
            A->>+B: request
            B->>+C: request (encrypt with TLS)
            C->>+D: request (encrypt with TLS)
            D->>+E: request
            E-->>-D: response
            D-->>-C: response (encrypt with TLS)
            C-->>-B: response (encrypt with TLS)
            B-->>-A: response
        end
        E-->>-D: 
        D-->>-C: 
        C-->>-B: 
        D-->>-C: HTTP GET Response (HTTPS)
        C-->>-B: HTTP GET Response (HTTPS)
        D-->>-C: 
        C-->>-B: 
        D-->>-C: 
        C-->>-B: 
        B-->>-A: 
    end
```
- forward proxy (http), tor connection
```mermaid
sequenceDiagram
    participant A as socks5 client
    participant B as my client
    participant C as forward proxy (squid, ...)
    participant D as nginx server (my socks5 module)
    participant E as tor client (e.g. 127.0.0.1:9050)
    participant F as tor ORs (entry <-> middle <-> exit)
    participant G as destination server (web, ssh, ...)
    loop
        A->>+B: connect (TCP)
        A->>+B: socks5 selection request (Socks5)
        B->>+C: HTTP CONNECT Request (TCP, HTTP)
        C->>C: User Authentication (no, basic, digest, ntlmv2, spnego(kerberos))
        C->>+D: check connection (TCP)
        D-->>C: 
        C-->>B: HTTP CONNECT Response Connection established (HTTP)
        note right of C: TCP Tunnel
        B->>+C: SSL connect (HTTPS)
        C->>+D: SSL connect (HTTPS)
        B->>+C: HTTP GET Request (HTTPS)
        C->>+D: HTTP GET Request (HTTPS)
        D->>D: check HTTP Request Header Key and Value (e.g. socks5: socks5)
        note right of D: if the key and value do not match, do nothing
        D-->>C: send SOCKS5_CHECK_MESSAGE (encrypt with TLS)
        C-->>B: send SOCKS5_CHECK_MESSAGE (encrypt with TLS)
        B->>B: check SOCKS5_CHECK_MESSAGE
        B->>+C: SSL connect (Socks5 over TLS)
        C->>+D: SSL connect (Socks5 over TLS)
        D->>D: if socks5_over_tls_client_certificate_authentication_flag is 1(on), do client certificate authentication
        B->>+C: socks5 selection request (Socks5 over TLS)
        C->>+D: socks5 selection request (Socks5 over TLS)
        D-->>-C: socks5 selection response (Socks5 over TLS)
        C-->>-B: socks5 selection response (Socks5 over TLS)
        B-->>-A: socks5 selection response (Socks5)
        alt socks5 server authentication method is username/password authentication
        A->>+B: socks5 username/password authentication request (Socks5)
        B->>+C: socks5 username/password authentication request (Socks5 over TLS)
        C->>+D: socks5 username/password authentication request (Socks5 over TLS)
        D->>D: check username and password
        D-->>-C: socks5 username/password authentication response (Socks5 over TLS)
        C-->>-B: socks5 username/password authentication response (Socks5 over TLS)
        B-->>-A: socks5 username/password authentication response (Socks5)
        end
        A->>+B: socks5 socks request (Socks5)
        B->>+C: socks5 socks request (Socks5 over TLS)
        C->>+D: socks5 socks request (Socks5 over TLS)
        D->>+E: connection (TCP)
        D->>+E: socks5 selection request (Socks5)
        E-->>-D: socks5 selection response (Socks5)
        D->>+E: socks5 socks request (Socks5)
        E->>+F: check connection (encrypt with TLS)
        F->>+G: check connection (TCP)
        G-->>F: 
        F-->>E: 
        E-->>-D: socks5 socks response (Socks5)
        D-->>-C: socks5 socks response (Socks5 over TLS)
        C-->>-B: socks5 socks response (Socks5 over TLS)
        B-->>-A: socks5 socks response (Socks5)
        loop until communication ends (forwarder)
            A->>+B: request
            B->>+C: request (encrypt with TLS)
            C->>+D: request (encrypt with TLS)
            D->>+E: request
            E->>+F: request (encrypt with TLS)
            F->>+G: request
            G-->>-F: response
            F-->>-E: response (encrypt with TLS)
            E-->>-D: response
            D-->>-C: response (encrypt with TLS)
            C-->>-B: response (encrypt with TLS)
            B-->>-A: response
        end
        G-->>-F: 
        F-->>-E: 
        E-->>-D: 
        D-->>-C: 
        C-->>-B: 
        D-->>-C: HTTP GET Response (HTTPS)
        C-->>-B: HTTP GET Response (HTTPS)
        D-->>-C: 
        C-->>-B: 
        D-->>-C: 
        C-->>-B: 
        B-->>-A: 
    end
```

## Installation
### Install dependencies
- server
    - gcc and make
    - nginx
    - openssl and libssl-dev
    - tor (optional)
    ```
    sudo apt install gcc make nginx libpcre3 libpcre3-dev zlib1g zlib1g-dev openssl libssl-dev
    sudo apt install tor
    ```

- client
    - gcc and make
    - openssl and libssl-dev
    - krb5-user, libkrb5-3 and libkrb5-dev
    ```
    sudo apt install gcc make openssl libssl-dev krb5-user libkrb5-3 libkrb5-dev
    ```

### Version
I tested this module using the following version.
- Debian 12
- nginx 1.24.0
- openssl 3.0.10

### Install
#### 1. download the latest [socks5 nginx module v2](https://github.com/shuichiro-endo/socks5-nginx-module-v2)
```
git clone https://github.com/shuichiro-endo/socks5-nginx-module-v2.git
```

#### 2. build and install
- server
    1. set up HTTPS on the nginx
    2. get the nginx version
    ```
    /usr/sbin/nginx -v
    ```
    3. download the nginx open source release
    ```
    cd socks5-nginx-module-v2
    wget https://nginx.org/download/nginx-x.xx.x.tar.gz
    tar -xzvf nginx-x.xx.x.tar.gz
    ```
    4. change privatekey and certificate (See [How to change socks5 server privatekey and certificate (for Socks5 over TLS)](https://github.com/shuichiro-endo/socks5-nginx-module-v2#how-to-change-socks5-server-privatekey-and-certificate-for-socks5-over-tls).)
    5. build my module (dynamic module)
    ```
    cd nginx-x.xx.x
    ./configure --with-compat --add-dynamic-module=../server --with-ld-opt="-lssl -lcrypto"
    make modules
    ```
    6. copy the module library (.so file) to the nginx modules directory
    ```
    ls -l /usr/share/nginx/modules/
    mkdir -p /usr/lib/nginx/modules
    sudo cp objs/ngx_http_socks5_module.so /usr/share/nginx/modules/
    ```
    7. load the module library
    ```
    sudo sh -c 'echo "load_module modules/ngx_http_socks5_module.so;" > /etc/nginx/modules-available/ngx_http_socks5_module.conf'
    sudo ln -s /etc/nginx/modules-available/ngx_http_socks5_module.conf /etc/nginx/modules-enabled/ngx_http_socks5_module.conf
    sudo systemctl restart nginx
    ```

- client
    1. copy ssl/tls server certificate (HTTPS, Socks5 over TLS) to my client directory
    ```
    cp xxx.crt socks5-nginx-module-v2/client/server_https.crt
    cp yyy.crt socks5-nginx-module-v2/client/server_socks5.crt
    ```
    2. modify client.c file (if you change the certificate filename or directory path)
    ```
    char server_certificate_filename_https[256] = "./server_https.crt";     // server certificate filename (HTTPS)
    
    char server_certificate_filename_socks5[256] = "./server_socks5.crt";   // server certificate filename (Socks5 over TLS)
    ```
    3. build
    ```
    cd socks5-nginx-module-v2/client
    make
    ```

## Usage
- server
    1. run nginx server
    ```
    sudo systemctl start nginx
    ```
    2. connect to my server from my client

- client
    1. change character encoding in terminal (UTF-8, e.g. en_US.UTF-8)

    2. run my client
    ```
    usage   : ./client -h listen_domainname -p listen_port -H target_socks5server_domainname -P target_socks5server_https_port
              [-A recv/send tv_sec(timeout 0-60 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)]
              [-C forwarder tv_sec(timeout 0-300 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]
              [-a forward proxy domainname] [-b forward proxy port] [-c forward proxy(1:http 2:https)]
              [-d forward proxy authentication(1:basic 2:digest 3:ntlmv2 4:spnego(kerberos))]
              [-e forward proxy username] [-f forward proxy password] [-g forward proxy user domainname]
              [-i forward proxy workstationname] [-j forward proxy service principal name] [-k forward proxy nthash hexstring]
              [-t (tor connection)]
              [-u (client certificate authentication(socks5 over tls))]
    example : ./client -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 443
            : ./client -h localhost -p 9050 -H foobar.test -P 443
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -A 3 -B 0 -C 3 -D 0
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -a proxy.test.local -b 3128 -c 1
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -a 127.0.0.1 -b 3128 -c 1 -d 1 -e forward_proxy_user -f forward_proxy_password
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -a 127.0.0.1 -b 3128 -c 1 -d 2 -e forward_proxy_user -f forward_proxy_password
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -a 127.0.0.1 -b 3128 -c 1 -d 3 -e forward_proxy_user -f forward_proxy_password -g forward_proxy_user_domainname -i forward_proxy_workstationname
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -a 127.0.0.1 -b 3128 -c 1 -d 3 -e test01 -f p@ssw0rd -g test.local -i WORKSTATION -A 10
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -a 127.0.0.1 -b 3128 -c 1 -d 3 -e forward_proxy_user -g forward_proxy_user_domainname -i forward_proxy_workstationname -k forward_proxy_nthash_hexstring
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -a 127.0.0.1 -b 3128 -c 1 -d 3 -e test01 -g test.local -i WORKSTATION -k de26cce0356891a4a020e7c4957afc72 -A 10
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -a 127.0.0.1 -b 3128 -c 1 -d 4 -j forward_proxy_service_principal_name
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -a 127.0.0.1 -b 3128 -c 1 -d 4 -j HTTP/proxy.test.local@TEST.LOCAL -A 10
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -t -A 10 -C 20
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -a 127.0.0.1 -b 3128 -c 1 -d 3 -e test01 -f p@ssw0rd -g test.local -i WORKSTATION -t -A 20 -C 20
            : ./client -h ::1 -p 9050 -H foobar.test -P 443 -a fe80::xxxx:xxxx:xxxx:xxxx%eth0 -b 3128 -c 1 -d 3 -e test01 -f p@ssw0rd -g test.local -i WORKSTATION -t -A 20 -C 20
    ```
    Note: The forward proxy (2:https) connection is an experimental function.
    
    3. connect to my client from other clients (browser, proxychains, ...)
    ```
    proxychains4 curl -v https://www.google.com
    curl -v -x socks5h://127.0.0.1:9050 https://www.google.com
    curl -v -x socks5h://127.0.0.1:9050 https://check.torproject.org/api/ip
    curl -v -x socks5h://127.0.0.1:9050 https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion
    ```

## Troubleshooting
### How to get nginx logs (for socks5 nginx module)
- server
    1. modify /etc/nginx/nginx.conf file (set the debug level of the error_log directive)
    ```
    ...
    error_log /var/log/nginx/error.log debug;
    ...
    ```
    2. modify ngx_http_socks5_module.c file (uncomment the following #define preprocessor directive)
    ```
    ...
    #define _DEBUG
    ...
    ```
    3. build my module (dynamic module)
    ```
    cd socks5-nginx-module-v2/nginx-x.xx.x
    ./configure --with-compat --add-dynamic-module=../server --with-ld-opt="-lssl -lcrypto"
    make modules
    ```
    4. copy the module library (.so file) to the nginx modules directory
    ```
    sudo cp objs/ngx_http_socks5_module.so /usr/share/nginx/modules/
    ```
    5. restart nginx server
    ```
    sudo systemctl restart nginx
    ```
    6. read error.log file
    ```
    sudo tail -f /var/log/nginx/error.log
    ```

### How to reduce number of connections in CLOSE_WAIT state
You can check number of connections in CLOSE_WAIT state by running the following command.
```
sudo ss -p --tcp state CLOSE-WAIT
```
If there are many connections in CLOSE_WAIT state, you can do the following.
- change the value of tcp_keepalive_time, tcp_keepalive_probes and tcp_keepalive_intvl (temporary)
    1. check the value before the changes
    ```
    cat /proc/sys/net/ipv4/tcp_keepalive_time
    cat /proc/sys/net/ipv4/tcp_keepalive_probes
    cat /proc/sys/net/ipv4/tcp_keepalive_intvl
    ```
    2. change the value
    ```
    sudo sh -c "echo 10 > /proc/sys/net/ipv4/tcp_keepalive_time"
    sudo sh -c "echo 2 > /proc/sys/net/ipv4/tcp_keepalive_probes"
    sudo sh -c "echo 3 > /proc/sys/net/ipv4/tcp_keepalive_intvl"
    ```
    3. check the value after the changes
    ```
    cat /proc/sys/net/ipv4/tcp_keepalive_time
    cat /proc/sys/net/ipv4/tcp_keepalive_probes
    cat /proc/sys/net/ipv4/tcp_keepalive_intvl
    ```
    4. restart client and server

- change the value of tcp_keepalive_time, tcp_keepalive_probes and tcp_keepalive_intvl (permanent)
    1. modify /etc/sysctl.conf file
    ```
    net.ipv4.tcp_keepalive_time = 10
    net.ipv4.tcp_keepalive_intvl = 3
    net.ipv4.tcp_keepalive_probes = 2
    ```
    2. check the value
    ```
    sudo sysctl -p
    ```
    3. reboot
    4. start client and server

- restart client and server

### Forward proxy authentication (3:ntlmv2)
In Active Directory, if an Active Directory username contains an accent mark (e.g. é), the character may be converted to another character (e.g. é -> e).

My client (Linux) does not have the ability to convert it automatically.

Therefore, the username must be converted manually.

- example
```
username:àéîõüåç       -> aeiouac
password:pàßßw0rð@

> ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -a 127.0.0.1 -b 3128 -c 1 -d 3 -e aeiouac -f pàßßw0rð@ -g test.local -i WORKSTATION -A 10
[I] Forward proxy connection:http
[I] Forward proxy authentication:ntlmv2
[I] Forward proxy username:aeiouac
[I] Forward proxy password:pàßßw0rð@
[I] Forward proxy user domainname:test.local
[I] Forward proxy workstationname:WORKSTATION
[I] Timeout recv/send tv_sec(0-60  sec): 10 sec recv/send tv_usec(0-1000000 microsec):      0 microsec
[I] Timeout forwarder tv_sec(0-300 sec):  3 sec forwarder tv_usec(0-1000000 microsec):      0 microsec
[I] [client -> server] Listening port 9050 on 0.0.0.0
[I] [client <- server] Connected from 127.0.0.1
[I] Forward proxy domainname:127.0.0.1, Length:9
[I] [server -> fproxy] Connecting ip:127.0.0.1 port:3128
[I] [server <- fproxy] Connected to forward proxy server
[I] negotiate_message ntlm_b64:TlRMTVNTUAABAAAABoIIAAAAAAAAAAAAAAAAAAAAAAA= ntlm_negotiate_message_length:32
[I] [server -> fproxy] Send http request to forward proxy
[I] [server <- fproxy] Recv http response from forward proxy
[I] http_header_data:Proxy-Authenticate: NTLM TlRMTVNTUAACAAAABAAEADgAAAAGgokC1Sw1WyqBO6EAAAAAAAAAAGoAagA8AAAABgEAAAAAAA9URVNUAgAIAFQARQBTAFQAAQAMAEQARQBCAEkAQQBOAAQAFAB0AGUAcwB0AC4AbABvAGMAYQBsAAMAIgBkAGUAYgBpAGEAbgAuAHQAZQBzAHQALgBsAG8AYwBhAGwABwAIABjeNwTKDtoBAAAAAA==
[I] authenticate_message ntlm_b64:TlRMTVNTUAADAAAAGAAYAEAAAACaAJoAWAAAAAoACgDyAAAABwAHAPwAAAALAAsAAwEAAAAAAAAAAAAABoKJAqXxKHGFLTY9SKn3Dz3ytVagU+ee6leU6AiNWv7/cAzXzyr10zNa+kMBAQAAAAAAAIDKwAPKDtoBoFPnnupXlOgAAAAAAgAIAFQARQBTAFQAAQAMAEQARQBCAEkAQQBOAAQAFAB0AGUAcwB0AC4AbABvAGMAYQBsAAMAIgBkAGUAYgBpAGEAbgAuAHQAZQBzAHQALgBsAG8AYwBhAGwABwAIABjeNwTKDtoBAAAAAAAAAAB0ZXN0LmxvY2FsYWVpb3VhY1dPUktTVEFUSU9O
[I] [server -> fproxy] Send http request to forward proxy
[I] [server <- fproxy] Recv http response from forward proxy
[I] Forward proxy connection established
[I] [server -> target] Try HTTPS connection (SSL_connect)
[I] [server <- target] Succeed HTTPS connection (SSL_connect)
[I] [server -> target] Send http request
[I] [server <- target] count:1 rec:9
[I] [server <- target] Server Socks5 OK
[I] [server -> target] Try Socks5 over TLS connection (BIO_do_handshake)
[I] [server <- target] Succeed Socks5 over TLS connection (BIO_do_handshake)
[I] [client -> server] Receive selection request:4 bytes
[I] [server -> target] Send selection request:4 bytes
[I] [server <- target] Receive selection response:2 bytes
[I] [client <- server] Send selection response:2 bytes
[I] [client -> server] Receive socks request:21 bytes
[I] [server -> target] Send socks request:21 bytes
[I] [server <- target] Receive socks response:10 bytes
[I] [client <- server] Send socks response:10 bytes
[I] Forwarder
[I] forwarder_bio recv error:0
[I] Worker exit
```

### Forward proxy authentication (4:spnego(kerberos))
If you receive the following error message, you may not have a ticket (TGT).
```
[E] gss_init_sec_context error:
An unsupported mechanism was requested.
The routine must be called again to complete its function.
An invalid status code was supplied.
An invalid status code was supplied.
An invalid status code was supplied.
An invalid status code was supplied.
An invalid status code was supplied.
[E] get_base64_kerberos_token error
[E] forward_proxy_authentication_spnego error
```
You need to get a ticket (TGT) as follows.
```
> klist
klist: No credentials cache found (filename: /tmp/krb5cc_1000)

> kinit test02@TEST.LOCAL
Password for test02@TEST.LOCAL:

> klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: test02@TEST.LOCAL

Valid starting       Expires              Service principal
01/26/2024 03:59:36  01/26/2024 13:59:36  krbtgt/TEST.LOCAL@TEST.LOCAL
	renew until 01/27/2024 03:59:33
```

## Notes
### How to change HTTP Request Header Key and Value
Note: There are characters that cannot be used in the HTTP Request Header Key or Value.
- server
    1. modify ngx_http_socks5_module.c file
    ```
    #define HTTP_REQUEST_HEADER_SOCKS5_KEY "socks5"
    #define HTTP_REQUEST_HEADER_SOCKS5_VALUE "socks5"
    #define HTTP_REQUEST_HEADER_TOR_KEY "tor"
    #define HTTP_REQUEST_HEADER_TOR_VALUE_ON "on"
    #define HTTP_REQUEST_HEADER_TOR_VALUE_OFF "off"
    #define HTTP_REQUEST_HEADER_TVSEC_KEY "sec"     // recv/send tv_sec
    #define HTTP_REQUEST_HEADER_TVUSEC_KEY "usec"   // recv/send tv_usec
    #define HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY "forwardersec"      // forwarder tv_sec
    #define HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY "forwarderusec"    // forwarder tv_usec
    ```
    2. build my module (dynamic module)
    ```
    cd socks5-nginx-module-v2/nginx-x.xx.x
    ./configure --with-compat --add-dynamic-module=../server --with-ld-opt="-lssl -lcrypto"
    make modules
    ```
    3. copy the module library (.so file) to the nginx modules directory
    ```
    sudo cp objs/ngx_http_socks5_module.so /usr/share/nginx/modules/
    ```
    4. restart nginx server
    ```
    sudo systemctl restart nginx
    ```

- client
    1. modify client.c file
    ```
    #define HTTP_REQUEST_HEADER_SOCKS5_KEY "socks5"
    #define HTTP_REQUEST_HEADER_SOCKS5_VALUE "socks5"
    #define HTTP_REQUEST_HEADER_TOR_KEY "tor"
    #define HTTP_REQUEST_HEADER_TOR_VALUE_ON "on"
    #define HTTP_REQUEST_HEADER_TOR_VALUE_OFF "off"
    #define HTTP_REQUEST_HEADER_TVSEC_KEY "sec"     // recv/send tv_sec
    #define HTTP_REQUEST_HEADER_TVUSEC_KEY "usec"   // recv/send tv_usec
    #define HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY "forwardersec"      // forwarder tv_sec
    #define HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY "forwarderusec"    // forwarder tv_usec
    #define HTTP_REQUEST_HEADER_USER_AGENT_VALUE "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246"
    
    ...
    
    if(tor_connection_flag == 0){	// tor connection: off
        if(strstr(target_domainname, ":") == NULL){	// no ipv6 address
            http_request_length = snprintf(http_request, BUFFER_SIZE+1, "GET / HTTP/1.1\r\nHost: %s:%s\r\nUser-Agent: %s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n%s: %s\r\n%s: %s\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\nConnection: close\r\n\r\n", target_domainname, target_port_number, HTTP_REQUEST_HEADER_USER_AGENT_VALUE, HTTP_REQUEST_HEADER_SOCKS5_KEY, HTTP_REQUEST_HEADER_SOCKS5_VALUE, HTTP_REQUEST_HEADER_TOR_KEY, HTTP_REQUEST_HEADER_TOR_VALUE_OFF, HTTP_REQUEST_HEADER_TVSEC_KEY, tv_sec, HTTP_REQUEST_HEADER_TVUSEC_KEY, tv_usec, HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY, forwarder_tv_sec, HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY, forwarder_tv_usec);
        }else{	// ipv6 address
            http_request_length = snprintf(http_request, BUFFER_SIZE+1, "GET / HTTP/1.1\r\nHost: [%s]:%s\r\nUser-Agent: %s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n%s: %s\r\n%s: %s\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\nConnection: close\r\n\r\n", target_domainname, target_port_number, HTTP_REQUEST_HEADER_USER_AGENT_VALUE, HTTP_REQUEST_HEADER_SOCKS5_KEY, HTTP_REQUEST_HEADER_SOCKS5_VALUE, HTTP_REQUEST_HEADER_TOR_KEY, HTTP_REQUEST_HEADER_TOR_VALUE_OFF, HTTP_REQUEST_HEADER_TVSEC_KEY, tv_sec, HTTP_REQUEST_HEADER_TVUSEC_KEY, tv_usec, HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY, forwarder_tv_sec, HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY, forwarder_tv_usec);
        }
    }else{	// tor connection: on
        if(strstr(target_domainname, ":") == NULL){	// no ipv6 address
            http_request_length = snprintf(http_request, BUFFER_SIZE+1, "GET / HTTP/1.1\r\nHost: %s:%s\r\nUser-Agent: %s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n%s: %s\r\n%s: %s\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\nConnection: close\r\n\r\n", target_domainname, target_port_number, HTTP_REQUEST_HEADER_USER_AGENT_VALUE, HTTP_REQUEST_HEADER_SOCKS5_KEY, HTTP_REQUEST_HEADER_SOCKS5_VALUE, HTTP_REQUEST_HEADER_TOR_KEY, HTTP_REQUEST_HEADER_TOR_VALUE_ON, HTTP_REQUEST_HEADER_TVSEC_KEY, tv_sec, HTTP_REQUEST_HEADER_TVUSEC_KEY, tv_usec, HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY, forwarder_tv_sec, HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY, forwarder_tv_usec);
        }else{	// ipv6 address
            http_request_length = snprintf(http_request, BUFFER_SIZE+1, "GET / HTTP/1.1\r\nHost: [%s]:%s\r\nUser-Agent: %s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n%s: %s\r\n%s: %s\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\n%s: %ld\r\nConnection: close\r\n\r\n", target_domainname, target_port_number, HTTP_REQUEST_HEADER_USER_AGENT_VALUE, HTTP_REQUEST_HEADER_SOCKS5_KEY, HTTP_REQUEST_HEADER_SOCKS5_VALUE, HTTP_REQUEST_HEADER_TOR_KEY, HTTP_REQUEST_HEADER_TOR_VALUE_ON, HTTP_REQUEST_HEADER_TVSEC_KEY, tv_sec, HTTP_REQUEST_HEADER_TVUSEC_KEY, tv_usec, HTTP_REQUEST_HEADER_FORWARDER_TVSEC_KEY, forwarder_tv_sec, HTTP_REQUEST_HEADER_FORWARDER_TVUSEC_KEY, forwarder_tv_usec);
        }
    }
    ```
    2. build
    ```
    cd socks5-nginx-module-v2/client
    make
    ```

### How to change SOCKS5_CHECK_MESSAGE
- server
    1. modify ngx_http_socks5_module.c file
    ```
    #define SOCKS5_CHECK_MESSAGE "socks5 ok"
    ```
    2. build my module (dynamic module)
    ```
    cd socks5-nginx-module-v2/nginx-x.xx.x
    ./configure --with-compat --add-dynamic-module=../server --with-ld-opt="-lssl -lcrypto"
    make modules
    ```
    3. copy the module library (.so file) to the nginx modules directory
    ```
    sudo cp objs/ngx_http_socks5_module.so /usr/share/nginx/modules/
    ```
    4. restart nginx server
    ```
    sudo systemctl restart nginx
    ```

- client
    1. modify client.c file
    ```
    #define SOCKS5_CHECK_MESSAGE "socks5 ok"
    ```
    2. build
    ```
    cd socks5-nginx-module-v2/client
    make
    ```

### How to change socks5 server Authentication Method
- server
    1. modify ngx_http_socks5_module.c file
    ```
    static char authentication_method = 0x0;	// 0x0:No Authentication Required  0x2:Username/Password Authentication
    static char username[256] = "socks5user";
    static char password[256] = "supersecretpassword";
    ```
    2. build my module(dynamic module)
    ```
    cd socks5-nginx-module-v2/nginx-x.xx.x
    ./configure --with-compat --add-dynamic-module=../server --with-ld-opt="-lssl -lcrypto"
    make modules
    ```
    2. copy the module library (.so file) to the nginx modules directory
    ```
    sudo cp objs/ngx_http_socks5_module.so /usr/share/nginx/modules/
    ```
    3. restart nginx server
    ```
    sudo systemctl restart nginx
    ```

### How to change socks5 server privatekey and certificate (for Socks5 over TLS)
- server
    1. generate server privatekey, publickey and certificate
    ```
    openssl req -x509 -days 3650 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -subj /CN=localhost -outform PEM -keyout server_socks5_private.key -out server_socks5.crt
    openssl x509 -text -noout -in server_socks5.crt
    ```
    2. copy the server privatekey and certificate
    ```
    cat server_socks5_private.key | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END PRIVATE KEY-----\\n"\\/"-----END PRIVATE KEY-----\\n";/g'
    cat server_socks5.crt | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END CERTIFICATE-----\\n"\\/"-----END CERTIFICATE-----\\n";/g'
    ```
    3. paste the privatekey and certificate into serverkey.h file
    ```
    char server_privatekey_socks5[] = "-----BEGIN PRIVATE KEY-----\n"\
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpEIBK1hhvc+HVJRk\n"\
    "QfpifIMOPxLIRJovTxjhFlnHJLihRANCAAQndxVggZiwxAQoi8ZysOmtC4U3Ufrx\n"\
    "skaIMBrDIi3Myanw8NtNaVaW/CzdzeG+U5sWx5IFA4iHyhOSp2hxi1Uo\n"\
    "-----END PRIVATE KEY-----\n";
    
    char server_certificate_socks5[] = "-----BEGIN CERTIFICATE-----\n"\
    "MIIBfjCCASOgAwIBAgIUWg2F5a7tuHBZcOuOQmQp7A9YEw8wCgYIKoZIzj0EAwIw\n"\
    "FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTIzMTEwODA3NTI0OFoXDTMzMTEwNTA3\n"\
    "NTI0OFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"\
    "AQcDQgAEJ3cVYIGYsMQEKIvGcrDprQuFN1H68bJGiDAawyItzMmp8PDbTWlWlvws\n"\
    "3c3hvlObFseSBQOIh8oTkqdocYtVKKNTMFEwHQYDVR0OBBYEFBRxce8YQWc4Z1Dc\n"\
    "vBgZndjGdTceMB8GA1UdIwQYMBaAFBRxce8YQWc4Z1DcvBgZndjGdTceMA8GA1Ud\n"\
    "EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhALIk//w4qN3Q4iVCyNgTeP1Z\n"\
    "SpiWrOcI+QYFQfgBSbAmAiEA34doDamtu1nhZXz6gka0ImX9I11HZiELVHlT3/BT\n"\
    "0pY=\n"\
    "-----END CERTIFICATE-----\n";
    ```
    4. build my module (dynamic module)
    ```
    cd socks5-nginx-module-v2/nginx-x.xx.x
    ./configure --with-compat --add-dynamic-module=../server --with-ld-opt="-lssl -lcrypto"
    make modules
    ```
    5. copy the module library (.so file) to the nginx modules directory
    ```
    ls -l /usr/share/nginx/modules/
    mkdir -p /usr/lib/nginx/modules
    sudo cp objs/ngx_http_socks5_module.so /usr/share/nginx/modules/
    ```
    6. restart nginx server
    ```
    sudo systemctl restart nginx
    ```

- client
    1. copy server_socks5.crt file to my client directory
    ```
    cp server_socks5.crt socks5-nginx-module-v2/client/server_socks5.crt
    ```
    2. modify client.c file (if you change the certificate filename or directory path)
    ```
    char server_certificate_filename_socks5[256] = "./server_socks5.crt";   // server certificate filename (Socks5 over TLS)
    ```
    3. build (if you change the certificate filename or directory path)
    ```
    cd socks5-nginx-module-v2/client
    make
    ```

### How to change socks5 server cipher suite TLS1.2, TLS1.3 (for Socks5 over TLS)
- server
    1. select cipher suite (TLS1.2) and check
    ```
    openssl ciphers -v "AESGCM+ECDSA:CHACHA20+ECDSA:+AES256"
    ```
    2. select cipher suite (TLS1.3) [https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_ciphersuites.html](https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_ciphersuites.html)
    ```
    TLS_AES_128_GCM_SHA256
    TLS_AES_256_GCM_SHA384
    TLS_CHACHA20_POLY1305_SHA256
    TLS_AES_128_CCM_SHA256
    TLS_AES_128_CCM_8_SHA256
    ```
    3. modify ngx_http_socks5_module.c file
    ```
    char cipher_suite_tls_1_2[1000] = "AESGCM+ECDSA:CHACHA20+ECDSA:+AES256";                                        // TLS1.2
    char cipher_suite_tls_1_3[1000] = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"; // TLS1.3
    ```
    4. build my module (dynamic module)
    ```
    cd socks5-nginx-module-v2/nginx-x.xx.x
    ./configure --with-compat --add-dynamic-module=../server --with-ld-opt="-lssl -lcrypto"
    make modules
    ```
    5. copy the module library (.so file) to the nginx modules directory
    ```
    sudo cp objs/ngx_http_socks5_module.so /usr/share/nginx/modules/
    ```
    6. restart nginx server
    ```
    sudo systemctl restart nginx
    ```

### How to set up client certificate authentication (for Socks5 over TLS)
- client
    1. generate client privatekey, publickey and certificate
    ```
    openssl req -x509 -days 3650 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -subj /CN=localhost -outform PEM -keyout client_socks5_private.key -out client_socks5.crt
    openssl x509 -text -noout -in client_socks5.crt
    ```
    2. copy the client privatekey and certificate
    ```
    cat client_socks5_private.key | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END PRIVATE KEY-----\\n"\\/"-----END PRIVATE KEY-----\\n";/g'
    cat client_socks5.crt | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END CERTIFICATE-----\\n"\\/"-----END CERTIFICATE-----\\n";/g'
    ```
    3. paste the privatekey and certificate into clientkey.h file
    ```
    char client_privatekey_socks5[] = "-----BEGIN PRIVATE KEY-----\n"\
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVlI3ePznE9rDgA8t\n"\
    "89jlF1ycGs3NRZxENRO3wuPvKkuhRANCAASTnYHeV4BiCybI7xQyOSS24I6np6bp\n"\
    "i4rXxqVammICpvBiYNJMACzWlUUeGtFBAQzOcUim9zf9cDq/nW9o1jEg\n"\
    "-----END PRIVATE KEY-----\n";

    char client_certificate_socks5[] = "-----BEGIN CERTIFICATE-----\n"\
    "MIIBfjCCASOgAwIBAgIUJGmCvAtce4aM07rJQ3ZzS2HTZkgwCgYIKoZIzj0EAwIw\n"\
    "FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI0MDIxOTIyMTMzMFoXDTM0MDIxNjIy\n"\
    "MTMzMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"\
    "AQcDQgAEk52B3leAYgsmyO8UMjkktuCOp6em6YuK18alWppiAqbwYmDSTAAs1pVF\n"\
    "HhrRQQEMznFIpvc3/XA6v51vaNYxIKNTMFEwHQYDVR0OBBYEFMcnL1L1q2KPB+7f\n"\
    "4eJDoRtGxo+/MB8GA1UdIwQYMBaAFMcnL1L1q2KPB+7f4eJDoRtGxo+/MA8GA1Ud\n"\
    "EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAKZLK9oM8NbY1RMUb4LnWpIJ\n"\
    "CZJbhZeupqlLaJOh9tmwAiEArEyZm8JkP0VodyQ5k/9kbOiKpwBwGseMh3UHLUb+\n"\
    "jhM=\n"\
    "-----END CERTIFICATE-----\n";
    ```
    4. build
    ```
    cd socks5-nginx-module-v2/client
    make
    ```

- server
    1. copy client_socks5.crt file to server directory (e.g. /etc/nginx/certs/)
    ```
    sudo mkdir /etc/nginx/certs
    sudo chmod 755 /etc/nginx/certs
    sudo cp client_socks5.crt /etc/nginx/certs/
    sudo chmod 644 /etc/nginx/certs/client_socks5.crt
    ```
    2. modify ngx_http_socks5_module.c file
    ```
    int socks5_over_tls_client_certificate_authentication_flag = 1;	// 0:off 1:on
    char client_certificate_filename_socks5[256] = "/etc/nginx/certs/client_socks5.crt";	// client certificate filename (Socks5 over TLS)
    ```
    3. build my module (dynamic module)
    ```
    cd socks5-nginx-module-v2/nginx-x.xx.x
    ./configure --with-compat --add-dynamic-module=../server --with-ld-opt="-lssl -lcrypto"
    make modules
    ```
    4. copy the module library (.so file) to the nginx modules directory
    ```
    sudo cp objs/ngx_http_socks5_module.so /usr/share/nginx/modules/
    ```
    5. restart nginx server
    ```
    sudo systemctl restart nginx
    ```

### How to change ip address and port number for tor connection
- server
    1. modify ngx_http_socks5_module.c file
    ```
    char tor_client_ip[256] = "127.0.0.1";
    char tor_client_ip_atyp = 0x1;		// ipv4:0x1 domainname:0x3 ipv6:0x4
    uint16_t tor_client_port = 9050;
    ```
    2. build my module(dynamic module)
    ```
    cd socks5-nginx-module-v2/nginx-x.xx.x
    ./configure --with-compat --add-dynamic-module=../server --with-ld-opt="-lssl -lcrypto"
    make modules
    ```
    3. copy the module library (.so file) to the nginx modules directory
    ```
    sudo cp objs/ngx_http_socks5_module.so /usr/share/nginx/modules/
    ```
    4. restart nginx server
    ```
    sudo systemctl restart nginx
    ```

## License
This project is licensed under the MIT License.

See the [LICENSE](https://github.com/shuichiro-endo/socks5-nginx-module-v2/blob/main/LICENSE) file for details.

