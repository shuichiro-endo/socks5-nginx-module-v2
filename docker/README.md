# socks5 server dockerfile (nginx module)

## Build
### 1. download the latest [socks5 nginx module v2](https://github.com/shuichiro-endo/socks5-nginx-module-v2)
```
git clone https://github.com/shuichiro-endo/socks5-nginx-module-v2.git
```

### 2. build
- server
    1. generate https server privatekey and certificate
    ```
    cd socks5-nginx-module-v2/docker
    openssl req -x509 -days 3650 -nodes -newkey rsa:4096 -subj /CN=localhost -outform PEM -keyout server_https_private.key -out server_https.crt
    openssl x509 -text -noout -in server_https.crt
    ```
    2. generate socks5 over tls server privatekey and certificate
    ```
    cd socks5-nginx-module-v2/docker
    openssl req -x509 -days 3650 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -subj /CN=localhost -outform PEM -keyout server_socks5_private.key -out server_socks5.crt
    openssl x509 -text -noout -in server_socks5.crt
    ```
    3. modify Dockerfile and startup.sh files (if you do not use tor)  
    Note: Tor is installed by default in a docker image. If you do not use tor, modify the following files.
    - modify Dockerfile (comment out)
        ```
        ...
        
        # apt
        RUN apt-get update \
            && apt-get install -y \
                vim \
                git \
                wget \
                gcc \
                make \
                nginx \
                libpcre3 \
                libpcre3-dev \
                zlib1g \
                zlib1g-dev \
                openssl \
                libssl-dev \
                cron \
                cowsay \
        #        tor \
            && apt-get clean \
            && rm -rf /var/lib/apt/lists/*
        
        ...

        # tor
        WORKDIR /root
        #COPY torrc /etc/tor/
        
        ...
        ```
        - startup.sh (comment out)
        ```
        set -e
        
        /root/script/generate_index.sh
        
        /etc/init.d/cron start
        
        #/etc/init.d/tor start
        
        /usr/sbin/nginx -g "daemon off;"
        ```
    4. docker build and run
    ```
    cd socks5-nginx-module-v2/docker
    docker build -t socks5-nginx-image .
    docker run -d -p 443:443 --name socks5-nginx socks5-nginx-image
    docker ps -a
    ```
    5. access to the https web server (nginx server in the docker container)
    ```
    > curl -s -k https://localhost
    
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <title>socks5-nginx-module test</title>
    </head>
    
    <body bgcolor="#181818">
    <span style="font-family:monospace;font-size:14px;line-height:1.1ex;color:#c0c0c0;">
    <pre>
    
    
     __________________<br>
    < I &#9829; socks5 ><br>
     ------------------<br>
            \   ^__^<br>
             \  (oo)\_______<br>
                (__)\       )\/\<br>
                    ||----w |<br>
                    ||     ||<br>
    
    
    </pre>
    </span>
    </body>
    </html>
    ```

## Usage
- client
    1. copy ssl/tls server certificate (HTTPS, Socks5 over TLS) to my client directory
    ```
    cp server_https.crt socks5-nginx-module-v2/client/server_https.crt
    cp server_socks5.crt socks5-nginx-module-v2/client/server_socks5.crt
    ```
    2. run my client
    ```
    ./client -h 0.0.0.0 -p 9050 -H localhost -P 443 -A 10 -C 10
    ```
    3. connect to my client from other clients (browser, proxychains, ...)
    ```
    curl -v -x socks5h://127.0.0.1:9050 https://www.google.com
    ```

## Notes
### How to set up client certificate authentication (for Socks5 over TLS, optional)
- client
    1. generate socks5 over tls client privatekey and certificate
    ```
    cd socks5-nginx-module-v2/client
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
    docker start socks5-nginx
    docker cp socks5-nginx-module-v2/client/client_socks5.crt socks5-nginx:/root/
    docker exec -it socks5-nginx bash
    ```
    ```
    cd /root
    mkdir /etc/nginx/certs
    chmod 755 /etc/nginx/certs
    cp /root/client_socks5.crt /etc/nginx/certs/
    chmod 644 /etc/nginx/certs/client_socks5.crt
    ```
    2. modify ngx_http_socks5_module.c file
    ```
    vim /root/socks5-nginx-module-v2/server/ngx_http_socks5_module.c
    ```
    ```
    static int socks5_over_tls_client_certificate_authentication_flag = 1;	// 0:off 1:on
    static char client_certificate_filename_socks5[256] = "/etc/nginx/certs/client_socks5.crt";	// client certificate filename (Socks5 over TLS)
    ```
    3. build my module (dynamic module)
    ```
    cd /root/socks5-nginx-module-v2/nginx-x.xx.x
    ./configure --with-compat --add-dynamic-module=../server --with-ld-opt="-lssl -lcrypto"
    make modules
    ```
    4. copy the module library (.so file) to the nginx modules directory
    ```
    cp objs/ngx_http_socks5_module.so /usr/share/nginx/modules/
    chown root:root /usr/share/nginx/modules/ngx_http_socks5_module.so
    chmod 700 /usr/share/nginx/modules/ngx_http_socks5_module.so
    exit
    ```
    5. restart nginx server
    ```
    docker restart socks5-nginx
    ```

