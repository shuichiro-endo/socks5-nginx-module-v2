# socks5 server dockerfile (nginx module)

## build
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
    2. generate socks5 over tls server privatekey, publickey and certificate
    ```
    cd socks5-nginx-module-v2/docker
    openssl req -x509 -days 3650 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -subj /CN=localhost -outform PEM -keyout server_socks5_private.key -out server_socks5.crt
    openssl x509 -text -noout -in server_socks5.crt
    ```
    3. docker build and run
    ```
    cd socks5-nginx-module-v2/docker
    docker build -t socks5-nginx-image .
    docker run -d -p 443:443 --name socks5-nginx socks5-nginx-image
    docker ps -a
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
    ./client -h 0.0.0.0 -p 9050 -H localhost -P 443 -A 10
    ```
    3. connect to my client from other clients (browser, proxychains, ...)
    ```
    curl -v -x socks5h://127.0.0.1:9050 https://www.google.com
    ```

