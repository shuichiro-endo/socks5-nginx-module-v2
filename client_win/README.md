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
4. build
    - client
    ```
    cd socks5-nginx-module-v2\client_win
    compile.bat
    ```
5. copy openssl dll files (libcrypto-3-x64.dll, libssl-3-x64.dll) to the client directory
    - client
    ```
    cd socks5-nginx-module-v2\client_win
    copy "C:\Program Files\OpenSSL\bin\libcrypto-3-x64.dll" .
    copy "C:\Program Files\OpenSSL\bin\libssl-3-x64.dll" .
    ```
