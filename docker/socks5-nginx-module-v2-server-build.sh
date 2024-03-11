#!/bin/bash
#
#  Title:  socks5-nginx-module-v2-server-build.sh
#  Author: Shuichiro Endo
#

set -e

NGINX_VERSION=$(nginx -v 2>&1 | awk -F/ '{print $2}')

cd /root/socks5-nginx-module-v2
echo -n "char server_privatekey_socks5[] = " > /root/socks5-nginx-module-v2/server/serverkey.h
cat /root/socks5-nginx-module-v2/server/server_socks5_private.key | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END PRIVATE KEY-----\\n"\\/"-----END PRIVATE KEY-----\\n";/g' >> /root/socks5-nginx-module-v2/server/serverkey.h
echo "" >> /root/socks5-nginx-module-v2/server/serverkey.h
echo -n "char server_certificate_socks5[] = " >> /root/socks5-nginx-module-v2/server/serverkey.h
cat /root/socks5-nginx-module-v2/server/server_socks5.crt | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END CERTIFICATE-----\\n"\\/"-----END CERTIFICATE-----\\n";/g' >> /root/socks5-nginx-module-v2/server/serverkey.h
echo "" >> /root/socks5-nginx-module-v2/server/serverkey.h

cd /root/socks5-nginx-module-v2
wget https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz
tar -xzvf nginx-$NGINX_VERSION.tar.gz

cd /root/socks5-nginx-module-v2/nginx-$NGINX_VERSION
./configure --with-compat --add-dynamic-module=../server --with-ld-opt="-lssl -lcrypto"
make modules

mkdir -p /usr/lib/nginx/modules
cp objs/ngx_http_socks5_module.so /usr/share/nginx/modules/
chown root:root /usr/share/nginx/modules/ngx_http_socks5_module.so
chmod 700 /usr/share/nginx/modules/ngx_http_socks5_module.so
sh -c 'echo "load_module modules/ngx_http_socks5_module.so;" > /etc/nginx/modules-available/ngx_http_socks5_module.conf'
ln -s /etc/nginx/modules-available/ngx_http_socks5_module.conf /etc/nginx/modules-enabled/ngx_http_socks5_module.conf

