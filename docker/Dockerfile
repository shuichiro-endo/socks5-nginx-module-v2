#
#  Title:  socks5 server dockerfile (nginx module)
#  Author: Shuichiro Endo
#

FROM debian:testing-slim

RUN apt-get update \
    && apt-get install -y \
        git\
        wget\
        gcc\
        make\
        nginx\
        libpcre3\
        libpcre3-dev\
        zlib1g\
        zlib1g-dev\
        openssl\
        libssl-dev\
        cron\
        cowsay\
        && apt-get clean\
        && rm -rf /var/lib/apt/lists/*


RUN mkdir /etc/nginx/ssl
#RUN openssl req -x509 -days 3650 -nodes -newkey rsa:4096 -subj /CN=localhost -keyout /etc/nginx/ssl/server_https_private.key -out /etc/nginx/ssl/server_https.crt
COPY server_https_private.key /etc/nginx/ssl/
COPY server_https.crt /etc/nginx/ssl/
COPY ssl.conf /etc/nginx/conf.d/


WORKDIR /root
RUN mkdir /root/script \
    && git clone https://github.com/shuichiro-endo/socks5-nginx-module-v2.git
COPY socks5-nginx-module-v2-server-build.sh /root/script/
COPY server_socks5_private.key /root/socks5-nginx-module-v2/server/
COPY server_socks5.crt /root/socks5-nginx-module-v2/server/
RUN chmod 755 /root/script/socks5-nginx-module-v2-server-build.sh \
    && /root/script/socks5-nginx-module-v2-server-build.sh


WORKDIR /root/script
COPY startup.sh /root/script/
COPY generate_index.sh /root/script/
COPY root /var/spool/cron/crontabs/
RUN chmod 755 /root/script/startup.sh \
    && chmod 755 /root/script/generate_index.sh \
    && chmod 600 /var/spool/cron/crontabs/root \
    && rm -rf /var/www/html/*


EXPOSE 443
CMD ["/root/script/startup.sh"]
