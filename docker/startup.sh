#!/bin/bash

set -e

/root/script/generate_index.sh

/etc/init.d/cron start

/usr/sbin/nginx -g "daemon off;"
