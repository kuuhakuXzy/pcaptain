#!/bin/sh
envsubst < /usr/share/nginx/html/config.template.js > /usr/share/nginx/html/config.js

envsubst '$NGINX_PORT' < /etc/nginx/conf.d/default.conf.template > /etc/nginx/conf.d/default.conf

#Start NGINX
exec "$@"