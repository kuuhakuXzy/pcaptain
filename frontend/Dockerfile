FROM nginx:alpine

COPY config/nginx.conf /etc/nginx/conf.d/default.conf.template

COPY components/ /usr/share/nginx/html/
COPY config/config.template.js /usr/share/nginx/html/

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]