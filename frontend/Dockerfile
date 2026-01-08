FROM nginx:alpine

COPY config/config.template.js /usr/share/nginx/html

COPY config/nginx.conf /etc/nginx/conf.d/default.conf.template

COPY components/constant.js /usr/share/nginx/html

COPY components/search-index.html /usr/share/nginx/html/index.html
COPY components/search-style.css /usr/share/nginx/html/
COPY components/search-script.js /usr/share/nginx/html/

COPY components/toast-index.html /usr/share/nginx/html/
COPY components/toast-style.css /usr/share/nginx/html/
COPY components/toast-script.js /usr/share/nginx/html/

COPY components/config-modal.html /usr/share/nginx/html/
COPY components/config-modal-style.css /usr/share/nginx/html/
COPY components/config-modal-script.js /usr/share/nginx/html/

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]
CMD ["nginx", "-g", "daemon off;"]