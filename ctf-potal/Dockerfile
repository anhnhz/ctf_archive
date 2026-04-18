FROM php:8.1-apache

COPY html/ /var/www/html/

RUN mkdir -p /tmp/api-portal/db && \
    chmod 777 /tmp/api-portal/db

EXPOSE 80