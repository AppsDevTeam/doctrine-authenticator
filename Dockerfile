FROM php:8.1-cli

RUN apt-get update

RUN apt-get install -y git unzip && curl --fail -sSL https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer