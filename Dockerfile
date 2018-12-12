FROM nginx:latest

ARG MODULE_DIR=ngx-stream-orig-dst-module
ARG MODULE_NAME=ngx_stream_orig_dst_module

RUN apt-get update && apt-get install -y apt-utils \
                                         autoconf \
                                         automake \
                                         build-essential \
                                         curl \
                                         git \
                                         iptables \
                                         libcurl4-openssl-dev \
                                         libgeoip-dev \
                                         liblmdb-dev \
                                         libpcre++-dev \
                                         libtool \
                                         libxml2-dev \
                                         libyajl-dev \
                                         pkgconf \
                                         wget \
                                         zlib1g-dev

ADD module $MODULE_DIR

RUN export NGINX_VERSION_SHORT=`echo ${NGINX_VERSION} | sed 's/-.*//'` && \
    wget http://nginx.org/download/nginx-${NGINX_VERSION_SHORT}.tar.gz && \
    tar zxvf nginx-${NGINX_VERSION_SHORT}.tar.gz && \
    rm -f /nginx-${NGINX_VERSION_SHORT}.tar.gz

RUN export NGINX_VERSION_SHORT=`echo ${NGINX_VERSION} | sed 's/-.*//'` && \
    cd nginx-${NGINX_VERSION_SHORT} && \
    ./configure --with-compat --with-stream --with-debug --add-dynamic-module=../$MODULE_DIR && \
    make modules && \
    cp objs/$MODULE_NAME.so /etc/nginx/modules

#RUN iptables -t nat -N NGINX_REDIRECT && \
#    iptables -t nat -A NGINX_REDIRECT -p tcp -j REDIRECT --to-port 15501

# Modify /etc/nginx/nginx.conf to dynamically load the module.
#RUN sed -i "5i load_module \"modules/$MODULE_NAME.so\";\n" /etc/nginx/nginx.conf
ADD nginx.conf /etc/nginx/nginx.conf
