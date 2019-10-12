# Copyright (c) 2019 Gilles Chehade <gilles@poolp.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# Build environment container
# This container is also used for testing so that final container stay clean

FROM alpine:3.10 as build

RUN apk add --no-cache \
    autoconf \
    automake \
    bison \
    ca-certificates \
    db-dev \
    fts-dev \
    gcc \
    libasr-dev \
    libevent-dev \
    libtool \
    libtool \
    make \
    musl-dev \
    openssl \
    openssl-dev \
    zlib-dev


RUN mkdir -p /var/lib/opensmtpd/empty \
    && adduser _smtpd -h /var/lib/opensmtpd/empty/ -D -H -s /bin/false \
    && adduser _smtpq -h /var/lib/opensmtpd/empty/ -D -H -s /bin/false \
    && mkdir -p /var/lib/opensmtpd/empty \
    && mkdir -p /var/mail \
    && mkdir -p /etc/mail \
    && mkdir -p /var/spool/smtpd

WORKDIR /opensmtpd
COPY . /opensmtpd

# Build opensmtpd
RUN rm -r /usr/local/ \
   && ./bootstrap \
   && ./configure \
        --with-gnu-ld \
        --with-pie \
        --with-table-db \
        --sysconfdir=/etc/mail \
        --with-path-mbox=/var/mail \
        --with-path-empty=/var/lib/opensmtpd/empty \
   && make \
   && make install \
   && chmod 711 /var/spool/smtpd

COPY smtpd/smtpd.conf /etc/mail/smtpd.conf
COPY docker/examples/config/aliases /etc/mail/aliases

# TODO run tests here

#==========================================================
# Release container
#
# OpenSMTPD needs root permissions to open port 25.
# It immediately changes to running as _smtpd after that.


FROM alpine:3.10
LABEL author="Arthur Moore <Arthur.Moore.git@cd-net.net>"
LABEL maintainer="Ihor Antonov <ihor@antonovs.family>"

EXPOSE 25
EXPOSE 465
EXPOSE 587

VOLUME /etc/mail
VOLUME /var/spool/smtpd
WORKDIR /var/spool/smtpd

RUN apk add --no-cache db openssl libevent libasr fts zlib ca-certificates \ 
    && mkdir -p /var/lib/opensmtpd/empty \
    && mkdir -p /var/mail \
    && mkdir -p /etc/mail \
    && mkdir -p /var/spool/smtpd \
    && touch /etc/mail/aliases \
    && adduser _smtpd -h /var/lib/opensmtpd/empty/ -D -H -s /bin/false \
    && adduser _smtpq -h /var/lib/opensmtpd/empty/ -D -H -s /bin/false \
    && chmod 711 /var/spool/smtpd

COPY --from=build /usr/local/ /usr/local/
COPY smtpd/smtpd.conf /etc/mail/smtpd.conf
COPY docker/examples/config/aliases /etc/mail/aliases
COPY docker/docker-entrypoint.sh /docker-entrypoint.sh

ENTRYPOINT [ "/docker-entrypoint.sh" ]

# Explicitly override any previously existing CMD
CMD [ ]
