#AUTOMAKE_OPTIONS = foreign subdir-objects
AUTOMAKE_OPTIONS = foreign

# what flags you want to pass to the C compiler & linker
#CFLAGS = --pedantic -Wall -std=c99 -O2
#CC = gcc
AM_CFLAGS  = -std=c99 -O2 -g -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700

AM_LFLAGS  = -lsqlite3 \
             -lmysqlclient \
             -lrt \
             -lcrypto \
             -lssl \
             -lpthread

AM_LDFLAGS = -L/usr/local/mysql-8.0.3-rc/lib \
             -L/usr/local/openssl-1.1.0e/lib

AM_CPPFLAGS = -I../inc \
              -I/usr/local/mysql-8.0.3-rc/include \
              -I/usr/local/openssl-1.1.0e/include

Uidaidir = $(includedir)/Uidai

# this lists the binaries to produce, the (non-PHONY, binary) targets in
# the previous manual Makefile
bin_PROGRAMS = Uidai 

UIDAI_SRC = util.c \
            uidai.c \
            otp.c \
            auth.c

UIDAI_INC = type.h \
            common.h \
            uidai.h \
            otp.h \
            auth.h \
            util.h

UAM_SRC = uam/http.c

UAM_INC = uam/http.h

OAUTH20_SRC = oauth20/sslc.c \
              oauth20/oauth20.c

OAUTH20_INC = oauth20/sslc.h \
              oauth20/oauth20.h

ACC_SRC = acc/utility.c \
          acc/net.c \
          acc/tun.c \
          acc/db.c \
          acc/nat.c \
          acc/redir.c \
          acc/timer.c \
          acc/dns.c \
          acc/arp.c \
          acc/dhcp.c \
          acc/icmp.c \
          acc/tcp.c \
          acc/subscriber.c \
          acc/radiusC.c \
          acc/md5.c \
          acc/acc.c

ACC_INC = ../inc/type.h \
          ../inc/common.h \
          ../inc/utility.h \
          ../inc/arp.h \
          ../inc/db.h \
          ../inc/dhcp.h \
          ../inc/dns.h \
          ../inc/icmp.h \
          ../inc/nat.h \
          ../inc/net.h \
          ../inc/packet.h \
          ../inc/tcp.h  \
          ../inc/timer.h \
          ../inc/transport.h \
          ../inc/tun.h \
          ../inc/md5.h \
          ../inc/radiusC.h \
          ../inc/redir.h \
          ../inc/subscriber.h \
          ../inc/acc.h

Uidai_SOURCES = $(UIDAI_SRC)
        
Uidai_HEADERS = $(UIDAI_INC)
             
Uidai_LDFLAGS = $(AM_LDFLAGS)
Uidai_LFLAGS = $(AM_LFLAGS)
Uidai_CFLAGS = $(AM_CFLAGS)
Uidai_CPPFLAGS = $(AM_CPPFLAGS)

LINK = $(LD) -o $@
