#AUTOMAKE_OPTIONS = foreign subdir-objects
AUTOMAKE_OPTIONS = foreign

# what flags you want to pass to the C compiler & linker
#CFLAGS = --pedantic -Wall -std=c99 -O2
#CC = gcc
AM_CFLAGS  = -std=c99 -O2 -g -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700

AM_LFLAGS  = -lrt \
             -lcrypto \
             -lssl \
             -lpthread

AM_LDFLAGS = -L/usr/local/openssl-1.1.0e/lib

AM_CPPFLAGS = -I/usr/local/openssl-1.1.0e/include

Uidaidir = $(includedir)/uidai

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

Uidai_SOURCES = $(UIDAI_SRC)
        
Uidai_HEADERS = $(UIDAI_INC)
             
Uidai_LDFLAGS = $(AM_LDFLAGS)
Uidai_LFLAGS = $(AM_LFLAGS)
Uidai_CFLAGS = $(AM_CFLAGS)
Uidai_CPPFLAGS = $(AM_CPPFLAGS)

LINK = $(LD) -o $@
