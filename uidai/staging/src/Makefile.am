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

staging_uidaidir = $(includedir)/staging

# this lists the binaries to produce, the (non-PHONY, binary) targets in
# the previous manual Makefile
bin_PROGRAMS = staging_uidai 

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

staging_uidai_SOURCES = $(UIDAI_SRC)
        
staging_uidai_HEADERS = $(UIDAI_INC)
             
staging_uidai_LDFLAGS = $(AM_LDFLAGS)
staging_uidai_LFLAGS = $(AM_LFLAGS)
staging_uidai_CFLAGS = $(AM_CFLAGS)
staging_uidai_CPPFLAGS = $(AM_CPPFLAGS)

LINK = $(LD) -o $@
