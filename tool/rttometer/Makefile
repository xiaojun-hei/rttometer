# RTTometer -- An adaptive RTT measurement tool using TCP packets
# Copyright (c) 2003 Amgad Zeitoun, The University of Michigan, Ann Arbor

CC = gcc
CFLAGS = -g -Wall -I/usr/local/include -L/usr/local/lib

rtometer: rttometer.c hashtable.c queue.c mode.c
	$(CC) $(CFLAGS) `libnet-config --defines` \
		-o rttometer rttometer.c hashtable.c queue.c mode.c\
		`libnet-config --libs` -lpcap

distrib: clean changelog man

changelog: rttometer.c Makefile
	perl -000 -ne 'next unless (/\*\s+Revision\s+history:/); \
		print "Extracted from rttometer.c:\n\n$$_"; exit;' \
		< rttometer.c | expand -t 4 > changelog

clean:
	rm -f core a.out rttometer *~
