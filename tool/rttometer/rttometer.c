/* -*- Mode: c; tab-width: 4; indent-tabs-mode: 1; c-basic-offset: 4; -*- */

/*
 * RTTometer -- An adaptive RTT measurement tool using TCP packets.
 *
 * This code was modified by Yunxian Wang from source code by Amgad Zeitoun
 *
 * Copyright (c) 2003 Amgad Zeitoun, the University of Michigan, Ann Arbor
 */


/*
 * Requires libnet (http://www.packetfactory.net/libnet) and libpcap
 * (http://www.tcpdump.org/).  To compile, try something like:
 *
 *	gcc -O2 -Wall `libnet-config --defines` \
 *		-o rtometer rtometer.c `libnet-config --libs` -lpcap
 *
 */

#define VERSION "RTTometer 0.3 (2006-07-22)"
#define BANNER  "Copyright (c) 2003 Amgad Zeitoun, the University of Michigan, Ann Arbor\n"

/*
 * TODO:
 *
 * - GNU autoconf for compilation.
 * - Catch Ctrl-C signal to stop probing.
 *
 */
#include <sys/dir.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <libgen.h> /* For basename() */

#ifndef __OpenBSD__
#include <net/if.h> 
#endif

#include <arpa/inet.h>
#include <libnet.h>
#include <pcap.h>

#ifndef SIOCGIFCONF
#include <sys/sockio.h> /* Solaris, maybe others? */
#endif

#include "hashtable.h"  /* Hashtable to hold pointers to probe packets */
#include "queue.h"      /* Event queue */

#ifndef AF_LINK
#define AF_LINK AF_INET /* BSD defines some AF_INET network interfaces as AF_LINK */
#endif

#if defined (__OpenBSD__) || defined(__FreeBSD__) || defined(__bsdi__)
#define HASSALEN  /* Awful, awful hack to make subinterfaces work on BSD. */
#endif

/* ECN (RFC2481) */
#ifndef TH_ECN
#define TH_ECN  0x40
#endif
#ifndef TH_CWR
#define TH_CWR  0x80
#endif
   
/* Buffer size used for a few strings, including the pcap filter */
#define TEXTSIZE	1024

/* Maximum payload size */
#define MAX_PAYLOAD_SIZE 1024

/* Maximum number of probes */
#define MAX_PROBES  3000

/* Maximum number of hosts to probe */
#define MAX_HOSTS  5000

/* Probe hashtable size (make it prime number) */
#define HASHTABLE_SIZE  103

/* The minimum number of probes required to calculate C's */
#define C_MIN_PROBES   5

/* The minimum number of probes to estimate epsilon */
#define EPS_MIN_PROBES  100

/* The default values of epsilon */
#define MINEPS 2.0
#define MEDEPS 4.0
#define BIGEPS 6.0

/* Delay groups */
#define MINGRP 50.0
#define MEDGRP 150.0

/* Default sleep time for host lookup */
#define DNS_TIMEOUT 1000

/*
 * How many bytes should we examine on every packet that comes off the
 * wire?  This doesn't include the link layer which is accounted for
 * later.  We're looking only for ICMP and TCP packets, so this should
 * work.  For ICMP, we also examine the quoted IP header, which is why
 * there's a *2 there.  The +32 is just to be safe.
 */

#define SNAPLEN	 (LIBNET_IP_H * 2 + \
	(LIBNET_TCP_H > LIBNET_ICMP_H ? LIBNET_TCP_H : LIBNET_ICMP_H) + 32)


#define MIN(x,y) ((x) < (y)? (x):(y))

/* To add support for additional link layers, add entries to the following table.*/

struct datalinktype {
	int type, offset;
	char *name;
} datalinktypes[] = {

#ifdef DLT_EN10MB
	{	DLT_EN10MB,			14,		"ETHERNET"		},
#endif
#ifdef DLT_PPP
	{	DLT_PPP,			4,		"PPP"			},
#endif
#ifdef DLT_SLIP
	{	DLT_SLIP,			16,		"SLIP"			},
#endif
#ifdef DLT_PPP_BSDOS
	{	DLT_PPP_BSDOS,		24,		"PPP_BSDOS"		},
#endif
#ifdef DLT_SLIP_BSDOS
	{	DLT_SLIP_BSDOS,		24,		"SLIP_BSDOS"	},
#endif
#ifdef DLT_FDDI
	{	DLT_FDDI,			21,		"FDDI"			},
#endif
#ifdef DLT_IEEE802
	{	DLT_IEEE802,		22,		"IEEE802"		},
#endif
#ifdef DLT_NULL
	{	DLT_NULL,			4,		"DLT_NULL"		},
#endif
#ifdef DLT_LOOP
	{	DLT_LOOP,			4,		"DLT_LOOP"		},
#endif

/* Does anyone know correct values for these? */
#ifdef DLT_RAW
	{	DLT_RAW,			-1,		"RAW"			},
#endif
#ifdef DLT_ATM_RFC1483
	{	DLT_ATM_RFC1483,	-1,		"ATM_RFC1483"	},
#endif
#ifdef DLT_EN3MB
	{	DLT_EN3MB,			-1,		"EN3MB"			},
#endif
#ifdef DLT_AX25
	{	DLT_AX25,			-1,		"AX25"			},
#endif
#ifdef DLT_PRONET
	{	DLT_PRONET,			-1,		"PRONET"		},
#endif
#ifdef DLT_CHAOS
	{	DLT_CHAOS,			-1,		"CHAOS"			},
#endif
#ifdef DLT_ARCNET
	{	DLT_ARCNET,			-1,		"ARCNET"		},
#endif

	/* End of the road */
	{	-1,					-1,		NULL			}
};

/* Event type */
#define PROBE_EVENT   0x10
#define TIMEOUT_EVENT 0x20

int __gxx_personality_v0;

/* Various globals */
u_int interval=1800;          /* inter-round interval in seconds */ 
FILE *output_file;           /* file containing the results */
FILE *logfile;
time_t logtime; 
char* log_time;
char *filename=NULL;         /* file containing hosts to ping */
char *outFileName=NULL;       /* output file name */
bool f_xml=false;            /* flag for creating xml output */
bool f_br=false;             /* using brute force algorithm */
bool f_rd=false;             /* using random selection algorithm */
bool f_tp=false;             /* using two_phase algorithm */

u_long dst_ip, src_ip=0;
u_short src_prt=0, dst_prt=80;
char *device=NULL, *name, *dst, *src=NULL;
char dst_name[TEXTSIZE], dst_prt_name[TEXTSIZE], filter[TEXTSIZE];
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *pcap;
int pcap_fd;
struct timeval now;
int	s,sockfd, datalink, offset;
int o_timeout=3, o_tau=500, o_debug=0, o_numeric=0, o_write=0, o_loop=0, o_pktlen=0,
	o_nprobes=6, o_dontfrag=0, o_tos=0, o_forceport=0, o_syn=0, o_ack=0, o_ecn=0, o_hour=0,
	o_nofilter=0, o_nogetinterfaces=0,  o_trackport, o_estimate_epsilon=0, o_set_default_epsilon=1;
u_char o_ttl=255;
int rcv=0;

hashtable *probe_ht;
queue *event_q;

int dst_reached = 0;   /* Flag to indicate if we hit the end-host */

/* interface linked list, built later by getinterfaces() */
struct interface_entry {
	char *name;
	u_long addr;
	struct interface_entry *next;
} *interfaces;

/* Information for each host */
typedef struct host_entry {
	struct host_entry  *prev, *next;         /* doulbe linked list */
	int                i;                    /* index into array */
	char               *name;                /* name as given by user */
	struct sockaddr_in saddr;               /* internet address */
} host_entry;

typedef struct host_port{
	struct host_port *prev, *next;
	int i;
	u_short port;
} host_port;

/* Information for each probe sent */
typedef struct proberecord {
	u_long seq;
	u_char rcv_ttl;
	u_short id, src_prt;
	struct timeval send_time, rcv_time;
	double delta;
	u_long addr;
	unsigned rcvd:1;
	unsigned timeout:1;
	char *state;
	char *string;
	struct proberecord *next, *prev;
} proberecord;

proberecord *prh, *prt = NULL;    /* Queue of proberecords */
unsigned int probes_sent = 0;     /* Length of proberecords queue */
unsigned int probes_timeout = 0;  /* Number of probes that failed */ 
unsigned int points_Cs = 0;       /* number of points used to estimate C's */

host_port *htp_list = NULL; /*head of the list of tcp port */
host_port *ttp_list = NULL; /*tail of the list of tcp port */

host_entry *h_list = NULL; /* head of the list of hosts */
host_entry *t_list = NULL; /* tail of the list of hosts */
//host_entry **table = NULL; /* talbe of pointers to hosts */
u_int num_hosts = 0;       /* total number of hosts */
u_int num_round = 1;           /* round number */
u_int num_ports = 0;

double min_rtt=999999.0;           /* The min. RTT */
float epsilon=MINEPS;            /* Allowable deviation */
float CI=0, CII=0, CIII=0;      /* congestion regions */
float CI_threshold=0.8;       /* confidence in CI */ 
double *RTTS;                 /*  store the rtts we get */
/* mode  */
float mode_all;

/* externals */
extern  int alphasort(); //prototype std lib functions 
extern char *optarg;
extern int optind, opterr, optopt;
extern char pcap_version[];
extern int errno;

/* fatal() and pfatal() are useful stdarg functions from namp. debug( ) and warn( ) are based on them*/

void fatal(char *fmt, ...)
{
	va_list ap;
	fflush(stdout);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

void debug(char *fmt, ...)
{
	va_list ap;
	if (! o_debug) return;
	fflush(stdout);
	fprintf(stderr, "debug: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fflush(stderr);
}

void warn(char *fmt, ...)
{
	va_list ap;
	fflush(stdout);
	fprintf(stderr, "Warning: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fflush(stderr);
}

void pfatal(char *err)
{
	debug("errno == %d\n", errno);
	fflush(stdout);
	perror(err);
}

void usage(void)
{
	printf("\n%s\n%s\n", VERSION, BANNER);
	printf("Usage: %s [options] [targets...]\n",name);
    printf("   -A                    TCP ACK probing packets\n");
    printf("   -c <n>                Set the maximum number of probes(default is 6)\n"); 
	printf("   -C <confidence>       Set the required confidence level(0<=n<=1, default is 0.8)\n");
	printf("   -d                    Debugging mode\n");
	printf("   -E                    Set the ECN flag in the outgoing SYN packets\n");
	printf("   -e <Epsilon>          Set the value of epsilon in ms(>=0, default is 2,4,6\n"); 
    printf("   -f <file>             Read list of targets from a file\n");
	printf("   -F                    Set the \"don't fragment\" flag in the outgoing probes\n");
    printf("   -h                    Print this help message\n");
	printf("   -H                    Probe round by round with interval specified by I\n");
    printf("   -i <interface>        Use the specified interface for outgoing probes\n");
    printf("   -I <interval>         Set the inter-round interval(default is 30min)\n");
    printf("   -l <packet length>    Set the total packet length\n");
	printf("   -L <number of rounds> Set the number of rounds of execution\n");
	printf("   -m <ttl>              Set the TTL in the outgoing probes\n");
    printf("   -n                    Numeric output only\n");
	printf("   -o <tos>              Set the TOS value in the outgoing packets\n"); 
    printf("   -P <port>             Use the specified source port to send probe packets from\n");
    printf("   -p <port>             Specify destination port (default is port 80)\n");
    printf("   -s <source address>   Set the source address for the outgoing probes\n");
	printf("   -S                    Probes are TCP SYN packets (default)\n");
	printf("   -t <timeout>          Specify a timeout, in seconds\n"); 
	printf("   -T <interval>         Set the inter-probe interval(>=10ms, default is 500ms)\n");
    printf("   -v                    Print current RTTometer version\n");
	printf("   -y                    Print the results on console\n");
	printf("   -z                    epsilon estimation mode(default is minimum RTT estimation mode\n");
    printf("   targets               List of hosts to probe (if no -f specified)\n");
    printf("\n");
}

void about(void)
{
	printf("\n%s\n%s\n", VERSION, BANNER);
	exit(0);
}

void *xrealloc(void *oldp, int size)
{
	void *p;

	if (!oldp)
		/* Kludge for SunOS, which doesn't allow realloc on a NULL pointer */
		p = malloc(size);
	else
		p = realloc(oldp, size);
	
	if (!p){
	//	fatal("Out of memory!  Could not reallocate %d bytes!\n", size);
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: Out of memory!\n", log_time);
	}
	
	memset(p, 0, size);
	return p;
}

/*Same as strncpy and snprintf, but always be sure the result is terminated. */
char *safe_strncpy(char *dst, const char *src, int size)
{
	dst[size-1] = '\0';
	return strncpy(dst, src, size-1);
}

int safe_snprintf(char *s, int size, char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vsnprintf(s, size, fmt, ap);
	s[size-1] = '\0';
	va_end(ap);

	return ret;
}

/* return a pointer to a string containing only the printable characters of the string passed to it. */
char *sprintable(char *s)
{
	static char buf[TEXTSIZE];
	int i;

	if (s && s[0])
		safe_strncpy(buf, s, TEXTSIZE);
	else
		safe_strncpy(buf, "(empty)", TEXTSIZE);

	for (i = 0; buf[i]; i++)
		if (! isprint((u_char) buf[i]))
			buf[i] = '?';

	return buf;
}

/* isdigit() across an entire string.*/
int isnumeric(char *s)
{
	int i;
	int ret = 1;
	
	if (!s || !s[0])
		return 0;

	for (i = 0; s[i]; i++) {
		if ( (!isdigit((u_char) s[i])) && s[i] != '.' )
			return 0;
		if (s[i] == '.' )
			ret = 2;
	}
	
	return ret;
}

int datalinkoffset(int type)
{
	int i;

	for (i = 0; datalinktypes[i].name; i++)
		if (datalinktypes[i].type == type)
			return datalinktypes[i].offset;

	return -1;
}

char *datalinkname(int type)
{
	static char name[TEXTSIZE];
	int i;

	for (i = 0; datalinktypes[i].name; i++)
		if (datalinktypes[i].type == type)
			return datalinktypes[i].name;

	safe_snprintf(name, TEXTSIZE, "#%d", type);
	return name;
}

/* Compute the difference between two timeval structures.*/
struct timeval tvdiff(struct timeval *tv1, struct timeval *tv2)
{
	struct timeval tvdiff;

	tvdiff.tv_sec = tv1->tv_sec - tv2->tv_sec;
	tvdiff.tv_usec = tv1->tv_usec - tv2->tv_usec;

	if ((tvdiff.tv_sec > 0) && (tvdiff.tv_usec < 0))
	{
		tvdiff.tv_usec += 1000000L;
		tvdiff.tv_sec--;
	}

	else if ((tvdiff.tv_sec < 0) && (tvdiff.tv_usec > 0))
	{
		tvdiff.tv_usec -= 1000000L;
		tvdiff.tv_sec++;
	}

	return tvdiff;
}

/* Is the timeval less than, equal to, or greater than zero? */
int tvsign(struct timeval *tv)
{
	if (tv->tv_sec < 0) return -1;

	if (tv->tv_sec == 0)
	{
		if (tv->tv_usec < 0) return -1;
		if (tv->tv_usec == 0) return 0;
		if (tv->tv_usec > 0) return 1;
	}

	if (tv->tv_sec > 0) return 1;

	return -1;
}

/*Inspired by libnet_host_lookup().*/
#define IPTOSBUFFERS	12
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3*4+3+1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	safe_snprintf(output[which], 3*4+3+1, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

/* A wrapper for libnet_host_lookup(), with the option not to resolve RFC1918 space.*/
char *iptohost(u_long in)
{
	u_char *p = (u_char *)&in;

	if ((o_numeric > -1) &&
		((p[0] == 10) ||
		(p[0] == 192 && p[1] == 168) ||
		(p[0] == 172 && p[1] >= 16 && p[1] <= 31)))
	{
		debug("Not attempting to resolve RFC1918 address %s\n", iptos(in));
		return iptos(in);
	}

	return libnet_host_lookup(in, o_numeric > 0 ? 0 : 1);
}

/* Allocates memory for a new proberecord structure.*/
proberecord *newproberecord(void)
{
	proberecord *record;

	record = xrealloc(NULL, sizeof(proberecord));
	record->state = xrealloc(NULL, TEXTSIZE);
	record->string = xrealloc(NULL, TEXTSIZE);
	record->next = NULL;
	record->prev = NULL;
	
	return record;
}

/* Destroys a proberecord structure, carefully, as not to leak memory.*/
void freeproberecord(proberecord *record)
{
	if (record->string)
		free(record->string);

	if (record->state)
		free(record->state);

	free(record);
}

/* Fetches the interface list, storing it in struct interface_entry interfaces.*/
void getinterfaces(void)
{
	struct interface_entry *p;
	struct ifconf ifc;
	struct ifreq *ifrp, ifr;
	int numreqs, i, s;
	u_long addr;
	int salen;
	char *x;

	debug("entering getinterfaces()\n");

	if (o_nogetinterfaces)
	{
		debug("Not fetching the interface list\n");
		return;
	}

	if (interfaces) {
   // 	fatal("Double call to getinterfaces()\n");
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: Double call to getinterfaces()\n", log_time);
		exit(1);
	}

	ifc.ifc_buf = NULL;
	p = NULL;

	numreqs = 32;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
//		fatal("socket error");
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: Socket error\n", log_time);
		exit(1);
	}

	debug("ifreq buffer set to %d\n", numreqs);

	for (;;)
	{
		ifc.ifc_len = sizeof(struct ifreq) * numreqs;
		ifc.ifc_buf = xrealloc(ifc.ifc_buf, ifc.ifc_len);

		if (ioctl(s, SIOCGIFCONF, &ifc) < 0) {
	//		pfatal("ioctl");
            logtime = time(NULL);
		    log_time = asctime(localtime(&logtime));
		    fprintf(logfile, "%s: ioctl error\n", log_time);
			exit(1);
		}

		/* This "+ sizeof(struct ifreq) + 64" crap seems to be an (Open?)BSDism. */
		if ( (ifc.ifc_len + sizeof(struct ifreq) + 64) >= (sizeof(struct ifreq) * numreqs) )
		{
			/* Assume it overflowed and try again */
			numreqs += 32;
			if (numreqs > 20000)
				break; /* Too big! */
			debug("ifreq buffer grown to %d\n", numreqs);
			continue;
		}

		break;
	}

	debug("Successfully retrieved interface list\n");

#ifdef HASSALEN
	debug("Using HASALEN method for finding addresses.\n");
#endif

	for (x = ifc.ifc_buf; x < (ifc.ifc_buf + ifc.ifc_len); x += salen)
	{
		ifrp = (struct ifreq *)x;

		memset(&ifr, 0, sizeof(struct ifreq));
		strcpy(ifr.ifr_name, ifrp->ifr_name);

#ifdef HASSALEN

		salen = sizeof(ifrp->ifr_name) + ifrp->ifr_addr.sa_len;
		if (salen < sizeof(*ifrp))
			salen = sizeof(*ifrp);

		addr = ((struct sockaddr_in *)&ifrp->ifr_addr)->sin_addr.s_addr;
		if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
	//		pfatal("ioctl(SIOCGIFFLAGS)");
			logtime = time(NULL);
		    log_time = asctime(localtime(&logtime));
		    fprintf(logfile, "%s: ioctl(SIOCGIFFLAGS) error\n", log_time);
			free(ifc.ifc_buf);
			exit(1);
		}

#else  /* HASALEN */

		salen = sizeof(*ifrp);

		if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
	//		pfatal("ioctl(SIOCGIFADDR)");
			logtime = time(NULL);
		    log_time = asctime(localtime(&logtime));
		    fprintf(logfile, "%s: ioctl(SIOCGIFADDR) error\n", log_time); 
			free(ifc.ifc_buf);
			exit(1);
		}
		addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

#endif /* HASSALEN else */

#ifdef AF_INET6
		if (ifrp->ifr_addr.sa_family == AF_INET6)
		{
			debug("Ignoring AF_INET6 address on interface %s\n",
				sprintable(ifr.ifr_name));
			continue;
		}
#endif

		if (ifrp->ifr_addr.sa_family != AF_INET &&
			ifrp->ifr_addr.sa_family != AF_LINK)
		{
			debug("Ignoring non-AF_INET address on interface %s\n",
				sprintable(ifr.ifr_name));
			continue;
		}

		if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0){
			pfatal("ioctl(SIOCGIFFLAGS)");
			logtime = time(NULL);
		    log_time = asctime(localtime(&logtime));
		    fprintf(logfile, "%s: ioctl(SIOCGIFLAGS) error\n", log_time); 
			exit(1);
		}
		if ((ifr.ifr_flags & IFF_UP) == 0)
		{
			debug("Ignoring down interface %s\n",
				sprintable(ifr.ifr_name));
			continue;
		}

		/* Deal with virtual hosts */
		for (i = 0; ifr.ifr_name[i]; i++)
			if (ifr.ifr_name[i] == ':')
				ifr.ifr_name[i] = '\0';

		/* Grow another node on the linked list... */
		if (!p)
			p = interfaces = xrealloc(NULL, sizeof(struct interface_entry));
		else
			p = p->next = xrealloc(NULL, sizeof(struct interface_entry));

		p->next = NULL;

		/* ... and fill it in */
		p->addr = addr;
		p->name = xrealloc(NULL, strlen(ifr.ifr_name) + 1);
		strcpy(p->name, ifr.ifr_name);

		debug("Discovered interface %s with address %s\n",
			sprintable(p->name), iptos(p->addr));
	}

	free(ifc.ifc_buf);
	debug("leaving getinterfaces()\n");
}

/* Determines the source address that should be used to reach the given destination address.*/
u_long findsrc(u_long dest)
{
	struct sockaddr_in sinsrc, sindest;
	int s, size;

	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
	//	pfatal("socket error");
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: socket error\n", log_time);
		return 0;
	}

	memset(&sinsrc, 0, sizeof(struct sockaddr_in));
	memset(&sindest, 0, sizeof(struct sockaddr_in));

	sindest.sin_family = AF_INET;
	sindest.sin_addr.s_addr = dest;
	sindest.sin_port = htons(53); /* can be anything */

	if (connect(s, (struct sockaddr *)&sindest, sizeof(sindest)) < 0) {
//		pfatal("connect");
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: connect error\n", log_time);
		close(s);
		return 0;
	}

	size = sizeof(sinsrc);
	if (getsockname(s, (struct sockaddr *)&sinsrc, &size) < 0) {
//		pfatal("getsockname");
        logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: getsockname error\n", log_time);
		close(s);
		return 0;
	}

	close(s);
	debug("Determined source address of %s to reach %s\n",
		iptos(sinsrc.sin_addr.s_addr), iptos(dest));
	return sinsrc.sin_addr.s_addr;
}

/* Find an appropriate device to use given the specified source address.
 * However, if we find an interface matching the global dst_ip address, set
 * the source address we're looking for to 127.0.0.1 in an attempt to select
 * the loopback.  Ofcourse, this entirely depends on the fact that a loopback
 * interface exists with an address of 127.0.0.1.*/
char *finddev(u_long with_src)
{
	struct interface_entry *p;
	char *device = NULL;

	debug("entering finddev()\n");

	/* First, see if we're trying to trace to ourself */
	for (p = interfaces; p; p = p->next)
		if (p->addr == dst_ip)
		{
			debug("Destination matches local address of interface %s;\n\tattempting to find loopback interface, o_nofilter set\n", p->name);
			with_src = libnet_name_resolve("127.0.0.1", 0);
			o_nofilter = 1;
		}

	for (p = interfaces; p; p = p->next)
		if (p->addr == with_src)
			device = p->name;
	
	debug("finddev() returning %s\n", device);
	return device;
}


/* Request a local unused TCP port from the kernel using bind(2)*/
u_short allocateport(u_short requested)
{
	struct sockaddr_in in;
	int	s, insize;

	if ((s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
//		pfatal("socket error");
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: socket error\n", log_time);
	}

	insize = sizeof(in);
	memset(&in, 0, insize);

	in.sin_family = AF_INET;
	in.sin_port = htons(requested);

	if ((bind(s, (struct sockaddr *)&in, insize)) < 0)
		return 0;

	if ((getsockname(s, (struct sockaddr *)&in, &insize)) < 0){
//		pfatal("getsockname");
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: getsockname error\n", log_time); 
	}

	close(s);
	return ntohs(in.sin_port);
}

/* Allocate an IP ID from our pool of unallocated ID's.  A cache is kept of
 * the last ALLOCATEID_CACHE_SIZE allocations, so we can check for duplicates.*/
#ifndef ALLOCATEID_CACHE_SIZE
#define ALLOCATEID_CACHE_SIZE 512
#endif

u_short allocateid(void)
{
	static u_short ids[ALLOCATEID_CACHE_SIZE];
	static int n;
	int i, j;

	if ((n = n % ALLOCATEID_CACHE_SIZE) == 0)
	{
		debug("Generating a new batch of %d IP ID's\n", ALLOCATEID_CACHE_SIZE);

		for(i = 0; i < ALLOCATEID_CACHE_SIZE; i++)
		{
			for(ids[i] = libnet_get_prand(PRu16), j = i + 1; j < ALLOCATEID_CACHE_SIZE + i; j++)
				if (ids[i] == ids[j % ALLOCATEID_CACHE_SIZE])
					ids[i] = libnet_get_prand(PRu16), j = i + 1;
		}
	}

	return ids[n++];
}


/* The aim is to display the probe inforamtion in a traceroute-like fashion.*/
void showprobe(proberecord *record)
{

	if (record->rcvd) {
		
		if(o_numeric)
			printf("%s", iptos(record->addr));
		else
			printf("%s (%s)", iptohost(record->addr), iptos(record->addr));

		printf(" seq=%ld ttl=%d ", record->seq, record->rcv_ttl);
		
		if (record->addr == INADDR_ANY)
			safe_strncpy(record->string, "* ", TEXTSIZE);

		printf("time=");
		printf(record->string, record->delta);

		/* tcp state */
		if(strlen(record->state) > 1)
			printf(" [%s]", record->state);

		/* Congestion regions */
		if (!o_estimate_epsilon)
			printf(" [%.4f][%.4f][%.4f]", CI, CII, CIII);
		
		/* Print time stamps for debugging only */
		printf(" send_time=%ld.%ld", record->send_time.tv_sec, record->send_time.tv_usec);
		
		printf("\n");

		fflush(stdout);
	}
}

/* Useful for debugging; dump #define's and command line options.*/
void debugoptions(void)
{
	if (! o_debug)
		return;

	debug("debugoptions():\n");

	/* TEXTSIZE SNAPLEN IPTOSBUFFERS ALLOCATEID_CACHE_SIZE device datalink
	 * datalinkname(datalink) datalinkoffset(datalink) o_ttl
	 * o_timeout o_debug o_pktlen o_nprobes o_dontfrag o_tos
	 * o_forceport o_syn o_ack o_ecn o_nofilter o_nogetinterfaces o_trackport
	 */
	debug("%16s: %-2d %14s: %-2d %16s: %-2d\n",
		"TEXTSIZE", TEXTSIZE,
		"SNAPLEN", SNAPLEN,
		"IPTOSBUFFERS", IPTOSBUFFERS);

	debug("%16s: %-2d %16s: %-2d %16s: %-2d\n",
		"ALLOCATEID_CACHE", ALLOCATEID_CACHE_SIZE,
		"datalink", datalink,
		"datalinkoffset", datalinkoffset(datalink));

	debug("%16s: %-2d %16s: %-2d %16s: %-2d\n",
		"o_ttl", o_ttl,
		"o_timeout", o_timeout);

	debug("%16s: %-2d %16s: %-2d %16s: %-2d\n",
		"o_debug", o_debug,
		"o_numeric", o_numeric,
		"o_pktlen", o_pktlen);

	debug("%16s: %-2d %16s: %-2d %16s: %-2d\n",
		"o_nprobes", o_nprobes,
		"o_dontfrag", o_dontfrag,
		"o_tos", o_tos);

	debug("%16s: %-2d %16s: %-2d %16s: %-2d\n",
		"o_forceport", o_forceport,
		"o_syn", o_syn,
		"o_ack", o_ack);

	debug("%16s: %-2d %16s: %d %16s: %-2d\n",
		"o_ecn", o_ecn,
		"o_nofilter", o_nofilter,
		"o_nogetinterfaces", o_nogetinterfaces);

	debug("%16s: %-2d %16s: %-12s %s: %s\n",
		"o_trackport", o_trackport,
		"datalinkname", datalinkname(datalink),
		"device", device);


}

/* Check command line arguments for sanity, and fill in the blanks.*/
void defaults(void)
{
	u_long recommended_src;
	
	getinterfaces();

	if ((dst_ip = libnet_name_resolve(dst, 1)) == 0xFFFFFFFF) {
//		fatal("Bad first destination address: %s, cannot be used to find source and device\n", dst);
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: Bad first destination address %s!\n", log_time, dst);
		exit(-1);
	}

	recommended_src = findsrc(dst_ip);

	if (!recommended_src) {
//		fatal("Can't find the source\n");
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: Can't find the source\n", log_time);
		exit(-1);
	}
	
	if (src)
	{
		if ((src_ip = libnet_name_resolve(src, 1)) == 0xFFFFFFFF) {
//			fatal("Bad source address: %s\n", src);
			logtime = time(NULL);
		    log_time = asctime(localtime(&logtime));
		    fprintf(logfile, "%s: Bad source address: %s\n", log_time, src);
			exit(-1);
		}		
	}
	else
		src_ip = recommended_src;

	if (device == NULL)
		/* not specified on command line */
		device = finddev(recommended_src);

	if (device == NULL)
	{
		/* couldn't find an appropriate interface */
		warn("Could not determine appropriate device; resorting to pcap_lookupdev()\n");
		device = pcap_lookupdev(errbuf);
	}

	if (device == NULL){
//		fatal("Could not determine device via pcap_lookupdev(): %s\n", errbuf);
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: Could not determine device via pcap_lookupdev(): %s\n", log_time, errbuf);
		exit(1);
	}

	if (pcap != NULL)
	{
		fprintf (stderr, "pcap not released 1\n");
		exit (-1);
	}

	if ((pcap = pcap_open_live(device, 0, 0, 0, errbuf)) == NULL){
//		fatal("error opening device %s: %s\n", device, errbuf);
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: error opening device %s: %s\n", log_time,device,errbuf); 
		exit(1);
	}

	datalink = pcap_datalink(pcap);
	offset = datalinkoffset(datalink);

	if (offset < 0) {
//		fatal("Sorry, media type of device %s (%s) is not supported\n",device, datalinkname(datalink));
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: Sorry, media type of device %s (%s) is not supported\n", 
			log_time,device, datalinkname(datalink)); 
		pcap_close(pcap);
		exit(1);
	}

	pcap_close(pcap);
	pcap = NULL;

	if (src_prt && o_trackport)
	{
		warn("--track-id implied by specifying the local source port\n");
		o_trackport = 0;
	}

	if (! o_trackport)
	{
#if defined (__SVR4) && defined (__sun)
		warn("--track-id is unlikely to work on Solaris\n");
#endif

		if (! o_forceport)
			src_prt = allocateport(src_prt);

		if (src_prt == 0){
//			fatal("Sorry, requested local port is already in use.  Use -P, instead of -p, to override.\n");
            logtime = time(NULL);
		    log_time = asctime(localtime(&logtime));
		    fprintf(logfile, "%s: Sorry, requested local port is already in use.  Use -P, instead of -p, to override.\n", log_time);
			exit(1);
		}
	}

	if (o_nprobes <= 0 || o_nprobes > MAX_PROBES) {
//		fatal("Number of probes must be between 1 and %d\n", MAX_PROBES);
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: Number of probes must be between 1 and %d\n", log_time, MAX_PROBES); 
		exit(1);
	}

	if (o_estimate_epsilon && o_nprobes < EPS_MIN_PROBES) {
//		fatal("Need at least %d probes to estimate epsilon\n", EPS_MIN_PROBES);
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: Need at least %d probes to estimate epsilon\n", log_time, EPS_MIN_PROBES);
		exit(1);
	}
	
	if (o_timeout <= 0) {
//		fatal("Timeout must be at least 1\n");
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: Timeout must be at least 1\n", log_time);
		exit(1);
	}

	if (o_tau < 10){
//		fatal("Inter-probe interval must be at least 10 msec\n");
        logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: Inter-probe interval must be at least 10 msec\n", log_time);
		exit(1);
	}

	if ( epsilon <= 0.0) {
//		fatal("Epsilon is %.3f. It must be greater than 0 msec\n", epsilon);
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: Epsilon is %.3f. It must be greater than 0 msec\n", log_time,epsilon);
		exit(1);
	}

	if ( (CI_threshold <= 0) || (CI_threshold > 1.0) ) {
//		fatal("CI threshold must be between 0 and 1\n");
        logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: CI threshold must be between 0 and 1\n", log_time);
		exit(1);
	}
	
	if (o_pktlen < LIBNET_TCP_H + LIBNET_IP_H)
	{
		if (o_pktlen != 0){
//			warn("Increasing packet length to %d bytes\n", LIBNET_TCP_H + LIBNET_IP_H);
            logtime = time(NULL);
		    log_time = asctime(localtime(&logtime));
		    fprintf(logfile, "%s: Increasing packet length to %d bytes\n", log_time,LIBNET_TCP_H + LIBNET_IP_H);
		}
            
		o_pktlen = 0;
	}
	else
		o_pktlen -= (LIBNET_TCP_H + LIBNET_IP_H);

	libnet_seed_prand();

/*
	if ((sockfd = libnet_open_raw_sock(IPPROTO_RAW)) < 0) {
		pfatal("socket allocation");
		exit(1);
	}
*/
	if (! (o_syn|o_ack))
	{
		debug("Setting o_syn, in absence of either o_syn or o_ack\n");
		o_syn = 1;
	}

	debugoptions();

//	fprintf(stderr, "Selected device %s, address %s", device, iptos(src_ip));
	logtime = time(NULL);
	log_time = asctime(localtime(&logtime));
	fprintf(logfile, "%s: Selected device %s, address %s ", log_time, device, iptos(src_ip));
	if (! o_trackport) {
		//fprintf(stderr, ", port %d", src_prt);
          logtime = time(NULL);
	      log_time = asctime(localtime(&logtime));
	      fprintf(logfile, ", port %d", src_prt);
	}
//	fprintf(stderr, " for outgoing packets\n");
	fprintf(logfile, " for outgoing packets\n");

}

/* check destination is valid or not, if so copy its name nad ip address */
bool dstcheck(){
    struct servent *serv;

	if ((dst_ip = libnet_name_resolve(dst, 1)) == 0xFFFFFFFF) {
//		fatal("Bad destination address: %s\n", dst);
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: Bad destination address: %s\n", log_time, dst);
		return false;
	}
	if (strcmp(dst, iptos(dst_ip)) == 0)
		safe_snprintf(dst_name, TEXTSIZE, "%s", dst);
	else
		safe_snprintf(dst_name, TEXTSIZE, "%s (%s)", dst, iptos(dst_ip));

	if ((serv = getservbyport(dst_prt, "tcp")) == NULL)
		safe_snprintf(dst_prt_name, TEXTSIZE, "%d", dst_prt);
	else
		safe_snprintf(dst_prt_name, TEXTSIZE, "%d (%s)", dst_prt, serv->s_name);

	return true;
}

/* Open the pcap listening device, and apply our filter.*/

bool initcapture( )
{
	struct bpf_program fcode;
	bpf_u_int32 localnet, netmask;

	if (pcap != NULL)
	{
//		fprintf (stderr, "pcap not released 2\n");
		logtime = time(NULL);
    	log_time = asctime(localtime(&logtime));
	    fprintf(logfile, "%s: pcap not released 2 ", log_time);
		exit (-1);
	}
	if (! (pcap = pcap_open_live(device, offset + SNAPLEN, 0,
#ifndef __linux__
								 1  /* 1 ms block if no packets are in the buffer */,
#else
								 0  /* Don't block (This is from Scriptroute) */,
#endif								 
									  

								 errbuf))) {
//		fatal("pcap_open_live failed: %s", errbuf);
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: pcap_open_live failed: %s\n", log_time, errbuf);
		return false;
	}
	
	safe_snprintf(filter, TEXTSIZE, " \
				 (tcp and src host %s and dst host %s and dst port %d) \
				 or (tcp and src host %s and src port %d and dst host %s) \
				 or ((icmp[0] == 11 or icmp[0] == 3) and dst host %s)",
				  iptos(src_ip), iptos(dst_ip), dst_prt,
				  iptos(dst_ip), dst_prt, iptos(src_ip),
				  iptos(src_ip));

	if (o_nofilter)
		filter[0] = '\0';

	debug("pcap filter is: %s\n", o_nofilter ? "(nothing)" : filter);

	localnet = 0;
	netmask = 0;

	if (pcap_lookupnet(device, &localnet, &netmask, errbuf) < 0) {
//		fatal("pcap_lookupnet failed: %s\n", errbuf);
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: pcap_lookupnet failed: %s\n", log_time, errbuf);
		pcap_close(pcap);
		return false;
	}

	if (pcap_compile(pcap, &fcode, filter, 1, netmask) < 0) {
//		fatal("filter compile failed: %s", pcap_geterr(pcap));
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: filter compile failed: %s\n", log_time, pcap_geterr(pcap));
		pcap_close(pcap);
		return false;
	}

	if (pcap_setfilter(pcap, &fcode) < 0) {
//		fatal("pcap_setfilter failed\n");
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: pcap_setfilter failed\n", log_time);
		pcap_close(pcap);
		return false;
	}

	pcap_fd = pcap_fileno(pcap);
	if (fcntl(pcap_fd, F_SETFL, O_NONBLOCK) < 0) {
//		pfatal("fcntl(F_SETFL, O_NONBLOCK) failed");
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: fcntl(F_SETFL, O_NONBLOCK) failed\n", log_time);
		pcap_close(pcap);
		return false;
	}

	return true;
}

/* Calculate the value of CI, CII, and CIII using the weighted quantized method.*/
int calculate_C_regions_quantized(void)
{
	proberecord *p;
	float ci, cii, ciii = 0;
	int n = 0;
	float val, w1, w2, w;
	
	if(probes_sent < C_MIN_PROBES)
		return 0;

	
	CI = CII = CIII = 0;
	
	p = prh;

	/* TODO: change that logic in the future */
	if(min_rtt == 999999.0)
		return 0;


	/* Do we need to set the default value of epsilon for the path */
	if(o_set_default_epsilon) {
		if(min_rtt <= MINGRP)
			epsilon = MINEPS;
		else if(min_rtt <= MEDGRP)
			epsilon = MEDEPS;
		else
			epsilon = BIGEPS;
	
		o_set_default_epsilon = 0;
	}

	while(p->next) {
		if(p->rcvd && p->next->rcvd) {
			n++;

			/* Look at the timeout flag and classify the point in the phase-plot */			
			if(!p->timeout && !p->next->timeout){
				/* Point in CI, CII, or CIII */
				if( (p->delta - min_rtt) <= epsilon)
					w1 = 1.0;
				else {
					val = (float)((int)((p->delta - min_rtt)/epsilon) + 1);
					w1 = 1.0/val;
				}
				if( (p->next->delta - min_rtt) <= epsilon)
					w2 = 1.0;
				else {
					val = (float)((int)((p->next->delta - min_rtt)/epsilon) + 1);
					w2 = 1.0/val;
				}

				w = w1 * w2;
			}
			else {
				/* Point in CII or CIII */
				if(p->timeout)
					w1 = 0.0;
				else {
					val = (float)((int)((p->delta - min_rtt)/epsilon) + 1);
					w1 = 1.0/val;
				}

				if(p->next->timeout)
					w2 = 0.0;
				else {
					val = (float)((int)((p->next->delta - min_rtt)/epsilon) + 1);
					w2 = 1.0/val;
				}
				
				w = w1 * w2;
			}

			ci += w;
			if(w1 == 1 || w2 == 1)
				/* This point in CII */
				cii += (1-w);
			else
				/* Definitely CIII */
				ciii += (1-w);
					
		}
		
		p = p->next;
	}

	if(n > 0) {
		CI = ci/n;
		CII =  cii/n;
		CIII =  ciii/n;
	}

	return n;
}


/* Sends out a TCP SYN packet with the specified TTL, and returns a
 * proberecord structure describing the packet sent, so we know what
 * to listen for later.  A new IP ID is generated for each probe, and
 * a new source port if o_trackport is specified.
 */
bool probe(proberecord *record, int seq)
{
	u_char *buf;
	u_char payload[MAX_PAYLOAD_SIZE];
	int i, size, ret;
	struct timeval when;
	queue_entry *qe;
	
	/* Initialize the packet buffer */
	size = LIBNET_IP_H + LIBNET_TCP_H + o_pktlen;

	libnet_init_packet(size, &buf);
    if (buf == NULL) {
        libnet_error(LIBNET_ERR_FATAL, "libnet_init_packet failed\n");
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: libnet_init_packet failed\n", log_time);
	}

	/* Initialize the packet payload */
	if (o_pktlen && !payload)
	{
		debug("Initializing payload of %d bytes\n", o_pktlen);
		for(i = 0; i < o_pktlen; i++)
			payload[i] = i % ('~' - '!') + '!';
		debug("Payload: %s\n", sprintable(payload));
	}

	record->seq = (u_long) seq;
	record->rcv_ttl = 0;
	record->addr = INADDR_ANY;
	record->src_prt = src_prt;
	record->id = allocateid();
	record->delta = 0;

	if (o_trackport)
	{
		record->src_prt = allocateport(0);
		if (record->src_prt == 0) {
//			pfatal("Could not allocate local port: bind");
		    logtime = time(NULL);
		    log_time = asctime(localtime(&logtime));
		    fprintf(logfile, "%s: Could not allocate local port: bind\n", log_time);
			return false;
		}
	}

	/* Build the packet, and send it off into the cold, cruel world ... */
	libnet_build_ip(
		LIBNET_TCP_H+o_pktlen,	/* len			*/
		o_tos,					/* tos			*/
		record->id,				/* id			*/
		o_dontfrag ? IP_DF : 0,	/* frag			*/
		o_ttl,					/* ttl			*/
		IPPROTO_TCP,			/* proto		*/
		src_ip,					/* saddr		*/
		dst_ip,					/* daddr		*/
		NULL,					/* data			*/
		0,						/* datasize?	*/
		buf);					/* buffer		*/

	libnet_build_tcp(
		record->src_prt,		/* source port	*/
		dst_prt,				/* dest port	*/
		record->seq,			/* seq number	*/
		record->seq+1,			/* ack number	*/

		(o_syn ? TH_SYN : 0) |
		(o_ack ? TH_ACK : 0) |
		(o_ecn ? TH_CWR|TH_ECN : 0), /* control	*/

		0,						/* window		*/
		0,						/* urgent?		*/
		payload,				/* data			*/
		o_pktlen,				/* datasize		*/
		buf + LIBNET_IP_H);		/* buffer		*/

	libnet_do_checksum(buf, IPPROTO_TCP, LIBNET_TCP_H + o_pktlen);

	/* I am updating the send_time when I see the packet on the wire.
	   I am just doing it here, just in case we don't capture the sent packet*/
	   
	if (gettimeofday(&(record->send_time), NULL) < 0) {
//		pfatal("gettimeofday");
		logtime = time(NULL);
    	log_time = asctime(localtime(&logtime));
	    fprintf(logfile, "%s: gettimeofday error\n", log_time);
		return false;
	}

	if ((ret = libnet_write_ip(sockfd, buf, size)) < size) {
//		fatal("libnet_write_ip failed?  Attempted to write %d bytes, only wrote %d\n",size, ret);
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: libnet_write_ip failed?  Attempted to write %d bytes, only wrote %d", log_time,size, ret);
		return false;
	}

	/* Add the probe to the hashtable of expected packets */
	if (!hashtable_insert(probe_ht, (const void *) record)) {
//		fatal("Inserting proberecord into the hashtable\n");
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: Inserting proberecord into the hashtable failed?\n", log_time); 
		return false;
	}

	/* Add timeout event in the event queue */
	when = record->send_time;
	when.tv_sec += o_timeout;
	qe = create_qentry(TIMEOUT_EVENT, when, record->seq);
	queue_insert(event_q, qe);
	libnet_destroy_packet(&buf);
	return true;

}
/* Horrible macro kludge, to be called only from process_packet(), for architectures
 * such as sparc that don't allow non-aligned memory access.  The idea is to
 * malloc new space (which is guaranteed to be properly aligned), copy the
 * packet we want to parse there, then cast the packet header struct against the new, aligned space.
 */

#define ALIGN_PACKET(dest, cast, offset) do { \
		static u_char *buf; \
		if (buf == NULL) buf = xrealloc(NULL, SNAPLEN - (offset)); \
		memcpy(buf, packet + (offset), len - (offset)); \
		dest = (struct cast *)buf; \
	} while (0) /* no semi-colon */


static void process_packet(const struct pcap_pkthdr *packet_hdr, const unsigned char *pbuf)
{
	struct libnet_ip_hdr *ip_hdr;
	u_char *packet;
	
	int len;
	double delta;
	proberecord *record;

	packet =(u_char *) (pbuf + offset);
	len = packet_hdr->caplen - offset;

	debug("received %d byte IP packet from pcap_next()\n", len);

	if (len < LIBNET_IP_H)
	{
		debug("Ignoring partial IP packet\n");
		return;
	}

	if (len > SNAPLEN)
	{
		debug("Packet received is larger than our snaplen?  Ignoring\n", SNAPLEN);
		return;
	}

	ALIGN_PACKET(ip_hdr, libnet_ip_hdr, 0);

	if (ip_hdr->ip_v != 4)
	{
		debug("Ignoring non-IPv4 packet\n");
		return;
	}

	if (ip_hdr->ip_hl > 5)
	{
		debug("Ignoring IP packet with IP options\n");
		return;
	}

	if ((ip_hdr->ip_dst.s_addr != src_ip) && (ip_hdr->ip_dst.s_addr != dst_ip))
	{
		debug("Ignoring IP packet not addressed to us or to our destination (pkt src ip %s)\n",
			  iptos(ip_hdr->ip_dst.s_addr));

		return;
	}

	
	/* ICMP packet */
	
	if (ip_hdr->ip_p == IPPROTO_ICMP) {
		struct libnet_icmp_hdr *icmp_hdr;
		struct libnet_ip_hdr *old_ip_hdr;
		struct libnet_tcp_hdr *old_tcp_hdr;
		
		if (len < LIBNET_IP_H + LIBNET_ICMP_H + 4)
		{
			debug("Ignoring partial icmp packet\n");
			return;
		}
		
		ALIGN_PACKET(icmp_hdr, libnet_icmp_hdr, 0 + LIBNET_IP_H);
		debug("Received icmp packet\n");

		/* The IP header that generated the ICMP packet is quoted here. */
		
		if (len < LIBNET_IP_H + LIBNET_ICMP_H + 4 + LIBNET_IP_H + 4)
		{
			debug("Ignoring icmp packet with incomplete payload\n");
			return;
		}

		ALIGN_PACKET(old_ip_hdr, libnet_ip_hdr,
					 0 + LIBNET_IP_H + LIBNET_ICMP_H + 4);

		/* The entire TCP header isn't here, but the port numbers are */
		ALIGN_PACKET(old_tcp_hdr, libnet_tcp_hdr,
					 0 + LIBNET_IP_H + LIBNET_ICMP_H + 4 + LIBNET_IP_H);

		if (old_ip_hdr->ip_v != 4)
		{
			debug("Ignoring ICMP packet which quotes a non-IPv4 packet\n");
			return;
		}

		if (old_ip_hdr->ip_hl > 5)
		{
			debug("Ignoring ICMP packet which quotes an IP packet with IP options\n");
			return;
		}

		if (old_ip_hdr->ip_dst.s_addr != dst_ip)
		{
			debug("Ignoring ICMP packet with incorrect quoted destination (%s, not %s)\n",
				  iptos(old_ip_hdr->ip_dst.s_addr), iptos(dst_ip));
			return;
		}

		if (old_ip_hdr->ip_src.s_addr != src_ip)
		{
			debug("Ignoring ICMP packet with incorrect quoted source (%s, not %s)\n",
				  iptos(old_ip_hdr->ip_src.s_addr), iptos(src_ip));
			return;
		}

		/* These are not the droids you are looking for */
		if (old_ip_hdr->ip_p != IPPROTO_TCP)
		{
			debug("Ignoring ICMP packet which doesn't quote a TCP header\n");
			return;
		}

		/* Check the hashtable for any matched packet*/		
		record = (proberecord *) hashtable_lookup(probe_ht, (unsigned int) ntohl(old_tcp_hdr->th_seq));

		if (record) {
			record->rcv_time = packet_hdr->ts;
			record->rcvd = 1;
		}
		else {
			debug("icmp packet doesn't contain the id we sent\n");
			return;
		}

		/* This is an ICMP reply, we need to remove the record from the hashtable */
		hashtable_remove(probe_ht, record);

		/* Remove the timeout event associated with this reply */
		queue_remove(event_q, TIMEOUT_EVENT, record->seq);
		
		/* Move along */
		if ((ntohs(old_tcp_hdr->th_sport) != record->src_prt)
			|| (ntohs(old_tcp_hdr->th_dport) != dst_prt))
		{
			debug("icmp packet doesn't contain the correct tcp port numbers\n");
			return;
		}

		if (icmp_hdr->icmp_type == ICMP_UNREACH) {
			char s[TEXTSIZE];
			
			switch(icmp_hdr->icmp_code) {
				case ICMP_UNREACH_NET:
					safe_strncpy(s, "!N", TEXTSIZE); break;
					
				case ICMP_UNREACH_HOST:
					safe_strncpy(s, "!H", TEXTSIZE); break;
					
				case ICMP_UNREACH_PROTOCOL:
					safe_strncpy(s, "!P", TEXTSIZE); break;
					
				case ICMP_UNREACH_PORT:
					safe_strncpy(s, "!p", TEXTSIZE); break;
					
				case ICMP_UNREACH_NEEDFRAG:
					safe_strncpy(s, "!F", TEXTSIZE); break;
					
				case ICMP_UNREACH_SRCFAIL:
					safe_strncpy(s, "!S", TEXTSIZE); break;
					
				case ICMP_UNREACH_NET_PROHIB:
				case ICMP_UNREACH_FILTER_PROHIB:
					safe_strncpy(s, "!A", TEXTSIZE); break;
					
				case ICMP_UNREACH_HOST_PROHIB:
					safe_strncpy(s, "!C", TEXTSIZE); break;
					
				case ICMP_UNREACH_NET_UNKNOWN:
				case ICMP_UNREACH_HOST_UNKNOWN:
					safe_strncpy(s, "!U", TEXTSIZE); break;
					
				case ICMP_UNREACH_ISOLATED:
					safe_strncpy(s, "!I", TEXTSIZE); break;
					
				case ICMP_UNREACH_TOSNET:
				case ICMP_UNREACH_TOSHOST:
					safe_strncpy(s, "!T", TEXTSIZE); break;
					
				case ICMP_UNREACH_HOST_PRECEDENCE:
				case ICMP_UNREACH_PRECEDENCE_CUTOFF:
				default:
					safe_snprintf(s, TEXTSIZE, "!<%d>", icmp_hdr->icmp_code);
			}
			
			safe_snprintf(record->string, TEXTSIZE, "%%.3f ms %s", s);

			dst_reached = 1;
		}
		else if (icmp_hdr->icmp_type == ICMP_TIMXCEED) {
			safe_strncpy(record->string, "%.3f ms", TEXTSIZE);
		}
		else if (icmp_hdr->icmp_type != ICMP_TIMXCEED &&
				 icmp_hdr->icmp_type != ICMP_UNREACH) {
			
			safe_strncpy(record->string, "%.3f ms -- Unexpected ICMP", TEXTSIZE);
		}

		delta = (double)(record->rcv_time.tv_sec - record->send_time.tv_sec) * 1000 +
			(double)(record->rcv_time.tv_usec - record->send_time.tv_usec) / 1000;

		record->delta = delta;
		record->addr = ip_hdr->ip_src.s_addr;
		record->rcv_ttl = ntohs(ip_hdr->ip_ttl);
			
		/* Update min. RTT */
		min_rtt = MIN(record->delta, min_rtt);

		/* Update C's */
		if(!o_estimate_epsilon)
			points_Cs = calculate_C_regions_quantized();

		/* Dispaly */
		if(o_write)
		    showprobe(record);
		
		return;
	}
	
	/* TCP packet */
	if (ip_hdr->ip_p == IPPROTO_TCP) {
		struct libnet_tcp_hdr *tcp_hdr;

		if ( (ip_hdr->ip_src.s_addr != dst_ip) && (ip_hdr->ip_src.s_addr != src_ip)) {
			debug("tcp packet's origin does not match target's address or our address (src ip %s)\n",
				  iptos(ip_hdr->ip_src.s_addr));
				return;
		}

		if (len < LIBNET_IP_H + LIBNET_TCP_H) {
			debug("Ignoring partial tcp packet\n");
			return;
		}

		ALIGN_PACKET(tcp_hdr, libnet_tcp_hdr, 0 + LIBNET_IP_H);

		debug("Received tcp packet %s:%d -> %s:%d, flags %s%s%s%s%s%s%s%s%s, Seq %u, Ack %u\n",
			  iptos(ip_hdr->ip_src.s_addr), ntohs(tcp_hdr->th_sport),
			  iptos(ip_hdr->ip_dst.s_addr), ntohs(tcp_hdr->th_dport),
			  tcp_hdr->th_flags & TH_RST  ? "RST " : "",
			  tcp_hdr->th_flags & TH_SYN  ? "SYN " : "",
			  tcp_hdr->th_flags & TH_ACK  ? "ACK " : "",
			  tcp_hdr->th_flags & TH_PUSH ? "PSH " : "",
			  tcp_hdr->th_flags & TH_FIN  ? "FIN " : "",
			  tcp_hdr->th_flags & TH_URG  ? "URG " : "",
			  tcp_hdr->th_flags & TH_CWR  ? "CWR " : "",
			  tcp_hdr->th_flags & TH_ECN  ? "ECN " : "",
			  tcp_hdr->th_flags ? "" : "(none)", ntohl(tcp_hdr->th_seq), ntohl(tcp_hdr->th_ack));
		

		/* Check the hashtable for any matched packet. We can either capture the TCP packet we send, or the TCP reply from
		   the target. In either cases the ACK number should be equal to the SEQ - 1 */
		record = (proberecord *) hashtable_lookup(probe_ht, (unsigned int) (ntohl(tcp_hdr->th_ack)-1) );

		if (record) {
			if(ntohs(tcp_hdr->th_dport) == record->src_prt) {
				record->rcv_time = packet_hdr->ts;
				record->rcvd = 1;
				/* This is the TCP reply, we need to remove the record from the hashtable */
				hashtable_remove(probe_ht, record);
				/* Remove the timeout event associated with this reply */
				queue_remove(event_q, TIMEOUT_EVENT, record->seq);
			}
			else if (ntohs(tcp_hdr->th_dport) == dst_prt) {
				record->send_time = packet_hdr->ts;
				/* This is the TCP packet we send, just update the send time and don't remove the record from the hashtable */
				return;
			}
		}
		else {
			debug("TCP packet is not expected!\n");
			return;
		}

		if (tcp_hdr->th_flags & TH_RST)
			safe_strncpy(record->state, "closed", TEXTSIZE);

		else if ((tcp_hdr->th_flags & TH_SYN)
				 && (tcp_hdr->th_flags & TH_ACK)
				 && (tcp_hdr->th_flags & TH_ECN))
			safe_strncpy(record->state, "open, ecn", TEXTSIZE);

		else if ((tcp_hdr->th_flags & TH_SYN)
				 && (tcp_hdr->th_flags & TH_ACK))
			safe_strncpy(record->state, "open", TEXTSIZE);
		
		else
			safe_snprintf(record->state, TEXTSIZE, "unknown,%s%s%s%s%s%s%s%s%s",
						  tcp_hdr->th_flags & TH_RST  ? " RST" : "",
						  tcp_hdr->th_flags & TH_SYN  ? " SYN" : "",
						  tcp_hdr->th_flags & TH_ACK  ? " ACK" : "",
						  tcp_hdr->th_flags & TH_PUSH ? " PSH" : "",
						  tcp_hdr->th_flags & TH_FIN  ? " FIN" : "",
						  tcp_hdr->th_flags & TH_URG  ? " URG" : "",
						  tcp_hdr->th_flags & TH_CWR  ? " CWR" : "",
						  tcp_hdr->th_flags & TH_ECN  ? " ECN" : "",
						  tcp_hdr->th_flags ? "" : " no flags");

		
		delta = (double)(record->rcv_time.tv_sec - record->send_time.tv_sec) * 1000 +
			(double)(record->rcv_time.tv_usec - record->send_time.tv_usec) / 1000;

		record->delta = delta;
		record->addr = ip_hdr->ip_src.s_addr;
		record->rcv_ttl = ip_hdr->ip_ttl;
		safe_strncpy(record->string, "%.3f ms", TEXTSIZE);
		
		dst_reached = 1;

		/* Update min. RTT */
		min_rtt = MIN(record->delta, min_rtt);
	
		/* Update C's */
		if(!o_estimate_epsilon)
			points_Cs = calculate_C_regions_quantized();
	
		/* Dispaly */
		if(o_write)
		    showprobe(record);

		return;	
	}

	debug("Ignoring non-ICMP and non-TCP received packet\n");
	
}

/* Just grab packets from pcap. Adopted from Scriptroute (www.scriptroute.org) by Neil Spring*/
static void grab_packet(void)
{
  struct pcap_pkthdr hdr;
  const unsigned char *pbuf;
#ifndef __linux__
  while((pbuf = pcap_next(pcap, &hdr)) != NULL) {
    process_packet(&hdr, pbuf);
  }
#else
  
  pbuf = pcap_next(pcap, &hdr);
  if(pbuf != NULL) {
	  debug("Some data were captured\n");
	  process_packet(&hdr, pbuf);
  }
  
#endif
}

/* Append a proberecord into the queue of probes */
void append_record(proberecord *record)
{
	assert(record);

	if(prt){
		record->prev = prt;
		prt->next = record;
	}
	else {
		/* first node in the queue */
		prh = record;
	}

	probes_sent++;
	prt = record;
}

bool run_probing(void)
{
	int q = 0;
	int done = 0;
	proberecord *record;
	struct timeval now, timeleft, when;
	int ret;
	fd_set sfd;
	queue_entry *qe;
	bool b_probe;
	
//	fprintf(stderr, "RTTometer to %s on port %s, %d hops max", dst_name, dst_prt_name, o_ttl);
	logtime = time(NULL);
	log_time = asctime(localtime(&logtime));
	fprintf(logfile, "%s: RTTometer to %s on TCP port %s, %d hops max\n", log_time,dst_name, dst_prt_name, o_ttl);

	if (o_pktlen){
//		fprintf(stderr, ", %d byte packets", o_pktlen + LIBNET_TCP_H + LIBNET_IP_H);
		logtime = time(NULL);
    	log_time = asctime(localtime(&logtime));
	    fprintf(logfile, "%d byte packets\n", o_pktlen + LIBNET_TCP_H + LIBNET_IP_H);
	}
//	fprintf(stderr, "\n");

	/*
	  Summary of the algorithm I am using for probing.
	  -schedule first probe
	  - while(!done)
	  -    get_time_to_next_event
	  -	  select
	  -	  if(fdset)
	  -	    grab_packets
	  -	  else(timeout)
	  -	    check the event queue and execute all pending events
      -
	  -		Make sure when you send a probe you schedule 2 events: Probe timeout and next probe
	*/		

	record = newproberecord();
	append_record(record);

	if ((sockfd = libnet_open_raw_sock(IPPROTO_RAW)) < 0) {
//		pfatal("socket allocation");
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: socket allocation failed?\n", log_time);
		return false;
	}

	b_probe = probe(record, q++);
	if (!b_probe) {
		libnet_close_raw_sock(sockfd);
		return false;
	}
	
	debug("Sent probe %d of %d for hop %d, IP ID %d, source port %d, %s%s%s\n",
		  q, o_nprobes, o_ttl, record->id, record->src_prt,
		  o_syn ? "SYN " : "",
		  o_ack ? "ACK " : "",
		  o_ecn ? "CWR ECN " : "");
	
	/* Schedule the next probe if we need to send more */
	if(q < o_nprobes) {
		gettimeofday(&when, NULL);
		when.tv_sec += (o_tau/1000);
		when.tv_usec += ((o_tau % 1000) *1000);
		
		if(when.tv_usec > 1000000) {
			when.tv_sec++;
			when.tv_usec -= 1000000;
		}
		qe = create_qentry(PROBE_EVENT, when, 0);
		queue_insert(event_q, qe);
	}
	
	qe = get_first_entry(event_q);
	debug("EventQ size [%ld]\n", event_q->size);
	while(qe) {
		debug("Event [%X] id [%u] time [%ld.%ld]\n", qe->type, qe->id, qe->time.tv_sec, qe->time.tv_usec);
		qe = qe->next;
	}
	
	while(!done) {
		
		gettimeofday(&now, NULL);
		qe = get_first_entry(event_q);

		assert(qe);  /* There should be at least an event in the queue! */

		if( timercmp(&qe->time, &now, <) ) {
			/* Already passed the event time */
			timevalclear(&timeleft);
		}
		else
			timeleft = tvdiff(&qe->time, &now);
	
		FD_ZERO(&sfd); //clear out the fd_set called sfd, so that it doesn't contain any file descriptors
		FD_SET(pcap_fd, &sfd); //add file descriptor pcap_fd to fd_set
		debug("Select waiting for time %ld.%ld\n", timeleft.tv_sec, timeleft.tv_usec);
		
		//select() returns the number of sockets that had things 
		ret = select(pcap_fd + 1, &sfd, NULL, NULL, &timeleft); 

		if (ret < 0) {
//			fatal("select");
			libnet_close_raw_sock(sockfd);
			logtime = time(NULL);
    	    log_time = asctime(localtime(&logtime));
	        fprintf(logfile, "%s: select error\n", log_time);
			return false;
		}
		else if (ret > 0) {
			/* Something was received */
			debug("pcap has something\n");
			if(FD_ISSET(pcap_fd, &sfd))
				grab_packet();
		}
		else
			debug("select() timeout\n");

		/* Now check the event queue and see if we need to execute some events */

		/* Do we need to stop probing once we hit the CI threshold? */
		if(!o_estimate_epsilon) {
			if(CI >= CI_threshold) {
				done = 1;
				continue;
			}
		}
		else {
			/* We are estimating epsilon. If we lose 20% of the probes there is no point to go on probing, 
			   as the threshold for estimating epsilon is that 80% of the probes are successful	*/
			if (probes_timeout > (0.2 * EPS_MIN_PROBES)) {
				done = 1;
				continue;
			}
		}
	
		gettimeofday(&now, NULL);

		while( ((qe = get_first_entry(event_q)) != NULL) &&
			   (timercmp(&(qe->time), &now, <)) ) {
			
			switch(qe->type) {
				case PROBE_EVENT:
					record = newproberecord();
					append_record(record);
					b_probe = probe(record, q++);
					if(!b_probe) {
						libnet_close_raw_sock(sockfd);
						return false;
					}
					
					debug("Sent probe %d of %d for hop %d, IP ID %d, source port %d, %s%s%s\n",
						  q, o_nprobes, o_ttl, record->id, record->src_prt,
						  o_syn ? "SYN " : "",
						  o_ack ? "ACK " : "",
						  o_ecn ? "CWR ECN " : "");

					if(q < o_nprobes) {
						/* Schedule the next probe */
						debug("Scheduling next probe\n");
						gettimeofday(&when, NULL);
						when.tv_sec += (o_tau/1000);
						when.tv_usec += ((o_tau % 1000) *1000);

						if(when.tv_usec > 1000000) {
							when.tv_sec++;
							when.tv_usec -= 1000000;
						}
						qe = create_qentry(PROBE_EVENT, when, 0);
						queue_insert(event_q, qe);
					}
					break;
				case TIMEOUT_EVENT:
					record = (proberecord *) hashtable_lookup(probe_ht, qe->id );
					if(!record){
					//	fatal("Timeout event associated with non-existing probe id %u\n", qe->id);
						logtime = time(NULL);
    	                log_time = asctime(localtime(&logtime));
	                    fprintf(logfile, "%s: Timeout event associated with non-existing probe id %u\n", log_time,qe->id);
						libnet_close_raw_sock(sockfd);
						return false;
					}
					record->timeout = 1;
					record->rcvd = 1;
					/* Remove the record from the hashtable */
					hashtable_remove(probe_ht, record);
					if(!o_estimate_epsilon)
						points_Cs = calculate_C_regions_quantized();

					probes_timeout++;
					break;
				default:
				//	fatal("Unidentified event in the event queue %d\n", qe->type);
					logtime = time(NULL);
    	            log_time = asctime(localtime(&logtime));
	                fprintf(logfile, "%s: Unidentified event in the event queue %d\n", log_time, qe->type); 
					libnet_close_raw_sock(sockfd);
					return false;
					break;
			}

			/* Remove the event */
			queue_remove(event_q, qe->type, qe->id);
		}
		
		debug("Probes waiting [%u], Events [%u]\n", probe_ht->inserted, event_q->size); 
		qe = get_first_entry(event_q);
		
		while(qe) {
			debug("Event [%X] id [%u] time [%ld.%ld]\n", qe->type, qe->id, qe->time.tv_sec, qe->time.tv_usec);
			qe = qe->next;
		}
		
		if(!probe_ht->inserted && !event_q->size) 
			done = 1;
	}

	if (!dst_reached)
	{
//		fprintf(stderr, "Destination not reached\n");
        logtime = time(NULL);
    	log_time = asctime(localtime(&logtime));
	    fprintf(logfile, "%s: Destination not reached\n",log_time);
	}

	libnet_close_raw_sock(sockfd);
	return true;
	
}

/* Verify a command line argument is numeric; only to be called from main(). */
float checknumericarg(int optopt)
{
	int type;
	type = isnumeric(optarg);
	if (!type) {
	//	printf("Numeric argument required for -%c (found %s)\n", optopt, optarg);
		logtime = time(NULL);
    	log_time = asctime(localtime(&logtime));
	    fprintf(logfile, "%s: Numeric argument required for -%c (found %s)\n",log_time,optopt, optarg);
		exit(1);
	}

	if(type == 2) 									  /* Float */
		return atof(optarg);
	/* Otherwise it is int */
	return atoi(optarg);
}

/* Help process long command line arguments, only to be called using the CHECKLONG() macro, 
 * and only from main().  If the given word matches the current word being processed, 
 * it's removed from the argument list, and returns 1. */
#define CHECKLONG(word) ( checklong_real(word, &i, &argc, &argv) )

int checklong_real(char *word, int *i, int *argc, char ***argv)
{
	int j;

	if (strcmp((*argv)[*i], word) != 0)
		return 0;

	/* shift */
	for (j = *i; (*argv)[j]; j++)
		(*argv)[j] = (*argv)[j+1];

	(*argc)--;
	(*i)--;

	return 1;
}

unsigned int hash_key(const void *key)
{
	const proberecord *p1 = (const proberecord *) key;

	/* How to distinguigh between packets. Src/Dst IPs are the same,
	   Dst port is fixed. We can either send each probe from a different src port,
	   put a unique IP ID in each packet (current implementation), or make a unique
	   sequence number in the TCP packet for each probe.
	   Since we receive both ICMP error messages and TCP replies from targets. The last
	   method is the only one to guarantee that we associate the right probe with each reply packet
	   
	   Therefore, the hash key is simply the sequence number
	*/

	return ( (unsigned int) p1->seq );
}

/* See if the proberecord matchs */
int compare_keys(const void *key1, const void *key2)
{
	const proberecord *p1 = (const proberecord *) key1;
	const proberecord *p2 = (const proberecord *) key2;

	return (p1->seq == p2->seq);
}

/* Compare function used by quicksort */
int cmprtt(const void* rtt1, const void* rtt2)
{
	double *f1, *f2;
	assert(rtt1);
	assert(rtt2);

	f1 = (double *) rtt1;
	f2 = (double *) rtt2;

	if(*f1 < *f2) return -1;
	if(*f1 > *f2) return 1;

	return 0;
}

/* Found in mode.c file */
extern float mode(double *array, int len);

/* Display some statistics */
void statistics(void)
{
	proberecord *p = prh;
	double *rtts;
	int n = 0;
	
	rtts = RTTS;
	assert(rtts);

	/* Get RTTS */
	while(p) {
		if(!p->timeout && p->rcvd)
			rtts[n++] = p->delta;
		p = p->next;
	}

	if(n > 0) {
		rcv = n;
		qsort((void *) rtts, n, sizeof(double), cmprtt);
		/* Get the mode */
		mode_all = mode(rtts, n);
		
		if(o_write) {
		     printf("Min/10-tile/Q1/Median/Mode/Q3/90-tile/Max: %.3f/%.3f/%.3f/%.3f/%.3f/%.3f/%.3f/%.3f\n",
			   rtts[0], rtts[(int)(n*0.1)], rtts[(int)(n*0.25)], rtts[(int)(n*0.5)], mode_all, rtts[(int)(n*0.75)], rtts[(int)(n*0.9)], rtts[n-1]);
		
		     printf("Min RTT: %.3f msec", min_rtt);
		     /* Do we need to display CI and epsilon? */
		     if (n >= C_MIN_PROBES)
				 printf(", confidence %.3f (CI), epsilon %.3f msec", CI, epsilon);
		     printf("\n");
		}
	}
	 
	if(o_write) {
        printf("Number of probes sent: %u\n", probes_sent);
	    printf("Number of replies received: %d\n", n);
	    printf("Probes lost: %d\n", probes_timeout);
	}

}

/* Estimate the value of Epsilon. According to the paper it is roughly 2x(Q3-Q1)
 * where Q1 and Q3 are the first and third Quartile */
float epsilon_estimation(void)
{
	proberecord *p;
	double *rtts;
	int n = 0;
	double eps = -1.0;
	
	p = prh;
	rtts = (double *) calloc(o_nprobes, sizeof(double));
	assert(rtts);

	/* Get RTTS */
	while(p) {
		if(!p->timeout && p->rcvd)
			rtts[n++] = p->delta;
		p = p->next;
	}

	if (n >= (0.8 * EPS_MIN_PROBES)) {		 /* At least 80% of the probes are successful */
		qsort((void *) rtts, n, sizeof(double), cmprtt);
		mode_all = mode(rtts, n);
	
		/* Estimate epsilon */
		eps = 2*(mode_all - (float) rtts[0]);

		/* Make sure that eps >=0, as the mode sometimes may be very close
		   to the min, and due to percision the subtraction might be -ve value */
		eps = (eps < 0)? 0.0: eps;			
	}
	
	free(rtts);
	return eps;
}

/* Copy string */
char *cpstr(char *str)
{
	char *p;
	if (str) {
		p = (char *) malloc (1+strlen(str));
		if (!p){
//			fprintf(stderr, "Can't allocate some space for a string\n");
			logtime = time(NULL);
    	    log_time = asctime(localtime(&logtime));
	        fprintf(logfile, "%s: Can't allocate some space for a string\n", log_time);
			exit(1);
		}
		strcpy(p, str);
		return p;
	}
	else 
		return NULL;
}

/* Add hosts to the linked list */
void add_host(char *name)
{
	struct hostent *host_ent;
	u_int ipaddress;
	struct in_addr *host_add;
	host_entry *he;

	if ((ipaddress = inet_addr(name)) != -1) 
	{   /* input name is an IP addr, go with it */

		he = (host_entry *) calloc(1, sizeof(host_entry));
		if(!he) {
//			fprintf(stderr, "Can't allocate memory to host_entry\n");
			logtime = time(NULL);
    	    log_time = asctime(localtime(&logtime));
	        fprintf(logfile, "%s: Can't allocate memory to host_entry\n", log_time);
			exit(1);
		}

		he->i = num_hosts++;
		he->name = cpstr(name);
		he->saddr.sin_family = AF_INET;
		he->saddr.sin_addr.s_addr = ipaddress;

		/* add to the list */
		if(!t_list){
			t_list = he;
			h_list = he;
			he->next = NULL;
			he->prev = NULL;
		}
		else{
			t_list->next = he;
			he->prev = t_list;
			he->next = NULL; 
			t_list = he;
		}
		
		return;
	}

	/* input name is not an IP addr, maybe it's a host name */
	host_ent = gethostbyname(name);
	if (host_ent == NULL) {
		if (errno == TRY_AGAIN) {
			usleep(DNS_TIMEOUT);
			host_ent = gethostbyname(name);
		}
		if (host_ent == NULL) {
//			fprintf(stderr, "Can't lookup host [%s], add it to the list anyway\n", name);
			logtime = time(NULL);
    	    log_time = asctime(localtime(&logtime));
	        fprintf(logfile, "%s: Can't lookup host [%s]\n", log_time,name);
            he = (host_entry *) calloc(1, sizeof(host_entry));
		    if(!he) {
			   // fprintf(stderr, "Can't allocate memory to host_entry\n");
				logtime = time(NULL);
    	        log_time = asctime(localtime(&logtime));
	            fprintf(logfile, "%s: Can't allocate memory to host_entry\n", log_time);
			    exit(1);
			}

		    he->i = num_hosts++;
		    he->name = cpstr(name);
		    he->saddr.sin_family = AF_INET;
		    he->saddr.sin_addr.s_addr = 0;

		 /* add to the list */
		    if(!t_list){
			    t_list = he;
			    h_list = he;
			    he->next = NULL;
			    he->prev = NULL;
			}
		    else{
			    t_list->next = he;
			    he->prev = t_list;
			    he->next = NULL; 
			    t_list = he;
			}
		return;
		}
	}

	host_add = (struct in_addr *) *(host_ent->h_addr_list);
	if (host_add == NULL) {
//		fprintf(stderr, "Can't lookup host [%s], add it to the list anyway\n", name);
		logtime = time(NULL);
    	log_time = asctime(localtime(&logtime));
	    fprintf(logfile, "%s: Can't lookup host [%s]\n", log_time,name);
		he = (host_entry *) calloc(1, sizeof(host_entry));
		    if(!he) {
			  //  fprintf(stderr, "Can't allocate memory to host_entry\n");
				logtime = time(NULL);
    	        log_time = asctime(localtime(&logtime));
	            fprintf(logfile, "%s: Can't allocate memory to host_entry\n", log_time);
			    exit(1);
			}

		    he->i = num_hosts++;
		    he->name = cpstr(name);
		    he->saddr.sin_family = AF_INET;
		    he->saddr.sin_addr.s_addr = 0;

		 /* add to the list */
		    if(!t_list){
			    t_list = he;
			    h_list = he;
			    he->next = NULL;
			    he->prev = NULL;
			}
		    else{
			    t_list->next = he;
			    he->prev = t_list;
			    he->next = NULL; 
			    t_list = he;
			}
		return;
	}
	else {
		/* it is indeed a hostname with a real address */
		he = (host_entry *) calloc(1, sizeof(host_entry));
		if(!he){
		//	fprintf(stderr, "Can't allocate memory to host_entry\n");
			logtime = time(NULL);
    	    log_time = asctime(localtime(&logtime));
	        fprintf(logfile, "%s: Can't allocate memory to host_entry\n", log_time);
			exit(1);
		}

		he->i = num_hosts++;
		he->name = cpstr(name);
		he->saddr.sin_family = AF_INET;
		he->saddr.sin_addr.s_addr = host_add->s_addr;

		/* add to the list */
		if(!t_list){
			t_list = he;
			h_list = he;
			he->next = NULL;
			he->prev = NULL;
		}
		else{
			t_list->next = he;
			he->prev = t_list;
			he->next = NULL; 
			t_list = he;
		}
	}
}

void add_port(u_short port){
    host_port *hp;
    hp = (host_entry *) calloc(1, sizeof(host_port));
    hp->i = num_ports++;
	hp->port = port;
	if(!ttp_list) {
		ttp_list = hp;
		htp_list = hp;
		hp->next = NULL;
		hp->prev = NULL;
	}
	else{
		ttp_list->next = hp;
		hp->prev = ttp_list;
		hp->next = NULL;
		ttp_list = hp;
	}
}

/* Read and set flags and variables from command line */
void parse_command_line(int argc, char **argv)
{
	FILE *ping_file;
	int  op,i;
	char *optstring;

	/* First loop through and extract long command line arguments ... */
	for(i = 1; argv[i]; i++)
	{
		if (CHECKLONG("--help"))
			usage();

		if (CHECKLONG("--version"))
			about();


		if (CHECKLONG("--track-id") ||
			CHECKLONG("--track-ipid"))
		{
			o_trackport = 0;
			debug("o_trackport disabled\n");
			continue;
		}

		if (CHECKLONG("--track-port"))
		{
			o_trackport = 1;
			debug("o_trackport set\n");
			continue;
		}

		if (strcmp(argv[i], "--") == 0)
			break;

		if (argv[i][0] == '-' && argv[i][1] == '-')
		{
		//	fprintf(stderr, "Unknown command line argument: %s\n", argv[i]);
			logtime = time(NULL);
    	    log_time = asctime(localtime(&logtime));
	        fprintf(logfile, "%s: Unknown command line argument: %s\n", log_time,argv[i]);
			usage();
		}
	}

	/* ... then handoff to getopt() */
	opterr = 0;
	optstring = "zhvdni:l:L:f:Fm:P:p:c:C:e:o:s:t:T:I:SAE:y:H";

	while ((op = getopt(argc, argv, optstring)) != -1)
		switch(op)
		{
			case 'h':
				usage();

			case 'v':
				about();

			case 'd':
				o_debug++;
				debug("%s\n", VERSION);
#ifdef LIBNET_VERSION
				debug("Compiled with libpcap version %s, libnet version %s\n",
					pcap_version, LIBNET_VERSION);
#else
				debug("Compiled with libpcap version %s\n", pcap_version);
#endif
				break;

			case 'n':
				o_numeric = 1;
				debug("o_numeric set to 1\n");
				break;

			case 'y':
				o_write = 1;
				debug("o_write set to 1\n");
				break;

			case 'z': /* Estimate Epsilon */
				o_estimate_epsilon = 1;
				debug("o_estimate_epsilon set to 1\n");
				break;
				
			case 'i': /* Network interface to use */
				device = optarg;
				debug("device set to %s\n", device);
				break;

			case 'I': /* Inter-round interval */
				interval = (int) checknumericarg(op);
				debug("interval between rounds set to %d\n",interval);
				break;

			case 'l': /* Packet length */
				o_pktlen = (int) checknumericarg(op);
				debug("o_pktlen set to %d\n", o_pktlen);
				break;

			case 'L': /* loop */
				o_loop = 1;
				num_round = (int) checknumericarg(op);
                debug("round set to %d\n", num_round);
				break;

			case 'f': /* read hosts from file */
				filename = optarg;
				debug(" Reading from file %s\n", filename);
				break;

			case 'F':
				o_dontfrag = 1;
				debug("o_dontfrag set\n");
				break;

			case 'm': /* TTL value */
				o_ttl = (int) checknumericarg(op);
				debug("o_ttl set to %d\n", o_ttl);
				break;

			case 'P': /* source port */
				o_forceport = 1;
				if (getuid()) fatal("Sorry, must be root to use -p\n");
				src_prt = checknumericarg(op);
				debug("src_prt set to %d\n", src_prt);
				break;
				
			case 'p': /* destination port */
				dst_prt = (int) checknumericarg(op);
				debug("dst_prt set to %d\n", dst_prt);
				break;

			case 'c': /* Number of probes */
				o_nprobes = (int) checknumericarg(op);
				debug("o_nprobes set to %d\n", o_nprobes);
				break;

			case 'C': /* CI Threshold */
				CI_threshold = checknumericarg(op);
				debug("CI_threshold set to %.3f\n", CI_threshold);
				break;

			case 'e': /* Value of Epsilon */
				epsilon = checknumericarg(op);
				o_set_default_epsilon = 0;
				debug("epsilon set to %.3f\n", epsilon);
				break;

			case 'H': /* Every hour to probe */
				o_hour = 1;
				debug("o_hour set to %d\n", o_hour);
				break;
				
			case 'o': /* TOS value */
				o_tos = (int)checknumericarg(op);
				debug("o_tos set to %d\n", o_tos);
				break;
		
			case 's': /* source address */
				if (getuid()) fatal("Sorry, must be root to use -s\n");
				src = optarg;
				break;

			case 't': /* Timeout */
				o_timeout = (int) checknumericarg(op);
				debug("o_timeout set to %d\n", o_timeout);
				break;

			case 'T': /* Inter-probe interval in msec */
				o_tau = (int) checknumericarg(op);
				debug("o_tau set to %d\n", o_tau);
				break;

			case 'S':
				o_syn = 1;
				debug("o_syn set\n");
				break;

			case 'A':
				o_ack = 1;
				debug("o_ack set\n");
				break;

			case 'E':
				o_ecn = 1;
				debug("o_ecn set\n");
				break;

			case '?':
			default:
				if (optopt != ':' && strchr(optstring, optopt)){
				//	printf("Argument required for -%c\n", optopt);
				    logtime = time(NULL);
    	            log_time = asctime(localtime(&logtime));
	                fprintf(logfile, "%s: Argument required for -%c\n", log_time,optopt);
					exit(1);
				}
			//	fprintf(stderr, "Unknown command line argument: -%c\n", optopt);
				logtime = time(NULL);
    	        log_time = asctime(localtime(&logtime));
	            fprintf(logfile, "%s: Unknown command line argument: -%c\n", log_time,optopt);
				usage();
				break;
		}

		if (o_loop && o_hour){ 
		//	 fprintf(stderr, "%s: specify only one of L, H\n", argv[0]);
			 logtime = time(NULL);
    	     log_time = asctime(localtime(&logtime));
	         fprintf(logfile, "%s: %s: specify only one of L, H\n", log_time,argv[0]);
		}
			 
		argv = &argv[optind];

		if (*argv && filename) { usage(); }
		else if (*argv && !filename) {
			while (*argv) {
				add_host(*argv);
				++argv;
			}
		}
		else if (!*argv && !filename) { usage();}
		else if (!*argv && filename) {
			char line [MAX_HOSTS];
			char host [MAX_HOSTS];
			char tpt[6];
			char upt[6];
			u_short tport=0;
			u_short uport=0;
			int status;
			char* newfilename="/home/poly_wang/rttometer/hosts.old";
			FILE *tmp=fopen(filename,"r");

			if(tmp){
				logtime=time(NULL);
				log_time = asctime(localtime(&logtime));
				fprintf(logfile, "%s: Change host file name\n", log_time);
				fclose(tmp);
				status = rename(filename, newfilename);
				if(status==-1){
					log_time = asctime(localtime(&logtime));
					fprintf(logfile, "%s: Change host file name fail\n", log_time);
				}
			}
			else {
                logtime=time(NULL);
				log_time = asctime(localtime(&logtime));
				fprintf(logfile, "%s: There is no new host file now\n", log_time);
			}			
		
			ping_file = fopen(newfilename, "r");

			if (!ping_file) {
			//	fprintf(stderr, "Can't open file %s\n", filename);
				logtime = time(NULL);
    	        log_time = asctime(localtime(&logtime));
	            fprintf(logfile, "%s: Can't open file %s\n", log_time,newfilename);
				exit(1);
			}

			while (fgets(line,MAX_HOSTS,ping_file)){
				if (sscanf(line, "%s %s %s", host,tpt,upt)!=3)
					continue;
				if ((!*host)||(host[0]=='#'))         /* avoid comments */
					continue;
				debug("Host [%s]\n", host);
				tport = atoi(tpt);
				add_host(host);
				add_port(tport);
			}

			fclose(ping_file);
		}
		else
			usage();

		if(getuid() & geteuid()) {
		//	printf("Got root?\n"); 
			logtime = time(NULL);
    	    log_time = asctime(localtime(&logtime));
	        fprintf(logfile, "%s: Got root?\n", log_time);
			exit(1);
		}
}

/* estimate the value of epsilon if o_estimate_epsilon flag is set*/
void estimate(void){

	if(o_write)
		printf("--------------- Statistics ----------------------\n");
	if(o_estimate_epsilon) {
		epsilon = epsilon_estimation();
		if(epsilon >= 0 && o_write) {
			printf ("Estimation of Epsilon: %.3f msec\n", epsilon);
			points_Cs = calculate_C_regions_quantized();
			printf("CI = %.3f\nCII = %.3f\nCIII = %.3f\n", CI, CII, CIII);
		}
		else if(o_write) {
			printf("Can't estimate epsilon!\n");
		}
	}
	statistics();
}

/* Transfer current time to "day_mon hour:min:sec" format */
char *asctime(const struct tm *timeptr)
{
    static char wday_name[7][3] = {
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
    };
    static char mon_name[12][3] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    static char result[20];

    sprintf(result, "%.3s_%.3s_%2d %.2d:%.2d:%.2d",
        wday_name[timeptr->tm_wday],
        mon_name[timeptr->tm_mon],
        timeptr->tm_mday, timeptr->tm_hour,
        timeptr->tm_min, timeptr->tm_sec);
    return result;
}

/* Only get the date time "day_mon" */
char *datetime(const struct tm *timeptr)
{
	static char mon_name[12][4] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    static char result[15];
    sprintf(result, "_%.3s%2d_%.2d%.2d%.2d",
        mon_name[timeptr->tm_mon],timeptr->tm_mday,
		timeptr->tm_hour,timeptr->tm_min, timeptr->tm_sec);
    return result;
}

/* if there is something when probing a host, print this as the result */
void print_fail(char *dst){
	time_t now_time;
	char* print_time;
	float r=9999.9999;
	now_time = time(NULL);
	print_time = asctime(localtime(&now_time));
	debug( "begin write the results\n");
	if(f_xml)
		fprintf(output_file, "   <record>\n      <time>%s</time>\n      <src>%s</src>\n      <dst>\
0.0.0.0</dst>\n      <pkt_len>0</pkt_len>\n      <pkt_sent>0</pkt_sent>\n      <pkt_recv>\
0</pkt_recv>\n      <min_rtt>%.4f</min_rtt>\n      <avg_rtt>%.4f</avg_rtt>\n      <max_rtt>\
%.4f</max_rtt>\n   </record>\n", print_time,iptos(src_ip),r,r,r);
	else
		fprintf(output_file, "%s  %s  0.0.0.0  0  0  0  %.4f  %.4f  %.4f\n",print_time,iptos(src_ip),r,r,r);
}

/* reset some parameters before moving to next host */
void reset(void){
	prh = NULL;
	prt = NULL;
	points_Cs = 0;
	probes_sent = 0;     
	probes_timeout = 0;
	CI = CII = CIII = 0;
	rcv = 0;
	dst_reached = 0;
}

void freerecord(){
    proberecord *p;
	p = prh;
	while(p) {
		freeproberecord(p);
		p = p->next;
	}
}

/*print the header of xml file*/
void print_head(){
	fprintf(output_file,"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	if(f_br)  fprintf(output_file,"<bruteforce>\n");
	else if(f_rd) fprintf(output_file,"<random>\n");
	else if(f_tp) fprintf(output_file,"<twophase>\n");
}

void print_tail(){
	if(f_br)  fprintf(output_file,"</bruteforce>\n");
	else if(f_rd) fprintf(output_file,"</random>\n");
	else if(f_tp) fprintf(output_file,"</twophase>\n");
}

/* Find .tmp file under current directory and change to .xml file */
char* getXMLFile(void)
{
	// find *.xml data file under current directory
	char* samplesxmlpath;
	struct dirent **namelist;
    int n;
	char *ptr;

	n = scandir(".", &namelist, 0, alphasort);
    if (n < 0) {
	//	printf("There are no files in current directory!\n");
		logtime = time(NULL);
    	log_time = asctime(localtime(&logtime));
	    fprintf(logfile, "%s: There are no files in current directory!\n", log_time);
        return NULL;
	}
    else {
		// list of files in current directory
		// look for any files that have suffix .xml
		// return the first one we find
		while(n--)
		{
		//	samplesxmlpath = namelist[n]->d_name;
		//	printf("I see %s\n",namelist[n]->d_name);
            ptr = strrchr(namelist[n]->d_name, '.');
			if((ptr != NULL) && ((strcmp(ptr, ".tmp") == 0))){
				 samplesxmlpath = (char *) calloc(strlen(namelist[n]->d_name)+1, sizeof(char));
				 if(!samplesxmlpath) {
		         //    fprintf(stderr, "Error allocating memory to host table\n");
                     logtime = time(NULL);
    	             log_time = asctime(localtime(&logtime));
	                 fprintf(logfile, "%s: Error allocating memory to host table\n", log_time);
		             exit(1);
				 }
				 else {
				     strcpy(samplesxmlpath, namelist[n]->d_name);
				//	 printf("I find %s\n", samplesxmlpath);
                     free(namelist);
				     return samplesxmlpath;
				 }
			}
		}
		free(namelist);
		return NULL;
	}

}

/*If find .tmp file, change to .xml file*/
void changeXMLFile(const char* samplesxmlpath)
{
	// change *.tmp to *.xml
	char* newName=NULL;
	char* oldName=NULL;
	char* prefix=NULL;
	int status; 
	int len=strlen(samplesxmlpath);

    newName = (char *) calloc(40, sizeof(char));
	oldName = (char *) calloc(40, sizeof(char));
    prefix = (char *) calloc(40, sizeof(char));
	strncpy(prefix, samplesxmlpath, len-4);
	strcat(oldName, "./");
	strcat(oldName, samplesxmlpath);
	strcat(newName, "./");
	strcat(newName, prefix); 
	strcat(newName,".xml");
	status = rename(oldName, newName);
	free(newName);
	free(oldName);
	free(prefix);
	if(status==-1){
	//	printf("Change name fail!\n");
		logtime = time(NULL);
    	log_time = asctime(localtime(&logtime));
	    fprintf(logfile, "%s: Change name fail\n", log_time);
	}
}


int main(int argc, char **argv)
{
	FILE *config_file;  //for config file
	char value[100];
	char str[50], val[10];
	char* int_val;

	char* src_date;
	//int name_len;
	char* srcIp=NULL;  
	char* day_time;
	char* xml = ".tmp";
	char* txt = ".txt";
	char* samplesxmlpath = NULL;
	
	interfaces = NULL;
    host_entry *h;
	host_port *hp;
	char* d_addr;
	int d_unlookuped;

	time_t now_time; 
	char* print_time;

	uid_t root_id;

	struct hostent *host_unlookuped;
	struct in_addr *host_ul;

	bool b_def,b_init,b_run;
	
#if defined (__SVR4) && defined (__sun)
	o_trackport = 1; /* --track-port should be the default for Solaris */
#else
	o_trackport = 0; /* --track-id should be the default for everything else */
#endif
    
	/* open logfile */
	logfile = fopen("/home/poly_wang/RTT.log", "a");
	if(!logfile)
		fprintf(stderr, "Error open log file\n");
	setlinebuf(logfile);

	/* strip out path from argv[0] */
	name = basename(argv[0]);
	parse_command_line(argc,argv);

	/* if there is configuration file, read value from it to set some paramaters */
    config_file = fopen ("/home/poly_wang/rttometer/RTTAgent.cfg", "r");
	if(!config_file){
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
	//	fprintf(stderr, "There is no configure file %s\n", "RTTAgent.cfg");
		fprintf(logfile, "%s: There is no configure file %s\n", log_time, "RTTAgent.cfg");
	}
	else {
		while(fgets(value, 100, config_file)){
			sscanf(value, "%s %s", str, val);
			int_val=val;
			if(strcmp(str, "xml")==0){
                if(strcmp(val, "true")==0)
					f_xml=true;
			}
			else if(strcmp(str, "bruteforce")==0){
                if(strcmp(val, "true")==0)
					f_br=true;
			}
			else if(strcmp(str, "random")==0){
                if(strcmp(val, "true")==0)
					f_rd=true;
			}
			else if(strcmp(str, "twophase")==0){
                if(strcmp(val, "true")==0)
					f_tp=true;
			}
			else if(strcmp(str, "inter_probe_interval")==0) 
				o_tau = atoi(int_val);
			else if(strcmp(str, "inter_round_interval")==0) 
				interval = atoi(int_val);
			else if(strcmp(str, "num_probes")==0) 
				o_nprobes = atoi(int_val);
			else if(strcmp(str, "packet_length")==0) 
				o_pktlen = atoi(int_val);
			else if(strcmp(str, "timeout")==0) 
				o_timeout = atoi(int_val);
			continue;
		}
		fclose(config_file);
	}
	

	h = h_list;
	hp = htp_list;
	RTTS = (double *) calloc(o_nprobes, sizeof(double));
    dst = h->name;
	defaults();

    /* open the output file to write results */
	now_time = time(NULL);
	day_time = datetime(localtime(&now_time));
	srcIp = iptos(src_ip);
	//name_len = strlen(srcIp)+12;
	src_date = (char *) calloc(50, sizeof(char));
    strcat(src_date, srcIp);
	strcat(src_date, day_time);
	
	if(f_xml){ // write results to a xml file
		strcat(src_date,xml);
		outFileName = src_date;
	}
	else{ //write results to a txt file
		strcat(src_date,txt);
		outFileName = src_date;
	}
	output_file = fopen(outFileName, "w");
	if (output_file == NULL) {
	//	fprintf(stderr, "Can't open output_file.\n");
		logtime = time(NULL);
		log_time = asctime(localtime(&logtime));
		fprintf(logfile, "%s: Can't open output_file.\n", log_time);
		exit(-1);
	}
	setlinebuf(output_file);
	if(f_xml)
		print_head();

	if(o_loop&&num_round) num_round--;

	/* Main loop */
	while(h){
		dst = h->name;
		if (hp) dst_prt = hp->port;
        d_unlookuped = h->saddr.sin_addr.s_addr;
		if(d_unlookuped && h) { /* current host is lookuped and not the end of the list */
			d_addr = inet_ntoa(h->saddr.sin_addr);
			b_def = dstcheck(); 
			/* First check whether the destination is available,if so continue, else move to next host */
			if(b_def) {
				b_init = initcapture(); 
				if (b_init){ /* initcapture() success for current host, continue */
					root_id = geteuid(); /* save the root privilege */
					seteuid(getuid());
					probe_ht = hashtable_new(HASHTABLE_SIZE, hash_key, compare_keys, NULL);
					event_q = (queue *) calloc(1, sizeof(queue));
					assert(event_q);
					b_run = run_probing();
					setuid(root_id);
					if(b_run) /* run_probing() success for current host, continue */
						estimate();
					else { /* run_probing() failed for current host, move to next one */
						print_fail(dst);
						h = h->next;
						if(hp) hp = hp->next;
						reset();
						if(prh) freerecord();
						pcap_close(pcap);
						pcap = NULL;
						free(event_q);
						continue;
					}
				}
				else { /* initcapture() failed for current host, move to next one */
					print_fail(dst);
					h = h->next;
					if(hp) hp = hp->next;
					reset();
					continue;
				}
			}
			else { /* defaults()failed for current host, move to next host*/
				print_fail(dst);
				h = h->next;
				if(hp) hp = hp->next;
				reset();
				continue;
			}
		} 
		else if(!d_unlookuped && h){ /* current host was not lookuped and not the end of the list*/
			host_unlookuped = gethostbyname(dst);
			if (host_unlookuped == NULL) { /* lookup again */
                if (errno == TRY_AGAIN) {
					usleep(DNS_TIMEOUT);
					host_unlookuped = gethostbyname(name);
				}
				if (host_unlookuped == NULL) {
	//				fprintf(stderr, "Still can't lookup host [%s]\n", dst);
					logtime = time(NULL);
		            log_time = asctime(localtime(&logtime));
		            fprintf(logfile, "%s: Still can't lookup host [%s]\n", log_time, dst);
					d_addr = "";
					print_fail(dst);
					h = h->next;
					if(hp) hp = hp->next;
					reset();
					continue;
				}
				else {
					host_ul = (struct in_addr *) *(host_unlookuped->h_addr_list);
					h->saddr.sin_addr.s_addr = host_ul->s_addr;
					d_addr = inet_ntoa(h->saddr.sin_addr);
					b_def = dstcheck(); 
					/* First check whether defaults() success or not, if so continue, otherwise move to next host */
					if(b_def) {
						b_init = initcapture(); 
						if (b_init){ /* initcapture() success for current host, continue */
							root_id = geteuid(); /* save the root privilege */
							seteuid(getuid());
							probe_ht = hashtable_new(HASHTABLE_SIZE, hash_key, compare_keys, NULL);
							event_q = (queue *) calloc(1, sizeof(queue));
							assert(event_q);
							b_run = run_probing();
							setuid(root_id);
							if(b_run) {  /* run_probing() success for current host, continue */
								estimate();
							}
							else { /* run_probing() failed for current host, move to next one */
								print_fail(dst);
								h = h->next;
								if(hp) hp = hp->next;
								reset();
								if(prh) freerecord();
								pcap_close(pcap);
						        pcap = NULL;
								free(event_q);
								continue;
							}
						}
						else { /* initcapture() failed for current host, move to next one */
							print_fail(dst);
							h = h->next;
							if(hp) hp = hp->next;
							reset();
							continue;
						}
					}
					else { /* defaults()failed for current host, move to next host*/
						print_fail(dst);
						h = h->next;
						if(hp) hp = hp->next;
						reset();
						continue;
					}
				}
			}
		}

		now_time = time(NULL);
		print_time = asctime(localtime(&now_time));
		debug( "begin write the results\n");
		if(rcv==0) {
			RTTS[0]=9999.9999;
			RTTS[-1]=9999.9999;
		}
		if(f_xml)
			fprintf(output_file, "   <record>\n      <time>%s</time>\n      <src>%s</src>\n      <dst>%s</dst>\n\
      <pkt_len>%d</pkt_len>\n      <pkt_sent>%d</pkt_sent>\n      <pkt_recv>%d</pkt_recv>\n      <min_rtt>%.4f</min_rtt>\n\
      <avg_rtt>%.4f</avg_rtt>\n      <max_rtt>%.4f</max_rtt>\n   </record>\n", 
	        print_time,iptos(src_ip),d_addr,o_pktlen + LIBNET_TCP_H + LIBNET_IP_H,
			probes_sent,rcv,RTTS[0],  RTTS[(int)(rcv*0.5)], RTTS[rcv-1]);
		else
			fprintf(output_file, "%s  %s  %s  %d  %d  %d  %.4f  %.4f  %.4f\n",
			print_time,iptos(src_ip),d_addr,o_pktlen + LIBNET_TCP_H + LIBNET_IP_H,
			probes_sent,rcv,RTTS[0],  RTTS[(int)(rcv*0.5)], RTTS[rcv-1]);
		
		h = h->next;
		if(hp) hp = hp->next;
		free(event_q);
		freerecord();
		reset();
		pcap_close(pcap);
		pcap = NULL;
        
	} /* while(h) */
	if(f_xml)
		print_tail();	
	fclose(output_file);
	samplesxmlpath = getXMLFile();
	if(samplesxmlpath)
		changeXMLFile(samplesxmlpath);

	fclose(logfile);
	close(s);
	return 0;
}
