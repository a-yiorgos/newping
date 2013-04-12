/* 
 * $Revision: 2.2 $
 *
 * This version of newping is a slight rewrite to support ping at any 
 * arbitary TCP port specified by the user.  The older version is 
 * available at ftp://ftp.nec.com/pub/security/socks.cstc/newping.c
 *
 * The rewrite was needed because I could no longer hack on the original
 * code and trace some core dumps. 
 *
 * Yiorgos Adamopoulos (adamo@ntua.gr) $Date: 1996/07/01 18:45:09 $
 *
 * Tested on Solaris2.5 (Sparc) with gcc-2.7.2.
 *
 * Switches:
 * 	-d:	debug mode (dafaults to no)
 *	-u:	udp ping (defaults to tcp)
 *	-p:	specify port to be probed (defaults to 37 (time))
 *	-S:	string to send (defaults to "foo")
 *	-q:	quiet mode (set $status only)
 */

#ifndef lint
static char hacksby[] =
"@(#)adamo@ntua.gr $Revision: 2.2 $";
#endif /* lint */

/* Blurb from original newping.c:

	There was some discussion a little while back about a "ping" for SOCKS.
	The obvious thing here seems to be to use something that uses a common
	TCP service to get an echo, rather than ICMP.  Luckily, such a thing
	already existed...

	Naturally, this depends on the target host not blocking the service on
	the appropriate port (in this case "time").  And this version is
	primarily for checking "Is it alive?" rather than gathering statistics
	on the average response time of several echo requests.  And it requires
	an ANSI C compiler (GCC 2 is sufficient).

	For SunOS 4, I use "gcc newping.c -o newping -DSOCKS -lsocks -lresolv"

	This version of newping was written by Adam Zell <zell@public.btr.com>,
	and was published in the September/October 1993 edition of Sys Admin.

	It uses the "time" TCP port to verify that a host is up, rather than
	using ICMP.  It is thus usable through a firewall that blocks ICMP.

	Requires an ANSI C compiler.

	Utterly trivial modifications made for SOCKS by
	Bryan Curnutt <bryan@Stoner.COM>.
*/

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>

#ifndef INADDR_NONE
#define INADDR_NONE	(-1)
#endif

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif

#ifdef HAS_NOT_HERROR		/* define this if your libresolv.a */
#define herror perror		/* does not have a herror()        */
#endif 

#define SVC_PORT	"time"		/* default service name  */
#define DEF_PORT	37 		/* default service port  */
#define DEF_TOUT	20 		/* default timeout       */
#define DEF_BUF		4096 		/* default buffer length */
#define DEF_REPEATS	10		/* repeats for ping -s   */

#define DEBUG		0x01		/* debug mode   */ 
#define TCP_PING	0x02		/* tcp ports    */
#define UDP_PING	0x04		/* udp ports    */
#define QUIET		0x08		/* like ping -s */

#define is_opt(x)	(opts & (x))	/* options check stuff */
#define not_opt(x)	(!(is_opt(x)))
#define add_opt(x)	(opts |= (x))
#define rm_opt(x)	(is_opt(x) > 0 ? (opts ^= (x)) : x)
unsigned long opts = TCP_PING;
extern int optind;
extern char *optarg;

#ifdef SOCKS				/* SOCKS compatibility */
#define connect(x, y, z) Rconnect(x, y, z)
#endif 

char __progname[] = "newping";

/*
 * All variables are defined as global.  It's a kludge
 * but it works ok for this program.
 */

int timeout = DEF_TOUT, seconds = 1, sckt, res, 
    sin_len = sizeof(struct sockaddr_in), def_port = DEF_PORT;
char c, svc_port[DEF_BUF] = SVC_PORT, hname[MAXHOSTNAMELEN], 
     hstr[MAXHOSTNAMELEN], foo[4096];
unsigned long ipaddr;
struct protoent	  *proto;
struct hostent *host;
struct servent *service;
struct sockaddr_in rem_sin;
struct sigaction sig;

/* This should be turned into sth. more helpful */

void usage() {
	fprintf(stderr, "usage: %s [-q] [-d] [-u] [-p port] [-S string] host [timeout]\n", __progname);
	exit(1);
}

void noconnect(int i) {
	alarm(1);
	seconds++;
	if (is_opt(DEBUG))
		printf("no connect after %d seconds\n", seconds - 1);
	if (seconds > timeout) {
		printf("%s not acknowledging connect\n", hname);
		exit(1);
	}
}

void noresponse(int i) {
	alarm(1);
	seconds++;
 	if (is_opt(DEBUG))
		printf("no response after %d seconds\n", seconds - 1);
	if (seconds > timeout) {
		printf("%s not responding\n", hname);
		exit(1);
	}
}

/* Finally, let's do sth. with the above crap ;-) */

main(int argc, char **argv) {

	if (argc == 1)				/* duh!?! */
		usage();

#ifdef SOCKS					/* SOCKS */
	SOCKSinit(pname);
#endif /* SOCKS */

	if ((proto = getprotobyname("tcp")) == NULL) {
		perror("getprotobyname");
		exit(1);
	}

	strcpy(foo, "foo\n\r");

	/* Parse the options on the command line. */

	while((c = getopt(argc, argv, "qdup:S:")) != -1) /* options */
	switch(c) {
	case 'd':					/* debug */
		add_opt(DEBUG);
		break;
	case 'u':					/* use udp */
		if ((proto = getprotobyname("udp")) == NULL) {
			perror("getprotobyname");
			exit(1);
		}
		rm_opt(TCP_PING); 
		add_opt(UDP_PING);
		break;
	case 'q':
		close(1); /* stdout */
		close(2); /* stderr */
		break;
	case 'S':
		sprintf(foo, "%s\n\r", optarg);
		foo[4095] = '\0';
		break;
	case 'p':					/* specify port */
		/*
		 * Warning, if you change to UDP, this should be done
		 * before issuing the -p switch.
		 */

		if (isdigit(optarg[0]))	{	/* we use port numbers */
			def_port = atoi(optarg);
			if ((service = getservbyport(def_port, proto->p_name)) == NULL) {
				strcpy(svc_port, "(unknown)");
			}
			else {
				strcpy(svc_port, service->s_name);
			}
		}
		else {				/* we use service names */
			if ((service = getservbyname(optarg, proto->p_name)) == NULL) {
				perror("getservbyname");
				exit(1);
			}
			strcpy(svc_port, optarg);
			def_port = service->s_port;
		}
		break;
	default:				/* dumb usage */
		usage();
	}

	rem_sin.sin_port = def_port;

	/*
	 * if argc - optind == 1 then we query a host with default timeout
	 * if argc - optind == 2 then we query a host with another timeout
	 * anything else is invalid
	 */

	switch(argc - optind) {
	case 2:
		timeout = atoi(argv[argc - 1]);
		if (timeout <= 0) {
			fprintf(stderr, "%s: timeout set <= 0.\n", __progname);
			usage();
		}
		if (is_opt(DEBUG))
			printf("Timeout set to %d seconds\n", timeout);
		argc--;			 /* so that we don't rite twice */
	case 1:
		if (isdigit(argv[argc - 1][0])) {	/* xxx.yyy.zzz.www */
			if ((ipaddr = inet_addr(argv[argc - 1])) == INADDR_NONE) {
				herror(argv[argc - 1]);
				exit(1);
			}

			rem_sin.sin_family = AF_INET;
			rem_sin.sin_addr.s_addr = ipaddr;

			if ((host = gethostbyaddr((char *) &ipaddr, sizeof(long), AF_INET)) == NULL) {
				/* herror(argv[argc - 1]);
				exit(1); */
				strcpy(hname, argv[argc - 1]);
			}
			else {
				strcpy(hname, host->h_name);
			}
		}
		else {				/* DNS style */
			if ((host = gethostbyname(argv[argc - 1])) == NULL) {
				herror(argv[argc - 1]);
				exit(1);
			}
			rem_sin.sin_family = host->h_addrtype;
			memcpy(&rem_sin.sin_addr.s_addr, host->h_addr, host->h_length);

			strcpy(hname, argv[argc -1]);
		}
		break;
	default:
		usage();
	}
	
	/* spit some debug output */

	if (is_opt(DEBUG)) {
		printf("Service %s recognised as port %d/%s\n", svc_port, def_port, proto->p_name);
		printf("Host %s has IP address %u.%u.%u.%u\n", hname, (rem_sin.sin_addr.s_addr >> 24) & 0xff, (rem_sin.sin_addr.s_addr >> 16) & 0xff, (rem_sin.sin_addr.s_addr >> 8) & 0xff, rem_sin.sin_addr.s_addr & 0xff);
	}

	/* aquire a socket */

	if (is_opt(TCP_PING)) {
		if ((sckt = socket(PF_INET, SOCK_STREAM, proto->p_proto)) < 0) {
			perror("socket");
			exit(1);
		}
	}
	else if (is_opt(UDP_PING)) {
		if ((sckt = socket(PF_INET, SOCK_DGRAM, proto->p_proto)) < 0) {
			perror("socket");
			exit(1);
		}
	}

	if (is_opt(DEBUG))
		printf("Socket open.  Descriptor Number %d\n", sckt);

	/* start signal handling */

	sig.sa_handler = &noconnect;		/* ALRM */
	sigemptyset(&sig.sa_mask);
#ifdef SA_RESTART
	sig.sa_flags = SA_RESTART;
#else
	sig.sa_flags = 0;
#endif /* SA_RESTART */
	sigaction(SIGALRM, &sig, NULL);
	alarm(1);

	/* connectivity check */

	res = connect(sckt, (struct sockaddr *) &rem_sin, sin_len);
	while (res < 0) {
		if (errno != EINTR && errno != EISCONN)
			perror("connect");
		
		switch(errno) {
			case EINTR:			/* interrupted... */
			case EISCONN:
				close(sckt);
				if (is_opt(TCP_PING)) {
					if ((sckt = socket(PF_INET, SOCK_STREAM, proto->p_proto)) < 0) {
						perror("socket");
						exit(1);
					}
				}
				else if (is_opt(UDP_PING)) {
					if ((sckt = socket(PF_INET, SOCK_DGRAM, proto->p_proto)) < 0) {
						perror("socket");
						exit(1);
					}
				}
				break;
			default:
				exit(1);
		}

		res = connect(sckt, (struct sockaddr *) &rem_sin, sin_len);
	}

	if (is_opt(DEBUG))
		printf("Connect made (returned with %d)\n", res);

	/* done with connect, change signal handlers */

	sig.sa_handler = &noresponse;
	sigaction(SIGALRM, &sig, NULL);

	/*
	 * Trivial catch.  Some tcp services wait until data is 
	 * send over the connection and send theirs over.  Not
	 * every service starts with a banner.  So we make them
	 * spit some garbage.
	 */

	if (send(sckt, foo, 5, 0) < 0) {
		perror("send");
		exit(1);
	}

	do {
		char buf[DEF_BUF];			 /* duh ?!? */

		res = recv(sckt, buf, DEF_BUF - 1, 0);
		if (res < 0 && errno != EINTR) { 
			perror("recv");
			exit(1);
		}
	} while (res < 0);

	/* done with responses, stop SIGALRM */

	sig.sa_handler = SIG_IGN;
	sigaction(SIGALRM, &sig, NULL);

	if (is_opt(DEBUG))
		printf("Received something.  Len = %d  Total Elapsed Time: %d\n", res, seconds);

	printf("%s is alive (%d)\n", hname, seconds);

	exit(0);
}

/* end of file */
