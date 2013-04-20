newping
=======

Your nmap -p [port] [host] before nmap

This version of newping is a slight rewrite to support ping at any arbitirary
TCP port specified by the user.  The older version is available at

	ftp://ftp.nec.com/pub/security/socks.cstc/newping.c

The rewrite was needed because I could no longer hack on the original code and
trace some core dumps. 

This version of newping was forked by the one written by Adam Zell
<zell@public.btr.com>, and was published in the September/October 1993 edition
of Sys Admin.

Yiorgos Adamopoulos (adamo@ntua.gr) $Date: 1996/07/01 18:45:09 $

Tested on Solaris2.5 (Sparc) with gcc-2.7.2.

Switches:
	-d:     debug mode (dafaults to no)
	-u:     udp ping (defaults to tcp)
	-p:     specify port to be probed (defaults to 37 (time))
	-S:     string to send (defaults to "foo")
	-q:     quiet mode (set $status only)

For historic reasons only.
