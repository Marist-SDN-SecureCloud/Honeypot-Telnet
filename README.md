README for LongTail-Telnet-honeypot-v2
==============

What LongTail-Telnet-honeypot-v2 does
--------------
Telnet-honeypot is a telnet honeypot which logs attempts to a
to syslog in the LongTail logging format. 

It can be started with the following commandline.

	/usr/local/sbin/ptelnetd -honeypot

It is based entirely on

	https://sites.google.com/site/columscode/home/ParanoidTelnetD

which is Copyright (C) 2014 Colum Paget

Installing the Honeypot
--------------
I have an installation script which will help significantly and you can
download and run it from
	wget https://raw.githubusercontent.com/wedaa/LongTail-Telnet-honeypot-v2/master/install_ptelnetd.sh

This will configure, make, and install ptelnetd into /usr/local/sbin/ptelnetd
and add a startup line to /etc/rc.local to start ptelnetd after a reboot.

Licensing
--------------
Minor Modifications Copyright (C) 2016 Eric Wedaa

OTHERWISE

Copyright (C) 2014 Colum Paget, colums.projects@gmail.com, http://www.cjpaget.co.uk

