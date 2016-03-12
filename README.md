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

Rsyslog Note
--------------

1) If you are using rsyslog, please use the following line in your honeypot's (and if you are
using a consolidation server's ) rsyslog.conf file.

  $ActionFileDefaultTemplate RSYSLOG_FileFormat


This sets the date format to a more easily parsable format:
	2016-03-06T04:33:43-05:00 ecdal2 sshd-22[25692]: IP: 183.3.202.102 PassLog: Username: root Password: leather

Please note the date stamp is YYYY-MM-DDTHH:MM:SS-GMT_offset.  Please note the capital "T" as the delimeter
from date to hour.

Logging Line Format
--------------
The log line format is as follows:
  YYYY-MM-DD<T>:HH:MM:SS.<optional milliseconds><DASH>HH:MM<SPACE>HOSTNAME<SPACE>ptelnetd[<PID>]:<SPACE>IP:<SPACE>127.0.0.1<SPACE>TelnetLog:<SPACE>Username:<SPACE>Username_tried<SPACE>Password:<SPACE>Password_tried

For Example:
  2016-03-10T12:26:18.899244-05:00 localhost ptelnetd[9836]: IP: 127.0.0.1 TelnetLog: Username: TEW Password: TEWEW


Licensing
--------------
Minor Modifications Copyright (C) 2016 Eric Wedaa

OTHERWISE

Copyright (C) 2014 Colum Paget, colums.projects@gmail.com, http://www.cjpaget.co.uk

