#/bin/bash
# Author:  Daniel Nicolas Gisolfi

# turn on cron
cron

# Turn on the telnet honeypot
/usr/sbin/ptelnetd -honeypot

# Enable the TCP server
python3 -u server.py