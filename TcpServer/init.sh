#/bin/bash
# Author:  Daniel Nicolas Gisolfi

# Turn on the telnet honeypot
/usr/sbin/ptelnetd -honeypot

# Enable the TCP server
python3 -u server.py