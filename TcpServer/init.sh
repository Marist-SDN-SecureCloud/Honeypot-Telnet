#/bin/bash
# Author:  Daniel Nicolas Gisolfi


# cp ptelnetd /usr/local/sbin/ptelnetd
# chmod a+rx /usr/local/sbin/ptelnetd

# Turn on the telnet honeypot
/usr/local/sbin/ptelnetd -honeypot

# Enable the TCP server
python3 -u server.py