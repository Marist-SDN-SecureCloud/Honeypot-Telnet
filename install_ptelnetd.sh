#!/bin/sh
######################################################################
# install_ptelnetd.sh
# Written by: Eric Wedaa
# Version: 1.0
# Last Update: 2016-03-10, Created
#
# LICENSE: GPLV2: Please see the README at 
# https://github.com/wedaa/LongTail-Log-Analysis/blob/master/README.md
#
######################################################################
if [[ $EUID -ne 0 ]]; then
	echo "Sorry, this script must be run as root" 1>&2
	exit 1
fi

if [ -d /usr/local/source/ptelnetd ] ; then
	echo "It looks like you have already installed the LongTail ptelnetd honeypots "
	echo "on this server."
	echo ""
	echo "If you wish to reinstall or install a newer version of the "
	echo "LongTail ptelnetd honeypots, then you need to run the following"
	echo "command:"
	echo "   /bin/rm -rf /usr/local/source/ptelnetd"
	echo "and then run this script again."
	exit;
fi

mkdir -p /usr/local/source/ptelnetd
cd /usr/local/source/ptelnetd

######################################################
wget https://github.com/wedaa/LongTail-Telnet-honeypot-v2/raw/master/paranoid-telnetd-0.4.tgz

tar -xf paranoid-telnetd-0.4.tgz
cd paranoid-telnetd-0.4

cp ptelnetd-initd /etc/init.d
chmod a+rx /etc/init.d/ptelnetd-initd

mv main.c main.c.orig
wget https://raw.githubusercontent.com/wedaa/LongTail-Telnet-honeypot-v2/master/main.c

./configure
make
if [ -e "ptelnetd" ] ; then
	cp ptelnetd /usr/local/sbin/ptelnetd
	chmod a+rx /usr/local/sbin/ptelnetd
	cd ..
else
	echo "Something is wrong, could not make ptelnetd properly, exiting now"
	exit
fi


##################################################
# check to see if it's already in /etc/rc.local
grep ^\/usr\/local\/sbin\/ptelnetd\  /etc/rc.local >/dev/null
if [ $? -eq 0 ]; then
    echo "ptelnetd already in /etc/rc.local"
else
	echo ""
	echo "Adding startup line for ptelnetd to /etc/rc.local"
	echo ""
	echo "/usr/local/sbin/ptelnetd -honeypot " >> /etc/rc.local
fi

echo "Please start ptelnetd by hand to start it now"
echo ""
echo "/usr/local/sbin/ptelnetd -honeypot"

