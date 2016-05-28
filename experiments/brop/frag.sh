#!/bin/bash

IP=$1

echo Fragging for $IP

killall -9 frag 2> /dev/null

RT=$(ip route get $IP | head -n 1)

RTR=$IP
SIP=$(echo $RT | awk '{print $5}')
DEV=$(echo $RT | awk '{print $3}')

if [[ "$RT" == *via* ]]
then
	RTR=$(echo $RT | awk '{print $3}')
	SIP=$(echo $RT | awk '{print $7}')
	DEV=$(echo $RT | awk '{print $5}')
fi

MAC=$(arp -an | grep "($RTR)" | awk '{print $4}')

if [[ "$MAC" != *:* ]]
then
	echo getting mac of $RTR
	ping -c 1 $RTR

	MAC=$(arp -an | grep "($RTR)" | awk '{print $4}')

	if [[ "$MAC" != *:* ]]
	then
		echo dunno
		exit 1
	fi
fi

IFIDX=$(ip link show dev $DEV | head -n 1 | awk '{print $1}' | tr -d ':')

echo Src IP $SIP Dst IP $IP MAC $MAC Dev $DEV Idx $IFIDX

set -m

./frag $IFIDX $MAC &

sleep 2

sysctl net.ipv4.ip_no_pmtu_disc=1
sysctl net.ipv4.route.mtu_expires=1

ifconfig frag0 $SIP dstaddr $IP mtu 9000 up
iptables -I INPUT -p tcp -s $IP --tcp-flags SYN,ACK SYN,ACK \
	-j NFQUEUE --queue-num 666

echo Done

fg 1
