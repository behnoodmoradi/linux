#!/bin/bash
PERMIT_TCP="22 443 5800 8888"
PERMIT_UDP="8888"
PERMIT_ICMP=false
DENY_EXCEPT_IRAN=true
COUNTRY=ir

#flush iptables
iptables -F
ip6tables -F

#get addresses of iran
if $DENY_EXCEPT_IRAN ; then
        echo 'Updating ubuntu and install ipset'
        apt update > /dev/null 2>&1
        apt install ipset -y > /dev/null 2>&1

        echo "download $COUNTRY address list"
        wget https://www.ipdeny.com/ipblocks/data/aggregated/$COUNTRY-aggregated.zone -O /tmp/$COUNTRY-aggregated.zone > /dev/null 2>&1

        ipset destroy $COUNTRY #/dev/null 2>&1
        ipset create $COUNTRY hash:net

        for IP in `cat /tmp/$COUNTRY-aggregated.zone`
        do
                ipset add $COUNTRY $IP > /dev/null 2>&1
        done

        rm -f /etc/ipset.rules > /dev/null 2>&1
        ipset save > /etc/ipset.rules /dev/null 2>&1
fi

#permit localhost
echo "permit local traffics"
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT

#allow related, established
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

#deny invalid
iptables -A INPUT -m conntrack  --ctstate INVALID -j DROP
iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP

ip6tables -A INPUT -m conntrack  --ctstate INVALID -j DROP
ip6tables -A OUTPUT -m conntrack --ctstate INVALID -j DROP

#deny except iran V4
if $DENY_EXCEPT_IRAN ; then
        iptables -A INPUT -m set ! --match-set $COUNTRY src -j DROP
fi

#permit tcp
for TCP in $PERMIT_TCP
do
        iptables -A INPUT -p tcp --dport $TCP -j ACCEPT
        ip6tables -A INPUT -p tcp --dport $TCP -j ACCEPT
done

#permit udp
for UDP in $PERMIT_UDP
do
        iptables -A INPUT -p udp --dport $UDP -j ACCEPT
        ip6tables -A INPUT -p udp --dport $UDP -j ACCEPT
done

#permit tcp
if $PERMIT_ICMP ; then
        iptables -A INPUT -p icmp -j ACCEPT
        ip6tables -A INPUT -p icmp -j ACCEPT
else
        iptables -A INPUT -p icmp -j DROP
        ip6tables -A INPUT -p icmp -j DROP
fi



#drop policy
iptables -P INPUT DROP
iptables -P OUTPUT DROP

ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
