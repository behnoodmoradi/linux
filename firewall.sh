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

        echo `wc -l | cat /etc/ipset.rules`
fi

#permit localhost
echo "permit local v4 traffics"
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

echo "permit local v6 traffics"
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT

#allow related, established v4
echo "permit ESTABLISHED,RELATED input v4"
        iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
echo "permit NEW,ESTABLISHED,RELATED input v4"
        iptables -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

echo "permit ESTABLISHED,RELATED input v6"
        ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
echo "permit NEW,ESTABLISHED,RELATED input v6"
        ip6tables -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

#deny invalid
echo "deny INVALID input v4"
        iptables -A INPUT -m conntrack  --ctstate INVALID -j DROP
echo "deny INVALID output v4"
        iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP

echo "deny INVALID input v6"
        ip6tables -A INPUT -m conntrack  --ctstate INVALID -j DROP
echo "deny INVALID output v6"
        ip6tables -A OUTPUT -m conntrack --ctstate INVALID -j DROP

#deny except iran V4
if $DENY_EXCEPT_IRAN ; then
        echo "deny input except $COUNTRY v4"
        iptables -A INPUT -m set ! --match-set $COUNTRY src -j DROP
fi

#permit tcp
for TCP in $PERMIT_TCP
do
        echo "permit tcp traffic on port $TCP v4"
                iptables -A INPUT -p tcp --dport $TCP -j ACCEPT
        echo "permit tcp traffic on port $TCP v6"
                ip6tables -A INPUT -p tcp --dport $TCP -j ACCEPT
done

#permit udp
for UDP in $PERMIT_UDP
do
        echo "permit udp traffic on port $UDP v4"
                iptables -A INPUT -p udp --dport $UDP -j ACCEPT
        echo "permit udp traffic on port $UDP v6"
                ip6tables -A INPUT -p udp --dport $UDP -j ACCEPT
        
        
done

#permit icmp
if $PERMIT_ICMP ; then
        echo "permit icmp traffics v4"
                iptables -A INPUT -p icmp -j ACCEPT
        echo "permit icmp traffics v6"
                ip6tables -A INPUT -p icmp -j ACCEPT
else
        echo "deny icmp traffics v4"
                iptables -A INPUT -p icmp -j DROP
        echo "deny icmp traffics v6"
                ip6tables -A INPUT -p icmp -j DROP
fi



#drop policy
echo "change input policy to DROP v4"
        iptables -P INPUT DROP
echo "change output policy to DROP v4"
        iptables -P OUTPUT DROP

echo "change input policy to DROP v6"
        ip6tables -P INPUT DROP
echo "change output policy to DROP v4"
        ip6tables -P OUTPUT DROP
