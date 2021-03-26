#!/usr/bin/env bash

enable_tcp() {
  if [ $# -ne 2 ]; then
    exit 1
  fi

  echo "Configure iptables (TCP Transparent proxy)"

  iptables -t nat -N FLYINGSOCKS

  iptables -t nat -A FLYINGSOCKS -d "$1" -j RETURN

  iptables -t nat -A FLYINGSOCKS -d 0.0.0.0/8 -j RETURN
  iptables -t nat -A FLYINGSOCKS -d 10.0.0.0/8 -j RETURN
  iptables -t nat -A FLYINGSOCKS -d 127.0.0.0/8 -j RETURN
  iptables -t nat -A FLYINGSOCKS -d 169.254.0.0/16 -j RETURN
  iptables -t nat -A FLYINGSOCKS -d 172.16.0.0/12 -j RETURN
  iptables -t nat -A FLYINGSOCKS -d 192.168.0.0/16 -j RETURN
  iptables -t nat -A FLYINGSOCKS -d 224.0.0.0/4 -j RETURN
  iptables -t nat -A FLYINGSOCKS -d 240.0.0.0/4 -j RETURN
  iptables -t nat -A FLYINGSOCKS -m set --match-set fs_whitelist dst -j RETURN

  iptables -t nat -A FLYINGSOCKS -p tcp -j REDIRECT --to-ports $2

  iptables -t nat -A PREROUTING -p tcp -j FLYINGSOCKS
}

iptables_backup() {
  iptables-save > iptables.bak
}

fs_pid=$(pidof fscli)
if [ -n "$fs_pid" ]; then
  echo "Program has been start."
  exit 1
fi

if [ -z "$SERVER_ADDRESS" ]; then
  echo "Not setup proxy server ip address environment variable SERVER_ADDRESS, ABORT"
  exit 1
fi

echo "Startup flyingsocks client..."
nohup ./fscli > /dev/null 2>&1& echo $! > /var/run/fscli.pid

sleep 3s
fs_pid=$(cat /var/run/fscli.pid)
if [ -z "$fs_pid" ]; then
  echo "Program startup failure"
  exit 1
fi

echo "flyingsocks client PID: $fs_pid"

if [ ! -f "./iptables.bak" ]; then
  iptables_backup
fi

if [ ! -f "./service.conf" ]; then
  echo "Service config file $0/service.conf not found"
  exit 1
fi

while read -r line
do
  if [ "${line:0:1}" == "#" ]; then
    continue
  fi
  line_parse=$(echo "$line" | sed 's/\-/_/g' | sed s/[[:space:]]//g)
  if [ "$line_parse" == "" ]; then
    continue
  fi
  eval "$line_parse"
done < "./service.conf"

# shellcheck disable=SC2154
if [ "$enable_tcp_proxy" == "true" ]; then
  enable_tcp "$SERVER_ADDRESS" "$proxy_tcp_port"
fi