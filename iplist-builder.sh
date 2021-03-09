#!/usr/bin/env bash

WHITELIST_URL="http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
DOWNLOAD_PATH="/tmp/iplist.txt"
OUTPUT_PATH="/tmp/iplist_out.txt"

if [ $# == 2 ]; then
  OUTPUT_PATH=$1
fi

if ! hash wget > /dev/null 2>&1;
then
  echo "Command wget not found, try curl."
  if ! hash curl > /dev/null 2>&1;
  then
    echo "Command curl not found, ABORT".
    exit 1
  fi
  curl -o $DOWNLOAD_PATH $WHITELIST_URL
else
  wget -O $DOWNLOAD_PATH $WHITELIST_URL
fi

if [ "$?" != "0" ]; then
  echo "Download failure, ABORT"
  exit 1
fi

echo "Download finish, parse download file..."

cat $DOWNLOAD_PATH | while read -r line
do
  if [[ $line == \#* ]];
  then
    continue
  fi

  IFS='|' read -ra array <<< "$line"

  if [ "${array[1]}" != "CN" ]; then
    continue
  fi

  if [ "${array[2]}" != "ipv4" ]; then
    continue
  fi

  network="${array[3]}"
  netmask="${array[4]}"

  cnt=0 var=$((netmask-1))
  while [ "$var" -gt 0 ]; do
    : $((cnt+=var&1, var>>=1))
  done

  echo "${network}/$((32-cnt))" >> $OUTPUT_PATH

done

echo "Parse download file complete, output file: $OUTPUT_PATH"