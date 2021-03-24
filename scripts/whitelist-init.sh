#!/usr/bin/env bash

WHITELIST_URL="http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
DOWNLOAD_PATH="/tmp/iplist.txt"
OUTPUT_PATH="."

WHITELIST_FILE_NAME="whitelist.txt"
IPSET_FILE_NAME="ipset-build.sh"

IPSET_NAME="fs_whitelist"

if [ $# = 2 ]; then
  OUTPUT_PATH="$1"
fi

rm -f "$DOWNLOAD_PATH" "$OUTPUT_PATH/$WHITELIST_FILE_NAME" "$OUTPUT_PATH/$IPSET_FILE_NAME"

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

touch "$OUTPUT_PATH/$IPSET_FILE_NAME"
echo "#!/usr/bin/env bash" >> "$OUTPUT_PATH/$IPSET_FILE_NAME"
echo "ipset flush $IPSET_NAME" >> "$OUTPUT_PATH/$IPSET_FILE_NAME"
echo "ipset create $IPSET_NAME hash:net timeout 259200 hashsize 4096 maxelem 65535" >> "$OUTPUT_PATH/$IPSET_FILE_NAME"

while read -r line
do
  if [[ $line == \#* ]];
  then
    continue
  fi

  IFS='|'
  read -ra array <<< "$line"

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

  element="${network}/$((32-cnt))"

  echo "$element" >> "$OUTPUT_PATH/$WHITELIST_FILE_NAME"
  echo "ipset add $IPSET_NAME $element" >> "$OUTPUT_PATH/$IPSET_FILE_NAME"
done < "$DOWNLOAD_PATH"

chmod +x "$OUTPUT_PATH/$IPSET_FILE_NAME"
echo "Parse download file complete, output file: $OUTPUT_PATH/$WHITELIST_FILE_NAME $OUTPUT_PATH/$IPSET_FILE_NAME"