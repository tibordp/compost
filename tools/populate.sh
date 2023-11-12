#!/bin/bash
set -e

for i in $(ls ./tools/emails); do
  for j in $(ls ./tools/emails/$i); do
    echo "Sending email from $j to $i"
    /home/tibordp/junk/curl/build/src/curl -vk --ssl-reqd \
      --url 'smtp://127.0.0.1:1025' \
      --mail-from $j \
      --mail-rcpt $i \
      --upload-file ./tools/emails/$i/$j
  done
done

