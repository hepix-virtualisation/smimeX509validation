#!/bin/sh

for i in 'cernvm.list' 'andrea.list' 'eduk.list' 'ian.list'
do
openssl smime -in ${i}  -CApath /etc/grid-security/certificates/ -verify 1 > /dev/null 
done

for i in 'cernvm.list' 'andrea.list' 'eduk.list' 'ian.list'
do
./message_signed_validation.py -m  ${i}
echo worked=$?
done
