The aim of this code is to authenticate SMIME signed messages, loading CRL's and CA details
following the Trust Anchor Distribution trust anchor system.

Contributors.
~~~~~~~~~~~~~

Below is a list of contributors. If you help in this project please add your
name.

Owen Synge : owen.synge@desy.de

Comments and feedback:

David Groep : davidg@nikhef.nl

Functions
~~~~~~~~~

This library is intended to work with trust anchors and certificate revocation lists (CRL)
and signing policies. The library does not retrive CRL's it is recomended that other tools
such as fetch-crl (https://dist.eugridpma.info/distribution/util/) to update your CRL's.

How to verify.
~~~~~~~~~~~~~~

To get the DN and CA of your signature.

openssl smime -in your_signed.msg \
 -pk7out | openssl pkcs7 -print_certs

To Verify the message against the CA certificate.

openssl smime -in your_signed.msg \
 -CAfile /etc/grid-security/certificates/dd4b34ea.0 \
 -verify 1> /dev/null


Whats developed.
~~~~~~~~~~~~~~~~

loadcanamespace.py is a simeple library developed to automate and
simplify the authentication of signed messages.

Thier is a small demo application for checking one or more signed
messages.

# python message_signed_validation.py -h
Usage: message_signed_validation.py [options]

Options:
  -h, --help            show this help message and exit
  -m MESSAGE, --message=MESSAGE
                        adds a message to be tested.
  -c CERTS_DIR, --certs-dir=CERTS_DIR
                        Path of certificates dir

Dependancies
~~~~~~~~~~~~

apt-get install python-m2crypto
apt-get install python-setuptools
