OverView
~~~~~~~~

This code reads Grid chain of trust directly to uniquely itentify a user based upon the certificxates subject. The flexability of this system allows easy cross institutional trust relationships.

An example Chain for trust is available as an example.

How smimeX509validation Works
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This assuming file a defining signing_policy of allowed DN's is followed, all certificate subjects may resolve to a unique chain of trust. smimeX509validation uses this to build its certifcate chain  Using this meachinism and agreed cerificate policies, 2 parties can have assurance of each others cross institute identity without exchanging more than public keys, which SMIME nicely embeds within messages.


Setup of a Grid Chain of Trust Directory.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Insert the x.509 certificates *.pem files. Vreate *.crl_url, *.signing_policy and your complete./

*.signing_policy and *.namespaces files is used by smimeX509validation to derive the certificate chain of trust from these namespaces. namespaces files have been superseeded by signing_policy files smimeX509validation reads both types independently.

It is recomended that this software is used in conjunction with fetch-crl. fetch-crl uses a crl url to download the crl for each CA.

fetch-crl gnereates *.r0 files, these are the crl for each certificate Authority referanced by a *.crl_url.

smimeX509validation parses these *.r0 certficate revocation lists for expired certificates.

Generating trustsrore r0 certificate revolation files.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Example use of the fetch-crl command

/usr/sbin/fetch-crl --infodir doc/examples/truststore/

For fetch-crl to work a name matchign file must exist with the crl's latest version url as the only content.

Trust store "signing_policy" files should oook like this:

    access_id_CA   X509   '/C=US/ST=UT/L=Salt Lake City/O=The USERTRUST Network/OU=http://www.usertrust.com/CN=UTN-USERFirst-Hardware'
    pos_rights     globus CA:sign
    cond_subjects  globus '"/C=NL/O=TERENA/*"'

Where "cond_subjects" strign value represents a filter of Subjects that are alowed access.

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
