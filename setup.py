#!/usr/bin/env python

from smimeX509validation.__version__ import version
from sys import version_info
if version_info < (2, 6):
	from distutils.core import setup
else:
    try:
        from setuptools import setup, find_packages
    except ImportError:
        from ez_setup import use_setuptools
        use_setuptools()
        from setuptools import setup, find_packages

setup(name='smimeX509validation',
    version = version,
    description = 'Utility for Verifying smime Message Signatures',
    long_description="""The aim of this code is to authenticate SMIME signed messages, loading CRL's and CA details
following the Trust Anchor Distribution trust anchor system. The library does not retrive
CRL's it is recomended that other tools such as fetch-crl to update your CRL's.""",
    author = 'Owen Synge',
    author_email = 'owen.synge@desy.de',
    license='Apache License (2.0)',
    install_requires=[
       "M2Crypto>=0.16",
        ],
    url = 'https://github.com/hepix-virtualisation/smimeX509validation',
    packages = ['smimeX509validation'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research'
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
        ],
    data_files=[('/usr/share/doc/smimeX509validation-%s' % (version),['README.md','ChangeLog','TODO','LICENSE']),
        ('/usr/share/doc/smimeX509validation-%s/examples' % (version),['outline_code.py','message_signed_validation.py'])]
    )
