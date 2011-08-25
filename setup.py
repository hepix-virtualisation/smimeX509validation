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
    author = 'Owen Synge',
    author_email = 'owen.synge@desy.de',
    install_requires=[
       "M2Crypto>=0.16",
        ],
    url = 'https://github.com/hepix-virtualisation/smimeX509validation',
    packages = ['smimeX509validation'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research'
        'Intended Audience :: Developers',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'License :: OSI Approved :: Apache 2.0',
        ],
    data_files=[('/usr/share/doc/smimeX509validation',['README','ChangeLog','TODO','LICENSE']),
        ('/usr/share/doc/smimeX509validation/examples',['outline_code.py','message_signed_validation.py'])]
    )
