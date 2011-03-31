#!/usr/bin/env python

from smimeX509validation.__version__ import version
try:
        from setuptools import setup, find_packages
except ImportError:
        from ez_setup import use_setuptools
        use_setuptools()
        from setuptools import setup, find_packages

# could be added below need owens aproval
# license = "'GPL3' or 'Apache 2'",
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
        'Topic :: Communications :: Email',
        'Topic :: Office/Business',
        'Topic :: Software Development :: Bug Tracking',
        ],
)
