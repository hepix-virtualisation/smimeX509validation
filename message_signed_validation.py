#!/usr/bin/env python
import optparse
import sys
from smimeX509validation import TrustAnchor
import logging, logging.config
import os.path
from smimeX509validation import TrustStore, LoadDirChainOfTrust

def main():
    p = optparse.OptionParser()
    p.add_option('-m', '--message', action ='append',
        help='adds a message to be tested.')
    p.add_option('-c', '--certs-dir', action ='store',
        help='Path of certificates dir',
        default='/etc/grid-security/certificates/')
    options, arguments = p.parse_args()
    if not os.path.isdir(options.certs_dir):
        print ("Warning not a directory:%s" % (options.certs_dir))
        sys.exit(1)
    anchor =  LoadDirChainOfTrust(options.certs_dir)
    if options.message == None:
        sys.exit(1)
    else:
        for item in options.message:
            print anchor.validate_file(item)
            smimeX509validation()

if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    main()
