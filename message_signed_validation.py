#!/bin/env python
import optparse
from smimeX509validation import ViewTrustAnchor
from smimeX509validation import *
#from smimeX509validation.loadcanamespace import ViewTrustAnchor

def main():
    p = optparse.OptionParser()
    p.add_option('-m', '--message', action ='append', 
        help='adds a message to be tested.')
    p.add_option('-c', '--certs-dir', action ='store', 
        help='Path of certificates dir',
        default='/etc/grid-security/certificates/')
    options, arguments = p.parse_args()
    anchor =  ViewTrustAnchor()
    anchor.update_ca_list(options.certs_dir)
    for item in options.message:
        anchor.validate_file(item)
       
if __name__ == "__main__":
    main()
