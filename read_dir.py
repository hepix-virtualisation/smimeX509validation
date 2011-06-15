#!/bin/env python
import os
from M2Crypto import SMIME, X509

def cert_loader(filename):
    x509c = X509.load_cert(filename)
    fred = str(x509c.get_subject())
    print "---%s--%s" % (fred.strip(),filename)
    


directory = "/etc/grid-security/certificates/"

for filename in os.listdir(directory):
    fullpath = os.path.join(directory,filename)
    splitname = filename.split('.')
    
    if splitname[1] == '0':
        cert_loader(fullpath)
     
