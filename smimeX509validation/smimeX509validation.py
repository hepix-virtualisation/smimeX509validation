import os.path
import shlex
import re
from M2Crypto import SMIME, X509, BIO
import time
import datetime
import logging, logging.config
import truststore
class NullHandler(logging.Handler):
    def emit(self, record):
        pass

h = NullHandler()
logging.getLogger("SmimeX509Validation").addHandler(h)


class smimeX509ValidationError(Exception):
       def __init__(self, value):
           self.parameter = value
       def __str__(self):
           return repr(self.parameter)

class TrustStore(object):
    def __init__(self, Time = None):
        if Time == None:
            Time = datetime.datetime.now()
        self.time = Time
    def setType(self, Metadata,TrustStoreType = "directoy"):
        pass
            
    def load_ca_namespace(self):
        pass
    def load_ca_signing_policy(self):
        pass
    def load_ca_cert(self):
        pass
    def load_ca_crl(self):
        pass
    def GerM2CryptoX509_Stack(self, subject, issuer, serial_number):
        return None
    def GetCertKeyBySubject(self, CertKeySubject):
        key = None
        return key

class smimeX509validation(object):

    def __init__(self,TrustStore):
        self.TrustStore = TrustStore
    
    
    def Process(inputString):
        buf = BIO.MemoryBuffer(inputString)
        sk = X509.X509_Stack()
        self.InputP7, Inputdata = SMIME.smime_load_pkcs7_bio(buf)
        try:
            M2CryptoX509Stack =  p7.get0_signers(sk)
        except AttributeError, e:
            if str(e) == "PKCS7 instance has no attribute 'get0_signers'":
                self.logger.error('m2crypto version 0.18 is the minimum supported, please upgrade.')
            raise e

        issuer_dn = None
        signer_dn = None
        signer_serial_number = None

        supplied_list = []
        while True:
            one = M2CryptoX509Stack.pop()

            if one == None:
                break
            else:
                supplied_list.append(one)

        certdictionary  = []
        for item in supplied_list:
            itemdictionary = {}
            issuer_dn = str(item.get_issuer())
            signer_dn = str(item.get_subject())
            cert_sn = str(item.get_serial_number())
            itemdictionary['subject'] = signer_dn
            itemdictionary['issuer'] = issuer_dn
            itemdictionary['serial_number'] = cert_sn

            certdictionary.append(itemdictionary)
        # Only validate files signed with a certificate issued a correct CA
        if not len(certdictionary) == 1:
            if len(certdictionary) > 1:
                raise SmimeX509ValidationError("To many keys in signature file.")
            if len(certdictionary) == 0:
                raise SmimeX509ValidationError("No keys found signature file.")

        baseCert = certdictionary[0]
        
        
        
        TrustStore.checkCrlHeirarchy(baseCert['subject'],baseCert['issuer'],baseCert['serial_number'])
       
        
        s = SMIME.SMIME()
        sk = X509.X509_Stack()
        TrustStoreM2CryptoX509_Stack = TrustStore.GerM2CryptoX509_Stack(self, baseCert)
        s.set_x509_stack()
        st = X509.X509_Store(TrustStoreM2CryptoX509_Stack)
        #print self.ca_name_spaces.ca[correct_issuer_dn].ca_filename
        for item in CaHeirarchy:
            foundKey = self.ca_name_spaces.GetKeyByDn(item)
            if foundKey == None:
                raise SmimeX509ValidationError("No trusted Key for '%s'" % (item))
            st.add_cert(foundKey)
        s.set_x509_store(st)
        try:
            v = s.verify(p7,data)
	#when python 2.6 is the min version of supported
	#change back to
	#except SMIME.PKCS7_Error as e:
        except SMIME.PKCS7_Error , e:
            raise SmimeX509ValidationError(e)

        output = {
            'signer_dn' : signer_dn,
            'issuer_dn' : issuer_dn,
            'data' : data.read()
        }
        return output

def LoadDirChainOfTrust(dirPath):
    DirTrustStore = TrustStore()
    for filename in os.listdir(dirPath):
        fullpath = os.path.join(dirPath,filename)
        if not os.path.isfile(fullpath):
            continue
        start,extention = os.path.splitext(filename)
        if extention == u'.namespaces':
            DirTrustStore.load_ca_namespace(fullpath)
        if extention == u'.signing_policy':
            DirTrustStore.load_ca_signing_policy(fullpath)
    for filename in os.listdir(directory):
        fullpath = os.path.join(directory,filename)
        if not os.path.isfile(fullpath):
            continue
        start,extention = os.path.splitext(filename)
        if extention in [u'.pem',u'.0']:
            DirTrustStore.load_ca_cert(fullpath)
        if extention == u'.r0':
            DirTrustStore.load_ca_crl(fullpath)
    return DirTrustStore


