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
    """The Trust Store is a Class Hiding the details of trusting Certification Authorities.
    It manages Certification Authoritie Namespaces, Certification Authorities, 
    and Certificate Revocation Lists. Downloading Certificate Revocation Lists is left 
    to fetch-crl or similar applications.
    This is a facard class to avoid complicating the Library API
    and because future implementations may be created"""
    def __init__(self, Time = None,TrustStoreType = "directoy",Metadata= {'dirCerts' : '/etc/grid-security/certificates/'}):
        if Time == None:
            Time = datetime.datetime.now()
        self.time = Time
        self.setMetadata  (Metadata)
        self.setType()
        
        
    def setType(self, TrustStoreType = "directoy"):
        if TrustStoreType == "directoy":
            self._TrustStore = truststore.TrustStore()
            self.setMetadata(self.Metadata)
        
    def setMetadata  (self, Metadata):
        self.Metadata = dict(Metadata)
        if hasattr(self, "_TrustStore"):
            self._TrustStore.setMetadata(Metadata)
    def update(self,filepath):
        if hasattr(self, "_TrustStore"):
            return self._TrustStore.update()
        return None
    def load_ca_signing_policy(self,filepath):
        if hasattr(self, "_TrustStore"):
            return self._TrustStore.load_ca_signing_policy(filepath)
        return None
    def load_ca_cert(self,filepath):
        if hasattr(self, "_TrustStore"):
            return self._TrustStore.load_ca_cert(filepath)
        return None
    def load_ca_crl(self,filepath):
        if hasattr(self, "_TrustStore"):
            return self._TrustStore.load_ca_crl(filepath)
        return None
    def load_ca_namespace(self,filepath):
        if hasattr(self, "_TrustStore"):
            return self._TrustStore.load_ca_namespace(filepath)
        return None
    def GerM2CryptoX509_Stack(self, subject, issuer, serial_number):
        if hasattr(self, "_TrustStore"):
            return self._TrustStore.GerM2CryptoX509_Stack(subject, issuer, serial_number)
        return None
    def GetCertKeyBySubject(self, CertKeySubject):
       if hasattr(self, "_TrustStore"):
            return self._TrustStore.GetCertKeyBySubject(CertKeySubject)
       return None

class smimeX509validation(object):

    def __init__(self,TrustStore):
        self.TrustStore = TrustStore
    
    def ProcessFile(self,inputString):
        if not os.path.isfile(inputString):
            # raise the IOError so we don't dump in the M2Crypto c library
            raise IOError('can not open ' + inputString)
        return self.Process(open(inputString).read())

    def Process(self,inputString):
        buf = BIO.MemoryBuffer(inputString)
        sk = X509.X509_Stack()
        InputP7, Inputdata = SMIME.smime_load_pkcs7_bio(buf)
        try:
            M2CryptoX509Stack =  InputP7.get0_signers(sk)
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
                raise smimeX509ValidationError("To many keys in signature file.")
            if len(certdictionary) == 0:
                raise smimeX509ValidationError("No keys found signature file.")

        baseCert = certdictionary[0]
        
        
        #TrustStore.checkCrlHeirarchy(baseCert['subject'],baseCert['issuer'],baseCert['serial_number'])
       
        
        s = SMIME.SMIME()
        sk = X509.X509_Stack()
        TrustStoreM2CryptoX509_Stack = self.TrustStore.GerM2CryptoX509_Stack(baseCert['subject'],baseCert['issuer'],baseCert['serial_number'])
        if TrustStoreM2CryptoX509_Stack == None:
            raise smimeX509ValidationError("No Trusted Stack found.")
        print TrustStoreM2CryptoX509_Stack
        s.set_x509_stack(TrustStoreM2CryptoX509_Stack)
        st = X509.X509_Store(TrustStoreM2CryptoX509_Stack)
        #print self.ca_name_spaces.ca[correct_issuer_dn].ca_filename
        
        s.set_x509_store(st)
        try:
            v = s.verify(InputP7,Inputdata)
	#when python 2.6 is the min version of supported
	#change back to
	#except SMIME.PKCS7_Error as e:
        except SMIME.PKCS7_Error , e:
            raise smimeX509ValidationError(e)

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
    for filename in os.listdir(dirPath):
        fullpath = os.path.join(dirPath,filename)
        if not os.path.isfile(fullpath):
            continue
        start,extention = os.path.splitext(filename)
        if extention in [u'.pem',u'.0']:
            DirTrustStore.load_ca_cert(fullpath)
        if extention == u'.r0':
            DirTrustStore.load_ca_crl(fullpath)
    return DirTrustStore


