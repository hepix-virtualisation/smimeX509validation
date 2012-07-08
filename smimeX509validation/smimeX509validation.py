import os.path
import shlex
import re
from M2Crypto import SMIME,  X509, BIO
import time
import datetime
import logging, logging.config
import truststore
import StringIO

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
    def __init__(self, Time = None,TrustStoreType = "directory",Metadata= {'dirCerts' : '/etc/grid-security/certificates/'}):
        if Time == None:
            Time = datetime.datetime.now()
        self.time = Time
        self.setMetadata  (Metadata)
        self.setType()
        self.update()
        
        
    def setType(self, TrustStoreType = "directory"):
        if TrustStoreType == "directory":
            self._TrustStore = truststore.TrustStore()
            self.setMetadata(self.Metadata)
        
    def setMetadata  (self, Metadata):
        self.Metadata = dict(Metadata)
        if hasattr(self, "_TrustStore"):
            self._TrustStore.setMetadata(Metadata)
    def update(self):
        if hasattr(self, "_TrustStore"):
            return self._TrustStore.update()
        return None
    def CheckCertificateRevocationList(self, InputCertMetaDataList):
        if hasattr(self, "_TrustStore"):
            return self._TrustStore.CheckCertificateRevocationList(InputCertMetaDataList)
        return None
    def GetM2CryptoX509_Stack(self, InputCertMetaDataList):
        if hasattr(self, "_TrustStore"):
            return self._TrustStore.GetM2CryptoX509_Stack(InputCertMetaDataList)
        return None
    def GetM2CryptoX509_Store(self, InputCertMetaDataList):
        if hasattr(self, "_TrustStore"):
            return self._TrustStore.GetM2CryptoX509_Store(InputCertMetaDataList)
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
        self.verified = False
        # Note we cast to a String type as unicode will not verify
        buf = BIO.MemoryBuffer(str(inputString))
        sk = X509.X509_Stack()
        try:
            InputP7, Inputdata = SMIME.smime_load_pkcs7_bio(buf)
        except SMIME.SMIME_Error , e:
            raise smimeX509ValidationError(e)
        self.InputDaraStringIO = StringIO.StringIO()
        self.InputDaraStringIO.write(Inputdata.read())
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

        InputCertMetaDataList  = []
        for item in supplied_list:
            itemdictionary = {}
            issuer_dn = str(item.get_issuer())
            signer_dn = str(item.get_subject())
            cert_sn = str(item.get_serial_number())
            itemdictionary['subject'] = signer_dn
            itemdictionary['issuer'] = issuer_dn
            itemdictionary['serial_number'] = cert_sn

            InputCertMetaDataList.append(itemdictionary)
        self.InputCertMetaDataList = InputCertMetaDataList
        # Only validate files signed with a certificate issued a correct CA
        if not len(InputCertMetaDataList) == 1:
            if len(InputCertMetaDataList) > 1:
                raise smimeX509ValidationError("To many keys in signature file.")
            if len(InputCertMetaDataList) == 0:
                raise smimeX509ValidationError("No keys found signature file.")
        
        if not self.TrustStore.CheckCertificateRevocationList(self.InputCertMetaDataList):
            raise smimeX509ValidationError("Cert %s is expired")
        
        baseCert = InputCertMetaDataList[0]
        
        
        #TrustStore.checkCrlHeirarchy(baseCert['subject'],baseCert['issuer'],baseCert['serial_number'])
       
        
        s = SMIME.SMIME()
        TrustStoreM2CryptoX509_Stack = self.TrustStore.GetM2CryptoX509_Stack(self.InputCertMetaDataList)
        if TrustStoreM2CryptoX509_Stack == None:
            raise smimeX509ValidationError("No Trusted Stack found.")
            
        TrustStoreM2CryptoX509_Store = self.TrustStore.GetM2CryptoX509_Store(self.InputCertMetaDataList)
        if TrustStoreM2CryptoX509_Store == None:
            raise smimeX509ValidationError("No Trusted Store found.")
        #print TrustStoreM2CryptoX509_Store
        s.set_x509_stack(TrustStoreM2CryptoX509_Stack)
        
        InputDaraBufffer = BIO.MemoryBuffer(self.InputDaraStringIO.getvalue())
        s.set_x509_store(TrustStoreM2CryptoX509_Store)
        try:
            v = s.verify(InputP7,InputDaraBufffer)
	    #when python 2.6 is the min version of supported
    	#change back to
	    #except SMIME.PKCS7_Error as e:
        except SMIME.PKCS7_Error , e:
            raise smimeX509ValidationError(e)
        self.verified = True
        output = {
            'SignerSubject' : signer_dn,
            'IssuerSubject' : issuer_dn,
            'Data' : self.InputDaraStringIO.getvalue()
        }
        return output

def LoadDirChainOfTrust(dirPath):
    DirTrustStore = TrustStore()
    DirTrustStore.setType("directory")
    
    Metadata= {'dirCerts' : dirPath}
    DirTrustStore.setMetadata(Metadata)
    DirTrustStore.update()
    return DirTrustStore


