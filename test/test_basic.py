import sys, os
sys.path = [os.path.abspath(os.path.dirname(os.path.dirname(__file__)))] + sys.path
import logging
import smimeX509validation
import unittest
import nose

class TestBasic(unittest.TestCase):
    def setUp(self):
        self.log = logging.getLogger("TestBasic")
        self.x509anchor = "/etc/grid-security/certificates/"
    def tearDown(self):
        pass
        
    def test_one(self):
        anchor =  smimeX509validation.LoadDirChainOfTrust(self.x509anchor)
        #smimeProcessor =  smimeX509validation.smimeX509validation(anchor)
        #print dir(smimeProcessor)
        #smimeProcessor.ProcessFile(item)
        #self.log.info(smimeProcessor.InputCertMetaDataList)
        #self.log.info(smimeProcessor.verified)
        #self.log.info(smimeProcessor.InputDaraStringIO.getvalue())

if __name__ == "__main__":
    logging.basicConfig()
    LoggingLevel = logging.DEBUG
    logging.basicConfig(level=LoggingLevel)
    log = logging.getLogger("main")
    nose.runmodule()

