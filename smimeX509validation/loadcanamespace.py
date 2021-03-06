import os.path
import shlex
import re
from M2Crypto import SMIME, X509, BIO
import time
import datetime
import logging, logging.config
from crl_utils import parse_crl_date

class NullHandler(logging.Handler):
    def emit(self, record):
        pass

h = NullHandler()
logging.getLogger("SmimeX509Validation").addHandler(h)

class SmimeX509ValidationError(Exception):
       def __init__(self, value):
           self.parameter = value
       def __str__(self):
           return repr(self.parameter)

def parse_ca_signing_policy_namespaces(namespaces):
    if len(namespaces) < 2:
        return []
    deleimeter = None
    if namespaces[0] in ['"',"'"]:
        deleimeter = namespaces[0]
    if deleimeter == None:
        return [namespaces]
    output = []
    for split in namespaces.split(deleimeter):
        cleanedsplit = split.strip()
        if len(cleanedsplit) > 0:
            output.append(cleanedsplit)
    return output

class CANamespacePermited:
    def __init__(self,issuer_dn):
        self.logger = logging.getLogger("SmimeX509Validation.loadcanamespace.CANamespacePermited")
        self.issuer_dn = issuer_dn
        self.namespaces = []
        self.namespaces_compiled = []
        self.crl = None
        self.crl_created = None
        self.crl_expires = None
    def add_issue_regex(self,subject_re):
        if subject_re in self.namespaces:
            return
        self.namespaces_compiled.append(re.compile(subject_re))
        self.namespaces.append(subject_re)
    def set_ca_filename(self,filename):
        self.ca_filename = filename
    def set_ca_x509(self,x509):
        self.x509 = x509
    def check_crl(self,serial_number):
        now = datetime.datetime.utcnow()
        if self.crl_expires == None:
            self.logger.error("Failed to parse CRL expiry date for issuer %s." % self.issuer_dn)
        else:
            if now >= self.crl_expires:
                self.logger.error("'%s' CRL has expired on '%s'." % (self.issuer_dn,self.crl_expires))
                return False
        if self.crl_created == None:
            self.logger.error("Failed to parse CRL creation date for issuer %s." % self.issuer_dn)
        else:
            if now <= self.crl_created:
                self.logger.error("CRL is created in the future %s." % self.issuer_dn)
                return False
        if self.crl == None:
            self.logger.error("CRL list unpassed %s." % self.issuer_dn)
            return False
        if int(serial_number) in self.crl:
            self.logger.error("CRL revokes %s." % serial_number)
            return False
        return True



class CANamespaces:
    def __init__(self):
        self.ca = {}
        self.logger = logging.getLogger("SmimeX509Validation.loadcanamespace.CANamespaces")
    def add_issuer_regex(self,issuer,regex):
        if issuer in self.ca.keys():
            self.ca[issuer].add_issue_regex(regex)
        else:
            new_namespace_ca = CANamespacePermited(issuer)
            new_namespace_ca.add_issue_regex(regex)
            self.ca[issuer] = new_namespace_ca

    def load_ca_namespace(self,filename):
        resolvedlines = []
        fp = open(filename)
        currentline = ''
        for line in fp.readlines():
            thisline = line.rstrip()
            if "\\" == thisline[-1:]:
                currentline = thisline[:-1]
            else:
                currentline += thisline
                resolvedlines.append(currentline)
                currentline = ''
        if len(currentline) > 0:
            resolvedlines.append(currentline)
        lexed_lines = []
        for line in resolvedlines:
            lexer = shlex.shlex(line, posix=True)
            toxenised = []
            for token in lexer:
                stripedtoken = token.strip()
                toxenised.append(stripedtoken)
            if len(toxenised) > 0:
                lexed_lines.append(toxenised)

        for line in lexed_lines:
            if line[0] == 'TO' and line[1] == 'Issuer' and line[3] == 'PERMIT' and line[4] == 'Subject':
                self.add_issuer_regex(line[2],line[5])

    def load_ca_signing_policy(self,filename):
        #print filename
        fp = open(filename)
        currentline = ''
        access_id_CA = None
        cond_subjects = None
        for line in fp.readlines():
            lexer = shlex.shlex(line, posix=True)
            toxenised = []
            for token in lexer:
                stripedtoken = token.strip()
                toxenised.append(stripedtoken)
            if len(toxenised) == 3:
                if toxenised[0] == 'access_id_CA':
                    access_id_CA = str(toxenised[2])
                if toxenised[0] == 'cond_subjects':
                    cond_subjects = parse_ca_signing_policy_namespaces(str(toxenised[2]))
        #print '%s][%s=B=%s' % (access_id_CA,cond_subjects,filename)
        if access_id_CA != None:
            for matcher in cond_subjects:
                regex = matcher.replace('*','.*')
                self.add_issuer_regex(access_id_CA,regex)


        #print access_id_CA,cond_subjects



    def load_ca_cert(self,filename):
        try:
            x509c = X509.load_cert(filename)
        except X509.X509Error as instance:
            self.logger.error("Failed to load CA cert '%s'" % (filename))
            return

        # First check thsi is a CA cert
        if 0 == x509c.check_ca():
            # Its not a CA
            self.logger.warning("Not a valid CA:%s" % (filename))
            return
        # Only process CA's with a namespace
        subject = str(x509c.get_subject())
        if not subject in self.ca.keys():
            return
        issuer = str(x509c.get_issuer())
        serial_number = str(x509c.get_serial_number())
        self.ca[subject].set_ca_filename(filename)
        self.ca[subject].set_ca_x509(x509c)
        self.ca[subject].issuer = issuer
        self.ca[subject].serial = serial_number
    def load_ca_crl(self,filename):
        crltext = str(X509.load_crl(filename).as_text())
        lines = crltext.split('\n')
        if 'Certificate Revocation List (CRL):' != lines[0]:
            return False
        section = 0

        regex_issuer = re.compile('        Issuer: ')
        regex_crl_created = re.compile('        Last Update: ')
        regex_crl_expires = re.compile('        Next Update: ')


        regex_serial = re.compile('    Serial Number: ')
        #regex_revoke_date = re.compile('        Revocation Date:')

        regex_section_revoked = re.compile('Revoked Certificates:')
        regex_section_revoked2 = re.compile('No Revoked Certificates.')
        regex_section_signature = re.compile('    Signature Algorithm: ')

        Issuer = None
        crl_update_created = None
        crl_update_expires = None
        revokationlist = set([])
        for line in lines:
            if section == 0:
                match_issuer = regex_issuer.match(line)
                if match_issuer:
                    Issuer = line[match_issuer.end():].strip()
                    continue
                match_crl_created = regex_crl_created.match(line)
                if match_crl_created:
                    crl_update_created = parse_crl_date(line[match_crl_created.end():].strip())
                    continue
                match_crl_expires = regex_crl_expires.match(line)
                if match_crl_expires:
                    crl_update_expires = parse_crl_date(line[match_crl_expires.end():].strip())
                    continue
                if regex_section_revoked.match(line) or regex_section_revoked2.match(line):
                    section = 1
                    continue
                #print line
            if section == 1:
                match_serial = regex_serial.match(line)
                if match_serial:
                    serial_num_string =  int(line[match_serial.end():].strip(),16)
                    revokationlist.add(serial_num_string)
                #match_revokedate = regex_revoke_date.match(line)
                #if match_revokedate:
                #    testerdate =  parse_crl_date(line[match_revokedate.end():].strip())
                #    if testerdate == None:
                #        print 'sdfsdf%s' % (line[match_revokedate.end():].strip())
                #    print testerdate.strftime("%b %d %H:%M:%S %Y GMT")
                if regex_section_signature.match(line):
                    section = 2
                    continue
                #print line
            if section == 2:
                continue
        if None == Issuer:
            self.logger.warning("CRL Issuer not found:%s" % (filename))
            return False
        if not Issuer in self.ca.keys():
            self.logger.debug("Namespace for Issuer '%s' does not exist:%s" % (Issuer,filename))
            return False
        self.ca[Issuer].crl = revokationlist
        self.ca[Issuer].crl_created = crl_update_created
        self.ca[Issuer].crl_expires = crl_update_expires
        if None == crl_update_created:
            self.logger.warning("CRL creation date not found:%s:%s" % (filename,Issuer))
            return False
        if None == crl_update_expires:
            self.logger.warning("CRL expiry date not found:%s:%s" % (filename,Issuer))
            return False
        now = datetime.datetime.utcnow()
        if now <= crl_update_created:
            self.logger.debug("CRL created in the future :%s:%s" % (filename,Issuer))
            return False
        if now >= crl_update_expires:
            self.logger.info("at %s the CRL expired:%s:%s" % (crl_update_expires,filename,Issuer))
            return False
        return True


    def with_dn_get_ca(self,dn):
        outputlist = []
        for cakey in self.ca.keys():
            for regex in self.ca[cakey].namespaces_compiled:
                if None != regex.match(dn):
                    outputlist.append(cakey)
        number_of_matches = len(outputlist)
        if number_of_matches > 1:
            raise Matches_more_than_one_ca
        if len(outputlist) == 0:
            return None
        return outputlist[0]

    def GetCaHeirarchListWithCaDn(self,dn):
        known = set(self.ca.keys())
        outputlist = []
        inputlist = [dn]
        while len(inputlist) > 0:
            item = inputlist.pop()
            outputlist.append(item)
            issuer = self.ca[item].issuer
            if issuer == item:
                break
            inputlist.append(self.ca[item].issuer)
        return outputlist


    def GetListCaWithSignerDn(self,dn):
        outputlist = []
        for cakey in self.ca.keys():
            for regex in self.ca[cakey].namespaces_compiled:
                if None != regex.match(dn):
                    outputlist.append(cakey)
        return outputlist

    def GetKeyByDn(self,Dn):
        # Takes a list of DN's and checks
        # they are orded correctly
        if not Dn in self.ca:
            return None
        return self.ca[Dn].x509

    def checkCrlHeirarchy(self,subject,issuer,serialno):
        possibleIssuers = self.GetListCaWithSignerDn(subject)
        if not issuer in possibleIssuers:
            raise SmimeX509ValidationError("Signers DN issued by unaproved CA.")
        CaHeirarchList = self.GetCaHeirarchListWithCaDn(issuer)
        current_Sn = serialno
        for item in CaHeirarchList:
            if not self.ca[issuer].check_crl(current_Sn):
                self.logger.info("'%s' CRL check with serial number '%s' failed shows '%s' is revoked." % (issuer,serialno,subject))
                return False
            current_Sn = self.ca[issuer].serial
        return True





class TrustAnchor:
    def __init__(self):
        self.logger = logging.getLogger("SmimeX509Validation.loadcanamespace.TrustAnchor")
        self.ca_name_spaces = CANamespaces()
    def update_ca_list(self,directory):
        ca_name_spaces = CANamespaces()
        for filename in os.listdir(directory):
            fullpath = os.path.join(directory,filename)
            if not os.path.isfile(fullpath):
                continue
            start,extention = os.path.splitext(filename)
            if extention == u'.namespaces':
                ca_name_spaces.load_ca_namespace(fullpath)
            if extention == u'.signing_policy':
                ca_name_spaces.load_ca_signing_policy(fullpath)
        for filename in os.listdir(directory):
            fullpath = os.path.join(directory,filename)
            if not os.path.isfile(fullpath):
                continue
            start,extention = os.path.splitext(filename)
            if extention in [u'.pem',u'.0']:
                ca_name_spaces.load_ca_cert(fullpath)
            if extention == u'.r0':
                ca_name_spaces.load_ca_crl(fullpath)
        self.ca_name_spaces = ca_name_spaces
    def validate_text(self,text_to_verify):
        buf = BIO.MemoryBuffer(text_to_verify)
        sk = X509.X509_Stack()
        p7, data = SMIME.smime_load_pkcs7_bio(buf)
        try:
            supplied_stack =  p7.get0_signers(sk)
        except AttributeError as e:
            if str(e) == "PKCS7 instance has no attribute 'get0_signers'":
                self.logger.error('m2crypto version 0.18 is the minimum supported, please upgrade.')
            raise e

        issuer_dn = None
        signer_dn = None
        signer_serial_number = None

        supplied_list = []
        while True:
            one = supplied_stack.pop()

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
        if not self.ca_name_spaces.checkCrlHeirarchy(baseCert['subject'],baseCert['issuer'],baseCert['serial_number']):
            raise SmimeX509ValidationError("Cert %s is expired")
        CaHeirarchy = self.ca_name_spaces.GetCaHeirarchListWithCaDn(baseCert['issuer'])
        s = SMIME.SMIME()
        sk = X509.X509_Stack()
        for item in CaHeirarchy:
            foundKey = self.ca_name_spaces.GetKeyByDn(item)
            if foundKey == None:
                raise SmimeX509ValidationError("No trusted Key for '%s'" % (item))
            sk.push(foundKey)
        s.set_x509_stack(sk)
        st = X509.X509_Store()
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
        except SMIME.PKCS7_Error as e:
            raise SmimeX509ValidationError(e)

        output = {
            'signer_dn' : signer_dn,
            'issuer_dn' : issuer_dn,
            'data' : data.read()
        }
        return output

    def validate_file(self,filename):
        if not os.path.isfile(filename):
            # raise the IOError so we don't dump in the M2Crypto c library
            raise IOError('can not open ' + filename)
        return self.validate_text(open(filename).read())



