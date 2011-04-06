import os.path
import shlex
import re
from M2Crypto import SMIME, X509
import time
import datetime
import logging, logging.config

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
           
def parse_crl_date(date_string):
    #
    splitdata = date_string.split(' ')
    date_list = []
    for item in splitdata:
        stripeditem = item.strip()
        if len(stripeditem) > 0:
            date_list.append(stripeditem)
    months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
    month_no = months.index(str(date_list[0])) +1
    timelist = date_list[2].split(':')
    return datetime.datetime(int(date_list[3]),month_no,int(date_list[1]),
        int(timelist[0]),int(timelist[1]),int(timelist[2]))

class CANamespacePermited:
    def __init__(self,issuer_dn):
        self.issuer_dn = issuer_dn
        self.namespaces = []
        self.namespaces_compiled = []
        self.crl = set([])
        self.crl_created = datetime.datetime.now()
        self.crl_expires = self.crl_created
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
        now = datetime.datetime.now()
        if now >= self.crl_expires:
            return False    
        if now <= self.crl_created:
            return False
        if int(serial_number) in self.crl:
            return False
        return True
            
        
        
class CANamespaces:
    def __init__(self):
        self.ca = {}
        self.logger = logging.getLogger("SmimeX509Validation.CANamespaces")
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
    def load_ca_cert(self,filename):
        x509c = X509.load_cert(filename)
        # First check thsi is a CA cert
        if 0 == x509c.check_ca():
            # Its not a CA
            self.logger.warning("Not a valid CA:%s" % (filename))
            return
        # Only process CA's with a namespace
        subject = str(x509c.get_subject())
        if not subject in self.ca.keys():
            return
        self.ca[subject].set_ca_filename(filename)
        self.ca[subject].set_ca_x509(x509c)
        
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
        now = datetime.datetime.now()
        if now <= crl_update_created or now >= crl_update_expires:
            return False
        if not Issuer in self.ca.keys():
            self.logger.warning("CRL for Issuer does not exist:%s:%s" % (filename,Issuer))
            return False
        self.ca[Issuer].crl = revokationlist
        self.ca[Issuer].crl_created = crl_update_created
        self.ca[Issuer].crl_expires = crl_update_expires
        #print Issuer
        #print crl_update_created
        
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
    
        
        
            
class TrustAnchor:
    def __init__(self):
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
    def validate_file(self,filename):
        if not os.path.isfile(filename):
            # raise the IOError so we don't dump in the M2Crypto c library
            raise IOError('can not open ' + filename)
        sk = X509.X509_Stack()
        p7, data = SMIME.smime_load_pkcs7(filename)
        supplied_stack =  p7.get0_signers(sk)
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
        if len(supplied_list) > 1:
            # We do not support proxy chains here.
            raise SmimeX509ValidationError("Library does not yet support long chains of trust")
        for item in supplied_list:
            issuer_dn = str(item.get_issuer())
            signer_dn = str(item.get_subject())
            
            # Only validate files signed with a certificate issued a correct CA
            correct_issuer_dn = self.ca_name_spaces.with_dn_get_ca(signer_dn)
            if issuer_dn != correct_issuer_dn:
                raise SmimeX509ValidationError("Signers DN issued by incorrect CA.")
            # Now we need to check the serial number
            signer_serial_number = item.get_serial_number()
            if not self.ca_name_spaces.ca[correct_issuer_dn].check_crl(signer_serial_number):
                raise SmimeX509ValidationError("Signers cert is revoked.")
        s = SMIME.SMIME()
        sk = X509.X509_Stack()
        
        sk.push(self.ca_name_spaces.ca[correct_issuer_dn].x509)
        s.set_x509_stack(sk)
        st = X509.X509_Store()
        #print self.ca_name_spaces.ca[correct_issuer_dn].ca_filename
        st.load_info(str(self.ca_name_spaces.ca[correct_issuer_dn].ca_filename))
        s.set_x509_store(st)
        try:
            v = s.verify(p7,data)
        except SMIME.PKCS7_Error as e:
            raise SmimeX509ValidationError(e)
            
        output = {
            'signer_dn' : signer_dn,
            'issuer_dn' : issuer_dn,
            'data' : data.read()
        }
        return output


