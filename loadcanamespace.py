import os.path
import shlex
import re
from M2Crypto import SMIME, X509

class trust_anchor:    
    def __init__(self):
        self.cas = []
    def contains_ca_by_dn(self,da_dn):
        ### Returns CA on success and None on failure ###
    
        pass
    def add_ca(self,da_dn):
        pass

class ca_namespace_permited:
    def __init__(self,issuer_dn):
        self.issuer_dn = issuer_dn
        self.namespaces = []
        self.namespaces_compiled = []
        
    def add_issue_regex(self,subject_re):
        if subject_re in self.namespaces:
            return
        self.namespaces_compiled.append(re.compile(subject_re))
        self.namespaces.append(subject_re)     
    def set_ca_filename(self,filename):
        self.ca_filename = filename
    def set_ca_x509(self,x509):
        self.x509 = x509
        
class ca_namespaces:
    def __init__(self):
        self.ca = {}
    def add_issuer_regex(self,issuer,regex):
        if issuer in self.ca.keys():
            self.ca[issuer].add_issue_regex(regex)
        else:
            new_namespace_ca = ca_namespace_permited(issuer)
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
            return
        section = 0
        
        regex_issuer = re.compile('        Issuer: ')
        regex_serial = re.compile('    Serial Number: ')
        
        regex_section_revoked = re.compile('Revoked Certificates:')
        
        Issuer = None
        
        for line in lines:
            if section == 0:
                if regex_issuer.match(line):
                    print line
                if regex_section_revoked.match(line):
                    print line
            if section == 1:
                
                pass
            if section == 2:
                pass
            
        
                
        
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
    
        
        
            
class view_trust_anchor:
    def __init__(self):
        pass
    def update_ca_list(self,anchor_of_trust,directory):
        ca_name_spaces = ca_namespaces()
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
        #print ca_name_spaces.ca.keys()
        print ca_name_spaces.with_dn_get_ca('/C=DE/O=GermanGrid/OU=DESY/CN=Owen Synge')
                
        

class controler_trust_anchor:
    def __init__(self):
        self.model = trust_anchor()
        self.view = view_trust_anchor()
    def update(self,directory):
        self.view.update_ca_list(self.model,directory)
        
        


if __name__ == "__main__":
    trust = controler_trust_anchor()
    trust.update(u'/etc/grid-security/certificates')
    
