import os.path

class certificate_autority:    
    def __init__(self):
        pass



class trust_anchor:    
    def __init__(self):
        self.cas = []



class view_trust_anchor:
    def __init__(self):
        pass
    def update_ca_list(self,anchor_of_trust,directory):
        extension_funct_map = {
            u'.0' : 'cert',
            u'.signing_policy' : 'signing_policy',
            u'.namespaces' : 'namespace',
            u'.crl_url' : 'crl_url',
            u'.pem' : 'cert',
            u'.r0' : 'crl',
            u'.info' : 'info',
        }
        filenames = {}
        forwardlinks = {}
        for filename in os.listdir(directory):
            fullpath = os.path.join(directory,filename)
            if os.path.islink(fullpath):
                
                linkedfilepath = os.path.realpath(fullpath)
                if str(directory) != str(os.path.dirname(linkedfilepath)):
                    print 'Warning symlink dows not match directory'
                    continue
                else:
                    linkedfile = os.path.basename(linkedfilepath)
                    linkedfilestart, linkedfileext = os.path.splitext(linkedfile)
                    start,extention = os.path.splitext(filename)
                    if not start in forwardlinks.keys():
                        forwardlinks[start] = linkedfilestart

        for filename in os.listdir(directory):
            fullpath = os.path.join(directory,filename)
            if not (os.path.islink(fullpath) or os.path.isfile(fullpath)):
                continue
            start,extention = os.path.splitext(filename)
            funct = extension_funct_map[extention]
            try:
                funct = extension_funct_map[extention]
            except:
                continue
            resolvedref = start
            if start in forwardlinks.keys():
                resolvedref = forwardlinks[start]
            details = {}
            if resolvedref in filenames.keys():
                details = filenames[resolvedref]
            details[funct] = fullpath
            filenames[resolvedref] = details
        cadetails = {}
        counter = 0
        for item in filenames.keys():
            #print item
            cacert = None
            if not 'cert' in filenames[item].keys():
                print 'xxxx%s' % filenames[item]
            
            if not 'info' in filenames[item].keys():
                print 'does not have info'
            if not 'signing_policy' in filenames[item].keys():
                print 'does not have signing_policy'
                print filenames[item]
            if not 'crl_url' in filenames[item].keys():
                print 'does not have crl_url'
                print filenames[item]
            if not 'info' in filenames[item].keys():
                print 'does not have info'
                print filenames[item]
            if not 'crl' in filenames[item].keys():
                print '%s does not have crl' % (item)
            counter += 1
            if not 'namespace' in filenames[item].keys():
                print '%s does not have namespace' % (item)
                #print filenames[item]
        print "sdfsdf=%s" % (counter)

                
        

class controler_trust_anchor:
    def __init__(self):
        self.model = trust_anchor()
        self.view = view_trust_anchor()
    def update(self,directory):
        self.view.update_ca_list(self.model,directory)
        
        


if __name__ == "__main__":
    trust = controler_trust_anchor()
    trust.update(u'/etc/grid-security/certificates')
    
