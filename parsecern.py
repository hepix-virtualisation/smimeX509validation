# The putpose of this code is to serve as example
# not to do anthing useful for the library

from M2Crypto import SMIME, X509


# Instantiate an SMIME object.
sk = X509.X509_Stack()
# Load the data, verify it.
p7, data = SMIME.smime_load_pkcs7('cernvm.list')
stack =  p7.get0_signers(sk)

looping = True
while looping:
    one = stack.pop()
    if one == None:
        break
    print one.get_subject()
    print one.get_serial_number()
    print one.get_issuer()



s = SMIME.SMIME()

x509c = X509.load_cert('/etc/grid-security/certificates/d254cc30.0')
print dir(x509c)
sk = X509.X509_Stack()
sk.push(x509c)
s.set_x509_stack(sk)
print 'got here'
# Load the signer's CA cert. In this case, because the signer's
# cert is self-signed, it is the signer's cert itself.
st = X509.X509_Store()
st.load_info('/etc/grid-security/certificates/1d879c6c.0')
st.load_info('/etc/grid-security/certificates/d254cc30.0')
print 'got here'
#st.load_info('usercert.pem')
s.set_x509_store(st)
p7, data = SMIME.smime_load_pkcs7('cernvm.list')
v = s.verify(p7,data)
print v
