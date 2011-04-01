# The putpose of this code is to serve as example
# not to do anthing useful for the library

from M2Crypto import SMIME, X509


# Instantiate an SMIME object.
sk = X509.X509_Stack()
# Load the data, verify it.
p7, data = SMIME.smime_load_pkcs7('bill')
stack =  p7.get0_signers(sk)

looping = True
while looping:
    one = stack.pop()
    if one == None:
        break
    print one.get_subject()
    print one.get_serial_number()
    print one.get_issuer()


crl = X509.load_crl('/etc/grid-security/certificates/dd4b34ea.r0')

print crl.as_text()
#print crl.crl.own()

s = SMIME.SMIME()

x509c = X509.load_cert('/etc/grid-security/certificates/dd4b34ea.0')
sk = X509.X509_Stack()
sk.push(x509c)
s.set_x509_stack(sk)

# Load the signer's CA cert. In this case, because the signer's
# cert is self-signed, it is the signer's cert itself.
st = X509.X509_Store()
st.load_info('/etc/grid-security/certificates/dd4b34ea.0')
#st.load_info('usercert.pem')
s.set_x509_store(st)
p7, data = SMIME.smime_load_pkcs7('bill')
v = s.verify(p7,data)
print v
