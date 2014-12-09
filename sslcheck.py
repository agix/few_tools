import sys
import re
import time
from subprocess import Popen, PIPE

if len(sys.argv)!=3:
    print "Usage: %s <ip> <port>"
    sys.exit()

def print_result(string, ip, port, test):
    if test[0]:
        print "\033[37m%s:%s %s : \033[1;32m%s"%(ip, port, string, test[1])
    else:
        print "\033[37m%s:%s %s : \033[1;31m%s"%(ip, port, string, test[1])

def IS(version, ip, port):
    p = Popen(['openssl', 's_client', version, '-connect', '%s:%s'%(ip, port)], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    p.stdin.write('GET / HTTP/1.0\nHostname: %s\n\n'%ip)
    res = p.stdout.read()
    if 'no peer certificate available' in res:
        return False
    else:
        return True

def GETCERTIF(ip, port):
    p = Popen("openssl s_client -showcerts -connect %s:%s < /dev/null | openssl x509 -text"%(ip, port), shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)    
    res = p.stdout.read()
    return res


def isSSLv2(ip, port):
    t = IS('-ssl2', ip, port)
    if t:
        return (False, t)
    else:
        return (True, t)

def isSSLv3(ip, port):
    t = IS('-ssl3', ip, port)
    if t:
        return (False, t)
    else:
        return (True, t)

def isTLSv11(ip, port):
    t = IS('-tls1_1', ip, port)
    if t:
        return (True, t)
    else:
        return (False, t)

def isTLSv12(ip, port):
    t = IS('-tls1_2', ip, port)
    if t:
        return (True, t)
    else:
        return (False, t)

def supportSecureRenegotiation(ip, port):
    p = Popen(['openssl', 's_client', '-connect', '%s:%s'%(ip, port)], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    p.stdin.write('GET / HTTP/1.0\nHostname: %s\n\n'%ip)
    res = p.stdout.read()
    if 'Secure Renegotiation IS supported' in res:
        return (True,True)
    else:
        return (False,False)

def enabledClientInitiatedRenegotiation(ip, port):
    p = Popen("(echo -en 'HEAD / HTTP/1.0\\n' && sleep 1 && echo -en 'R\\n\\n') | openssl s_client -connect %s:%s"%(ip, port), shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    err = p.stderr.read()
    if 'RENEGOTIATING' in err and 'handshake failure' in err:
        return (True,False)
    else:
        return (False,True)

def weakPublicKeySize(ip, port):
    p = Popen(['openssl', 's_client', '-connect', '%s:%s'%(ip, port)], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    p.stdin.write('GET / HTTP/1.0\nHostname: %s\n\n'%ip)
    res = p.stdout.read()
    size = re.findall('Server public key is ([0-9]+) bit', res)[0]
    if int(size)<=1024:
        return (False, str(True)+' ('+size+' bits)')
    else:
        return (True, str(False)+' ('+size+' bits)')

def expire(ip, port):
    res = GETCERTIF(ip, port)
    notAfter = re.findall('Not After :(.+)',res)[0]
    return (True, notAfter)

def weakHashAlgorithm(ip, port):
    res = GETCERTIF(ip, port)
    algo = re.findall('Signature Algorithm: (.+)',res)[0]
    if 'sha1' in algo or 'md5' in algo:
        return (False, str(True)+' ('+algo+')')
    else:
        return (True, str(False)+' ('+algo+')')

def useCRL(ip, port):
    res = GETCERTIF(ip, port)
    if 'CRL Distribution Points' in res:
        return (True, True)
    else:
        return (False, False)

def enabledCipherSuites(ip, port, ciphers):
    p = Popen(['openssl', 's_client', '-cipher', ciphers, '-connect', '%s:%s'%(ip, port)], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    p.stdin.write('GET / HTTP/1.0\nHostname: %s\n\n'%ip)
    res = p.stdout.read()
    if 'Cipher is (NONE)' in res:
        return (True, False)
    else:
        return (False, True)

def CRIMEVulnerable(ip, port):
    p = Popen(['openssl', 's_client', '-connect', '%s:%s'%(ip, port)], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    p.stdin.write('GET / HTTP/1.0\nHostname: %s\n\n'%ip)
    res = p.stdout.read()
    if 'Compression: NONE' in res:
        return (True, False)
    else:
        return (False, True)

def CRIMESPDYVulnerable(ip, port):
    p = Popen(['openssl', 's_client', '-nextprotoneg', 'NULL', '-connect', '%s:%s'%(ip, port)], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    p.stdin.write('GET / HTTP/1.0\nHostname: %s\n\n'%ip)
    res = p.stdout.read()
    try:
        protocols = re.findall('Protocols advertised by server:(.+)',res)[0]
    except:
        protocols = ''
    if 'spdy' in protocols:
        return (False, True)
    else:
        return (True, False)

ip = sys.argv[1]
port = sys.argv[2]

print_result("SSLv2 compatible", ip, port, isSSLv2(ip, port))
print_result("SSLv3 compatible", ip, port, isSSLv3(ip, port))
print_result("TLSv1.1 compatible", ip, port, isTLSv11(ip, port))
print_result("TLSv1.2 compatible", ip, port, isTLSv12(ip, port))
print_result("Support secure renegotiation", ip, port, supportSecureRenegotiation(ip, port))
print_result("Client-initiate renegotiation", ip, port, enabledClientInitiatedRenegotiation(ip, port))
print_result("Weak public key size (<=1024)", ip, port, weakPublicKeySize(ip, port))
print_result("Expire on", ip, port, expire(ip, port))
print_result("Weak hash algorithm", ip, port, weakHashAlgorithm(ip, port))
print_result("Use Certificate Revocation List", ip, port, useCRL(ip, port))
print_result("Weak cipher suites", ip, port, enabledCipherSuites(ip, port, 'NULL,EXPORT,LOW'))
print_result("Enabled RC4", ip, port, enabledCipherSuites(ip, port, 'RC4'))
print_result("Crime vulnerable", ip, port, CRIMEVulnerable(ip, port))
print_result("Crime (SPDY) vulnerable", ip, port, CRIMESPDYVulnerable(ip, port))
