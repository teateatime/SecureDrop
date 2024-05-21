import ECDH
import encryption
from tinyec import registry, ec
from random import randrange
import FileCredibility
import HashPasswords
import CertificateAuthority
import cryptography

def decrypt_incoming_file(file_name, encoding, one_time_private_key, sal=b'\xdd:\x12\xb3b\xab&\xa6\xaat\xbfM\xc2G\xc7@P\xd3\xba,>\xd5\x91\x06N\xf4\xfe\x0c\xccf\\xbb') -> bool:
    ca_response, file = certificate_authority.Authenticate('s.pub')
    if not ca_response:
        raise cryptography.exceptions.InvalidSignature()

    status = True
    sym_key = ECDH.compress(
        ECDH.getShairKey(
            one_time_private_key,
            readPublicKey(file)
        )
    )
    url_safe_sym_key = HashPasswords.calcMaster(sym_key, sal, b'', 'sym')
    FileCredibility.fullStop(file_name + encoding)
    with open(file_name + encoding, 'rb') as fout:
        enc_byte_file = fout.read()
    byte_file = encryption.decrypt_bytes(enc_byte_file, url_safe_sym_key)
    try:
        with open(file_name + encoding, 'wb') as fin:
            fin.write(byte_file)
    except:
        status = False
    FileCredibility.updateFiles([file_name + encoding])
    return status

def new_Pri_Pub(seed):
    CurrentCurve = ECDH.getCurve(randrange(seed))
    pri_key = ECDH.getPri(CurrentCurve)
    pub_key = ECDH.getPub(pri_key, CurrentCurve)
    return pri_key, pub_key

def formatKey(pub_key):
    return "[" + pub_key.curve.name + ',' + str(pub_key.x) + ',' + str(pub_key.y) + "]"

def gen_receiver_key_file():
    PriPubPair = new_Pri_Pub(99999999)
    pri_key = PriPubPair[0]
    pub_key = PriPubPair[1]
    with open('r.pub', 'w') as write:
        write.write(formatKey(pub_key))
    FileCredibility.updateFiles(['r.pub'])
    response, _ = certificate_authority.requestSignature('r.pub')
    if not response:
        return -1
    return pri_key

def readPublicKey(init_file):
    FileCredibility.fullStop(init_file)
    with open(init_file, 'r') as out:
        content = out.readline().replace('[', '').replace(']', '').split(',')
    return ec.Point(registry.get_curve(content[0]), int(content[1]), int(content[2]))

def gen_sender_key_file():
    ca_response, file = certificate_authority.requestSignature('r.pub')
    if not ca_response:
        raise cryptography.exceptions.InvalidSignature()

    external_public_key = readPublicKey(file)
    pri_key = ECDH.getPri(external_public_key.curve)
    pub_key = ECDH.getPub(pri_key, external_public_key.curve)

    with open('s.pub', 'w') as write:
        write.write(formatKey(pub_key))
    FileCredibility.updateFiles(['s.pub'])

    response, _ = certificate_authority.requestSignature('s.pub')
    if not response:
        return -1

    return ECDH.compress(pri_key * external_public_key)

def gen_send_file(b64_sym_key, file_name, encoding, sal=b'\xdd:\x12\xb3b\xab&\xa6\xaat\xbfM\xc2G\xc7@P\xd3\xba,>\xd5\x91\x06N\xf4\xfe\x0c\xccf\\xbb'):
    url_safe_key = HashPasswords.calcMaster(b64_sym_key, sal, b'', 'sym')
    return encryption.encrypt_symmetric(url_safe_key, file_name + encoding, file_name + '.zok')

def getSymKey(pub_file, pri):
    pub = readPublicKey(pub_file)
    return ECDH.compress(ECDH.getShairKey(pub, pri))
