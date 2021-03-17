from jwcrypto import jwk, jws, jwt, jwe
from jwcrypto.common import json_encode, json_decode
from cbor2 import dumps, loads
from cose import SymmetricKey, Enc0Message, CoseAlgorithms, KeyOps, CoseHeaderKeys
from itertools import zip_longest
import time


def group(n, iterable, fillvalue=None): 
    args = [iter(iterable)] * n
    return zip_longest(fillvalue=fillvalue, *args)

def dump_c_hex(data):
    return ', '.join([''.join(['0x', *x]) for x in group(2, data.hex())])


payload = {'bip': '172.31.0.3', 'exp': 1893456000, 'sid':520987254}

# payload={"id":2**24-1,"exp":int(time.time()),'nonce':2**64-1,'bip':2**32-1}

# payload = [2**32-1, int(time.time()), 2**32-1, 2**32-1]

print("Payload:%s" % payload)

jose_secret = jwk.JWK.generate(kty='oct',size=128)
header={'alg':'dir','enc':'A128GCM'}
jwetoken=jwe.JWE(json_encode(payload),json_encode(header))
jwetoken.add_recipient(jose_secret)
print("=========================================================")
print("JWE TOKEN : %s" % jwetoken.serialize(1).encode().hex())
print("JWE TOKEN with length:%d" % len(jwetoken.serialize(1).encode()))
print("=========================================================")



cose_secret = SymmetricKey.generate_key(key_len=16, algorithm=CoseAlgorithms.A128GCM, key_ops=KeyOps.ENCRYPT)
payload = dumps(payload)
nonce = b'\x00\x01\x02\x03' * 3
cwetoken = Enc0Message({CoseHeaderKeys.ALG: CoseAlgorithms.A128GCM}, {CoseHeaderKeys.IV: nonce}, payload).encode(nonce, cose_secret)

print("=========================================================")
print("CWE KEY :   %s" % dump_c_hex(cose_secret.k))
print("CWE TOKEN : %s" % dump_c_hex(cwetoken))
print("CWE TOKEN with length:%d" % len(cwetoken))
print("=========================================================")
