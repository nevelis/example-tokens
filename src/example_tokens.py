import IPython
from jwcrypto import jwk, jws, jwt, jwe
from jwcrypto.common import json_encode, json_decode

import os, struct, sys

secret_key = jwk.JWK.generate(kty='oct',size=256)
user_centric_header = {'alg':'dir','enc':'A128CBC-HS256'}

# User-centric token with bound-ip, expiration time, and nti (nonce).
# Token will be encrypted with 128CBC-HS256, using direct symmetric
# encryption
header = {'alg':'dir','enc':'A128CBC-HS256'}
# App ID for this service
app_id = 0x10001
# Origin packet, no reflection needed
reflect_type = 0
# Token is bound to IP bip. It expires on 01/01/2030, and comes with
# an nti (nonce) value for potential revocation.
payload = {'bip':'172.31.0.3','exp':1893456000, 'nti':151234143124}

token_header = (reflect_type) << 28 | app_id
jwetoken = jwe.JWE(json_encode(payload),
                   json_encode(header))
jwetoken.add_recipient(secret_key)

print("#######################")
print("User-Centric Network Token")
print("\n\n")
print("#### Payload ####")
print(payload)
print("\n\n")
print("#### Secret Key ####")
print(secret_key.export())
print("\n\n")
print("#### Token (JSON format) ####")
print(jwetoken.serialize())
print("\n\n")
print("#### Token (compact format) ####")
print(jwetoken.serialize(True))
print("\n\n")
print("#### Token (compact format) - HEX ####")
print(jwetoken.serialize(True).encode('utf8').hex())
print("\n\n")
print("#### Token (Compact with Token Header) - HEX ####")
print(struct.pack('!I',token_header).hex() + jwetoken.serialize(True).encode('utf8').hex())
print("\n\n")

    

