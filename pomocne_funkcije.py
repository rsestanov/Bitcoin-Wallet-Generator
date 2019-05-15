import codecs
import hashlib

import base58


def sha256_hash(key):
   

    return hashlib.sha256(key).digest()


def base58CheckEncode(version, hex_key):
   

  
    assert len(version) == 2, "Verzija mora biti duljine 2!"

  
    versioned_hex_key = version + hex_key


    versioned_bytes_key = codecs.decode(versioned_hex_key, 'hex')

   
    return base58.b58encode_check(versioned_bytes_key)
