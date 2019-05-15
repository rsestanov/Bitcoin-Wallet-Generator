import codecs
import hashlib
import os
from binascii import hexlify
import pprint

import ecdsa as ecdsa

import pomocne_funkcije


class BitcoinWallet:
    priv_kljuc_hex = None
    priv_kljuc_wif = None
    javni_kljuc_cijeli = None
    javni_kljuc_skraceni = None
    adresa_dugo = None
    adresa_kratko = None

    def __init__(self):
        self.generiraj_priv_kljuc()
        self.izracunaj_dugi_javni_kljuc()
        self.izracunaj_priv_kljuc_wif()
        self.izracunaj_kratki_javni_kljuc()
        self.izracunaj_skracenu_adresu()
        self.izracunaj_dugacku_adresu()

    def generiraj_priv_kljuc(self):
       
        kljuc = os.urandom(32)

      
        hex_kljuc = hexlify(kljuc)

      
        self.priv_kljuc_hex = hex_kljuc

    def izracunaj_dugi_javni_kljuc(self):
        
        priv_kljuc_hex = self.priv_kljuc_hex
        assert priv_kljuc_hex, "Privatni kljuc nije postavljen!"

       
        priv_kljuc_bytes = codecs.decode(priv_kljuc_hex, 'hex')

     
        krivulja = ecdsa.SECP256k1

        
        signing_key = ecdsa.SigningKey.from_string(priv_kljuc_bytes, curve=krivulja)
        verifying_key = signing_key.get_verifying_key()

     
        javni_kljuc_bytes = b'\04' + verifying_key.to_string()

    
        javni_kljuc_hex = codecs.encode(javni_kljuc_bytes, 'hex')

     
        self.javni_kljuc_cijeli = javni_kljuc_hex

    def izracunaj_priv_kljuc_wif(self):
        
        priv_kljuc_hex = self.priv_kljuc_hex
        assert priv_kljuc_hex, "Privatni kljuc nije postavljen!"

        
        self.priv_kljuc_wif = pomocne_funkcije.base58CheckEncode(b'80', priv_kljuc_hex)

    def izracunaj_kratki_javni_kljuc(self):
        
        javni_kljuc_cijeli = self.javni_kljuc_cijeli
        assert javni_kljuc_cijeli, "Dugacki javni kljuc nije postavljen!"

       
        kljuc_u_bajtovima = codecs.decode(javni_kljuc_cijeli, 'hex')
        assert len(kljuc_u_bajtovima) == 65, "Dugacki javni kljuc nije duljine 65 bajtova!"

      
        x = kljuc_u_bajtovima[1:33]
        zadnji_byte = kljuc_u_bajtovima[-1]

     
        if zadnji_byte & 1:
            prefix = b'03'
        else:
            prefix = b'02'

       
        x_hex = codecs.encode(x, 'hex')

      
        self.javni_kljuc_skraceni = prefix + x_hex

    @staticmethod
    def kriptiraj_javni_kljuc(javni_kljuc_hex):
       
        kljuc_u_bajtovima = codecs.decode(javni_kljuc_hex, 'hex')
        hash_kljuca = pomocne_funkcije.sha256_hash(kljuc_u_bajtovima)

       
        ripemd160 = hashlib.new('ripemd160')
       
        ripemd160.update(hash_kljuca)
     
        ripe_digest = ripemd160.digest()
       
        encrypted_key = codecs.encode(ripe_digest, 'hex')
        return encrypted_key

    @staticmethod
    def izracunaj_adresu(kriptirani_javni_kljuc):
       

        public_160bit_key = BitcoinWallet.kriptiraj_javni_kljuc(kriptirani_javni_kljuc)
        return pomocne_funkcije.base58CheckEncode(b'00', public_160bit_key)

    def izracunaj_dugacku_adresu(self):
        
        self.adresa_dugo = BitcoinWallet.izracunaj_adresu(self.javni_kljuc_cijeli)

    def izracunaj_skracenu_adresu(self):
       
        self.adresa_kratko = BitcoinWallet.izracunaj_adresu(self.javni_kljuc_skraceni)

    def __repr__(self):
        
        return pprint.pformat({
            'Privatni Kljuc': self.priv_kljuc_hex,
            'Privatni Kljuc(WIF)': self.priv_kljuc_wif,
            'Javni Kljuc (Potpuni)': self.javni_kljuc_cijeli,
            'Javni Kljuc (Komprimirani)': self.javni_kljuc_skraceni,
            'Adresa (Potpuna)': self.adresa_kratko,
            'Adresa (Komprimirana)': self.adresa_dugo
        }, width=200)


wallet = BitcoinWallet()
print(wallet)
