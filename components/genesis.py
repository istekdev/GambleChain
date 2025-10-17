from bip32utils import BIP32Key
from Crypto.Hash import RIPEMD
from mnemonic import Mnemonic
from hashlib import sha256
import base58
import ecdsa
import json
import os

m = Mnemonic("english")

def gen():
  address = ""
  entropy = os.urandom(24)
  seedphrase = m.to_mnemonic(entropy)
  seed = m.to_seed(seedphrase, passphrase="")

  master = BIP32Key.fromEntropy(seed)
  private = master.PrivateKey()
  public = master.PublicKey()
  sign = ecdsa.SigningKey.from_string(private, curve=ecdsa.SECP256k1)

  version = bytes([0x54])
  ripemd = RIPEMD.new(public)
  checksum = sha256(sha256(version + ripemd).digest()).digest()[:4]
  raw58 = base58.b58encode(version + ripemd + checksum).decode()

  extraction = base58.b58decode(raw58)
  eVersion = extraction[0:1]
  eRIPEMD = extraction[1:21]
  eChecksum = extraction[21:25]
  if sha256(sha256(eVersion + eRIPEMD).digest()).digest()[:4] == eChecksum:
    address = "gc" + raw58
  else:
    address = "Invalid"

  mintData = {
    "address": address,
    "private": private.hex(),
    "public": public.hex(),
    "signingKey": sign.hex(),
    "amount": 10**100
  }

  with open("./minter.json", "w") as w:
    json.dump(mintData, w, indent=4)
