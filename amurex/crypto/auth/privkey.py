from cryptography.hazmat.primitives.serialization import load_ssh_private_key
from hashlib import sha1
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa

AMUREX_PRIVKEY_TYPE_LOOKUP = {
	ec.EllipticCurvePrivateKey : 'ecdsa-sha2-',
    rsa.RSAPrivateKey : 'ssh-rsa',
    dsa.DSAPrivateKey : 'ssh-dss',
    ed25519.Ed25519PrivateKey: 'ssh-ed25519',
}

class PrivKey:
	def __init__(self, key, keytype = None):
		self.keytype = keytype
		self.key = key
		if keytype is None:
			self.keytype = AMUREX_PRIVKEY_TYPE_LOOKUP[type(self.key)]
	
	@staticmethod
	def from_keyfile(filepath, passphrase = None):
		key = load_ssh_private_key(open(filepath, "rb").read(), passphrase)
		return PrivKey(key)
	
	



