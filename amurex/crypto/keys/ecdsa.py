import io
import base64
import traceback
from amurex.crypto.keys import SSHKeyAlgo
from amurex.protocol.messages import SSHString
from amurex.crypto.mpint import inflate_long, deflate_long
from cryptography.hazmat.primitives.asymmetric.utils import (
	decode_dss_signature,
	encode_dss_signature,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

AMUREX_ECDSA_NAME_TO_CURVE = {
	'nistp256' : ec.SECP256R1,
	'nistp384' : ec.SECP384R1,
	'nistp521' : ec.SECP521R1,
}
AMUREX_ECDSA_CURVE_TO_NAME = {v: k for k, v in AMUREX_ECDSA_NAME_TO_CURVE.items()}
AMUREX_ECDSA_CURVE_TO_HASHOBJ = {
	ec.SECP256R1: hashes.SHA256,
	ec.SECP384R1: hashes.SHA384,
	ec.SECP521R1: hashes.SHA512,
}

class SSH_ECDSA_SIGNATURE:
	def __init__(self):
		self.keytype = None
		self.rs = None
		self.r = None
		self.s = None
	
	@staticmethod
	def from_bytes(data):
		return SSH_ECDSA_SIGNATURE.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		cert = SSH_ECDSA_SIGNATURE()
		cert.keytype = SSHString.from_buff(buff, as_string=True)
		cert.rs = SSHString.from_buff(buff)
		tdata = io.BytesIO(cert.rs)
		cert.r = inflate_long(SSHString.from_buff(tdata))
		cert.s = inflate_long(SSHString.from_buff(tdata))
		return cert
	
	def to_bytes(self):
		data = SSHString.to_bytes(self.keytype)
		tdata  = SSHString.to_bytes(deflate_long(self.r))
		tdata += SSHString.to_bytes(deflate_long(self.s))
		data += SSHString.to_bytes(tdata)
		return data

class SSHKeyECDSAVeifyKey:
	def __init__(self):
		self.keytype = None
		self.identifier = None
		self.q = None
		self.verifykey:ec.EllipticCurvePublicKey = None

	def verify_server_signature(self, signature, raw_pubkey_msg):
		try:
			cert = SSH_ECDSA_SIGNATURE.from_bytes(signature)
			signature = encode_dss_signature(cert.r, cert.s)
			hashobj = AMUREX_ECDSA_CURVE_TO_HASHOBJ[type(self.verifykey.curve)]()
			self.verifykey.verify(
				signature, raw_pubkey_msg, ec.ECDSA(hashobj)
			)
			return True
		except Exception as e:
			return False

	def to_knownhostline(self):
		data = self.to_bytes()
		return 'ecdsa-sha2-%s' % self.identifier, base64.b64encode(data).decode()
	
	@staticmethod
	def from_bytes(data):
		return SSHKeyECDSAVeifyKey.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		keytype = SSHString.from_buff(buff, as_string=True)
		identifier = SSHString.from_buff(buff, as_string=True)
		q = SSHString.from_buff(buff)
		key = SSHKeyECDSAVeifyKey()
		key.keytype = keytype
		key.identifier = identifier
		key.q = q
		curve = AMUREX_ECDSA_NAME_TO_CURVE[identifier]()
		key.verifykey = ec.EllipticCurvePublicKey.from_encoded_point(curve, q)
		return key

	def to_pubkeyblob(self):
		data  = SSHString.to_bytes("ecdsa-sha2-%s" % self.identifier)
		data += SSHString.to_bytes(self.to_bytes())
		return data

	def to_bytes(self):
		data = b''
		data += SSHString.to_bytes(self.keytype)
		data += SSHString.to_bytes(self.identifier)
		data += SSHString.to_bytes(self.q)
		return data

class SSHKeyECDSA(SSHKeyAlgo):
	def __init__(self):
		SSHKeyAlgo.__init__(self)
		self.verifykey:SSHKeyECDSAVeifyKey = None
		self.signkey   = None
		self.privkey   = None
	
	def sign(self, data, keytype = ''):
		sigdata = self.privkey.sign(data, ec.ECDSA(AMUREX_ECDSA_CURVE_TO_HASHOBJ[type(self.privkey.curve)]()))
		r, s = decode_dss_signature(sigdata)
		sig = SSH_ECDSA_SIGNATURE()
		sig.keytype = self.verifykey.keytype
		sig.r = r
		sig.s = s
		return sig.to_bytes()

	def to_knownhostline(self):
		return self.verifykey.to_knownhostline()

	def verify_server_signature(self, signature:bytes, raw_pubkey_msg:bytes):
		return self.verifykey.verify_server_signature(signature, raw_pubkey_msg)

	def load_pubkey_bytes(self, data:bytes):
		return self.load_pubkey_buffer(io.BytesIO(data))

	def load_pubkey_buffer(self, buff: io.BytesIO):
		self.verifykey = SSHKeyECDSAVeifyKey.from_buffer(buff)
		return self.verifykey

	def load_privkey(self, privkey: ec.EllipticCurvePrivateKey):
		self.privkey = privkey
		self.verifykey = SSHKeyECDSAVeifyKey()
		self.verifykey.verifykey = self.privkey.public_key()
		self.verifykey.identifier = AMUREX_ECDSA_CURVE_TO_NAME[type(self.privkey.public_key().curve)]
		self.verifykey.keytype = "ecdsa-sha2-%s" % self.verifykey.identifier
		
		pn = self.privkey.public_key().public_numbers()
		keysize = (self.privkey.public_key().curve.key_size +7) //8
		x = pn.x.to_bytes(keysize, byteorder='big', signed=False)
		y = pn.y.to_bytes(keysize, byteorder='big', signed=False)
		self.verifykey.q = b'\x04' + x + y

	def to_pubkeyblob(self):
		return self.verifykey.to_pubkeyblob()