import io
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
AMUREX_ECDSA_CURVE_TO_HASHOBJ = {
	ec.SECP256R1: hashes.SHA256,
	ec.SECP384R1: hashes.SHA384,
	ec.SECP521R1: hashes.SHA512,
}

class SSH_ECDSA_CERTIFICATE:
	def __init__(self):
		self.keytype = None
		self.rs = None
		self.r = None
		self.s = None
	
	@staticmethod
	def from_bytes(data):
		return SSH_ECDSA_CERTIFICATE.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		cert = SSH_ECDSA_CERTIFICATE()
		cert.keytype = SSHString.from_buff(buff, as_string=True)
		cert.rs = SSHString.from_buff(buff)
		tdata = io.BytesIO(cert.rs)
		cert.r = inflate_long(SSHString.from_buff(tdata))
		cert.s = inflate_long(SSHString.from_buff(tdata))
		return cert

class SSHKeyECDSA(SSHKeyAlgo):
	def __init__(self):
		SSHKeyAlgo.__init__(self, 'ecdsa-sha2-')
		self.verifykey = None
		self.signkey   = None
		self.privkey   = None

	def verify_server_signature(self, signature, raw_pubkey_msg):
		try:
			cert = SSH_ECDSA_CERTIFICATE.from_bytes(signature)
			signature = encode_dss_signature(cert.r, cert.s)
			hashobj = AMUREX_ECDSA_CURVE_TO_HASHOBJ[type(self.verifykey.curve)]()
			self.verifykey.verify(
                signature, raw_pubkey_msg, ec.ECDSA(hashobj)
            )
			return True
		except Exception as e:
			traceback.print_exc()
			return False

	@staticmethod
	def from_ssh_keyfile():
		pass

	@staticmethod
	def from_ssh_pubkeyfile():
		pass

	@staticmethod
	def from_bytes(data):
		return SSHKeyECDSA.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		keytype = SSHString.from_buff(buff, as_string=True)
		identifier = SSHString.from_buff(buff, as_string=True)
		q = SSHString.from_buff(buff)
		key = SSHKeyECDSA()
		curve = AMUREX_ECDSA_NAME_TO_CURVE[identifier]()
		key.verifykey = ec.EllipticCurvePublicKey.from_encoded_point(curve, q)
		return key

	
	#def to_bytes(self):
	#	data = b''
	#	data += SSHString.to_bytes('ssh-ed25519')
	#	data += SSHString.to_bytes(deflate_long(self.exponent))
	#	data += SSHString.to_bytes(deflate_long(self.modulus))
	#	return data
