import io
import base64
import traceback
from amurex.crypto.keys import SSHKeyAlgo
from amurex.protocol.messages import SSHString
from amurex.crypto.mpint import inflate_long, deflate_long
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


AMUREX_SSH_RSAKEY_ALGO_HASH_LOOKUP = {
	'ssh-rsa' : hashes.SHA1,
	'rsa-sha2-256': hashes.SHA256,
	'rsa-sha2-512': hashes.SHA512
}

class SSH_RSA_SIGNATURE:
	def __init__(self):
		self.keytype = None
		self.keydata = None
	
	@staticmethod
	def from_bytes(data):
		return SSH_RSA_SIGNATURE.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		cert = SSH_RSA_SIGNATURE()
		cert.keytype = SSHString.from_buff(buff ,as_string=True)
		cert.keydata = SSHString.from_buff(buff)
		return cert
	
	def to_bytes(self):
		data = SSHString.to_bytes(self.keytype)
		data += SSHString.to_bytes(self.keydata)
		return data

class SSH_RSA_PUBKEY:
	def __init__(self):
		self.keytype:str = None
		self.exponent:int = None
		self.modulus:int = None
		self.pubkey:rsa.RSAPublicKey = None
	
	def to_knownhostline(self):
		data = self.to_bytes()
		return 'ssh-rsa', base64.b64encode(data).decode()

	def to_pubkeyblob(self):
		data  = SSHString.to_bytes('rsa-sha2-512')
		data += SSHString.to_bytes(self.to_bytes())
		return data
	
	@staticmethod
	def from_pubkey(pubkey:rsa.RSAPublicKey):
		pk = SSH_RSA_PUBKEY()
		pk.pubkey = pubkey
		numbers = pubkey.public_numbers()
		pk.exponent = numbers.e
		pk.modulus = numbers.n
		return pk

	@staticmethod
	def from_bytes(data):
		return SSH_RSA_PUBKEY.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		keytype = SSHString.from_buff(buff)
		exponent = inflate_long(SSHString.from_buff(buff))
		modulus = inflate_long(SSHString.from_buff(buff))
		key = SSH_RSA_PUBKEY()
		key.keytype = keytype
		key.exponent = exponent
		key.modulus = modulus
		key.pubkey = rsa.RSAPublicNumbers(
				e=exponent, 
				n=modulus
			).public_key(default_backend())

		return key

	def to_bytes(self, keytype = 'ssh-rsa'):
		data = b''
		data += SSHString.to_bytes(keytype)
		data += SSHString.to_bytes(deflate_long(self.exponent))
		data += SSHString.to_bytes(deflate_long(self.modulus))
		return data

	def verify_server_signature(self, signature, raw_pubkey_msg):
		try:
			cert = SSH_RSA_SIGNATURE.from_bytes(signature)
			hashobj = AMUREX_SSH_RSAKEY_ALGO_HASH_LOOKUP[cert.keytype]()
			blocksize = self.pubkey.key_size//8
			data = cert.keydata
			if blocksize != len(cert.keydata):
				pad_size = blocksize - (len(cert.keydata)% blocksize)
				data = b'\x00'*pad_size + cert.keydata
			self.pubkey.verify(
				data, raw_pubkey_msg, padding.PKCS1v15(), hashobj
			)
			return True
		except Exception as e:
			traceback.print_exc()
			return False

class SSHKeyRSA(SSHKeyAlgo):
	def __init__(self):
		SSHKeyAlgo.__init__(self)
		self.pubkey:SSH_RSA_PUBKEY = None
		self.privkey:rsa.RSAPrivateKey = None

	def sign(self, data, keytype):
		sigdata = self.privkey.sign(
			data,
			padding=padding.PKCS1v15(),
			algorithm=AMUREX_SSH_RSAKEY_ALGO_HASH_LOOKUP[keytype](),
		)

		sig = SSH_RSA_SIGNATURE()
		sig.keytype = keytype
		sig.keydata = sigdata
		return sig.to_bytes()

	def to_knownhostline(self):
		return self.pubkey.to_knownhostline()

	def verify_server_signature(self, signature:bytes, raw_pubkey_msg:bytes):
		return self.pubkey.verify_server_signature(signature, raw_pubkey_msg)

	def load_pubkey_bytes(self, data:bytes):
		return self.load_pubkey_buffer(io.BytesIO(data))

	def load_pubkey_buffer(self, buff: io.BytesIO):
		self.pubkey = SSH_RSA_PUBKEY.from_buffer(buff)
		return self.pubkey
	
	def load_privkey(self, privkey: rsa.RSAPrivateKey):
		self.privkey = privkey
		self.pubkey = SSH_RSA_PUBKEY.from_pubkey(privkey.public_key())
	
	def to_pubkeyblob(self):
		return self.pubkey.to_pubkeyblob()
