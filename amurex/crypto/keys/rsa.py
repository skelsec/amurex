import io
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

class SSH_RSA_CERTIFICATE:
	def __init__(self):
		self.keytype = None
		self.keydata = None
	
	@staticmethod
	def from_bytes(data):
		return SSH_RSA_CERTIFICATE.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		cert = SSH_RSA_CERTIFICATE()
		cert.keytype = SSHString.from_buff(buff ,as_string=True)
		cert.keydata = SSHString.from_buff(buff)
		return cert


class SSHKeyRSA(SSHKeyAlgo):
	def __init__(self):
		SSHKeyAlgo.__init__(self, 'ssh-rsa')
		self.exponent = None
		self.modulus = None
		self.pubkey = None
		self.privkey = None

	def verify_server_signature(self, signature, raw_pubkey_msg):
		try:
			print(signature)
			cert = SSH_RSA_CERTIFICATE.from_bytes(signature)
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

	@staticmethod
	def from_ssh_keyfile():
		pass

	@staticmethod
	def from_ssh_pubkeyfile():
		pass

	@staticmethod
	def from_bytes(data):
		return SSHKeyRSA.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		keytype = SSHString.from_buff(buff)
		exponent = inflate_long(SSHString.from_buff(buff))
		modulus = inflate_long(SSHString.from_buff(buff))
		key = SSHKeyRSA()
		key.exponent = exponent
		key.modulus = modulus
		key.pubkey = rsa.RSAPublicNumbers(
				e=exponent, 
				n=modulus
			).public_key(default_backend())

		return key

	
	def to_bytes(self):
		data = b''
		data += SSHString.to_bytes("ssh-rsa")
		data += SSHString.to_bytes(deflate_long(self.exponent))
		data += SSHString.to_bytes(deflate_long(self.modulus))
		return data
