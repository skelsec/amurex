

class SSHEncryptionAlgo:
	def __init__(self, name,blocksize, keysize, ivsize):
		self.name = name
		self.blocksize = blocksize
		self.keysize = keysize
		self.ivsize = ivsize
	
	def init_keys(self, key:bytes, IV:bytes):
		raise NotImplementedError()

	def encrypt(self, msg:bytes) -> bytes:
		raise NotImplementedError()

	def decrypt(self, msg:bytes) -> bytes:
		raise NotImplementedError()

from typing import Dict
from amurex.crypto.encryption.aes128ctr import AES128CTR
from amurex.crypto.encryption.aes192ctr import AES192CTR
from amurex.crypto.encryption.aes256ctr import AES256CTR

AMUREX_ENCRYPTION_ALGORITHMS:Dict[str, SSHEncryptionAlgo] = {
	'aes256-ctr' : AES256CTR,
	'aes192-ctr' : AES192CTR,
	'aes128-ctr' : AES128CTR
}