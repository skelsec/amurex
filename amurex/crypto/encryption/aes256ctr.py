from amurex.crypto.encryption import SSHEncryptionAlgo
from unicrypto.symmetric import AES, cipherMODE

class AES256CTR(SSHEncryptionAlgo):
	def __init__(self):
		SSHEncryptionAlgo.__init__(self, 'aes256-ctr', 16, 32, 16)
		self.obj = None

	def init_keys(self, key:bytes, IV:bytes) -> bytes:
		self.obj = AES(key[:32], cipherMODE.CTR, IV[:16])

	def encrypt(self, msg:bytes) -> bytes:
		return self.obj.encrypt(msg)

	def decrypt(self, msg:bytes) -> bytes:
		return self.obj.decrypt(msg)
