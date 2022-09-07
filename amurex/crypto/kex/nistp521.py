
from unicrypto.hashlib import sha512
from cryptography.hazmat.primitives.asymmetric import ec
from amurex.crypto.kex.ecdhnist import SSHKEXNISTBase

class SSHKEXNISTP521(SSHKEXNISTBase):
	def __init__(self):
		SSHKEXNISTBase.__init__(self, sha512, ec.SECP521R1())