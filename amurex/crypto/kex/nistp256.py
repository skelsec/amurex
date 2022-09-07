
from unicrypto.hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import ec
from amurex.crypto.kex.ecdhnist import SSHKEXNISTBase

class SSHKEXNISTP256(SSHKEXNISTBase):
	def __init__(self):
		SSHKEXNISTBase.__init__(self, sha256, ec.SECP256R1())