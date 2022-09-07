
from unicrypto.hashlib import sha384
from cryptography.hazmat.primitives.asymmetric import ec
from amurex.crypto.kex.ecdhnist import SSHKEXNISTBase

class SSHKEXNISTP384(SSHKEXNISTBase):
	def __init__(self):
		SSHKEXNISTBase.__init__(self, sha384, ec.SECP384R1())