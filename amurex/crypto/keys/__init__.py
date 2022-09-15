import base64
import io
from typing import Dict
from amurex.protocol.messages import SSHString
from cryptography.hazmat.primitives.serialization import load_ssh_private_key
from cryptography.hazmat.primitives.asymmetric import dsa as cdsa 
from cryptography.hazmat.primitives.asymmetric import ec as cec
from cryptography.hazmat.primitives.asymmetric import ed25519 as ced25519
from cryptography.hazmat.primitives.asymmetric import rsa as crsa

class SSHKeyAlgo:
	def __init__(self):
		pass
	
	def to_knownhostline(self):
		raise NotImplementedError()

	def verify_server_signature(self, signature:bytes, raw_pubkey_msg:bytes):
		raise NotImplementedError()

	def load_pubkey_bytes(self, data:bytes):
		raise NotImplementedError()

	def load_pubkey_buffer(self, buff: io.BytesIO):
		raise NotImplementedError()

	@staticmethod
	def load_pubkey_from_server(servermsg):
		keytype = SSHString.from_buff(io.BytesIO(servermsg))
		keyobj = AMUREX_HOST_KEY_ALGORITHMS[keytype]()
		return keyobj.load_pubkey_bytes(servermsg)
	
	@staticmethod
	def load_pubkey_from_string_b64(keytype, b64s):
		return SSHKeyAlgo.load_pubkey_from_bytes(keytype, base64.b64decode(b64s))

	@staticmethod
	def load_pubkey_from_bytes(keytype, data):
		keyobj = AMUREX_HOST_KEY_ALGORITHMS[keytype]()
		return keyobj.load_pubkey_bytes(data)

	@staticmethod
	def load_privkey_file(fname:str, fileformat:str = 'openssh', password:str = None):
		with open(fname, 'rb') as f:
			return SSHKeyAlgo.load_privkey_file_bytes(f.read(), fileformat, password)

	@staticmethod
	def load_privkey_file_bytes(data:bytes, fileformat:str = 'openssh', password:str = None):
		if isinstance(password, str):
			password = password.encode()
		privkey = load_ssh_private_key(data, password)
		if isinstance(privkey, crsa.RSAPrivateKey):
			from amurex.crypto.keys.rsa import SSHKeyRSA
			key = SSHKeyRSA()
			key.load_privkey(privkey)

		elif isinstance(privkey, cec.EllipticCurvePrivateKey):
			from amurex.crypto.keys.ecdsa import SSHKeyECDSA
			key = SSHKeyECDSA()
			key.load_privkey(privkey)

		elif isinstance(privkey, ced25519.Ed25519PrivateKey):
			from amurex.crypto.keys.curve25519 import SSHKeyED25519
			key = SSHKeyED25519()
			key.load_privkey(privkey)

		elif isinstance(privkey, cdsa.DSAPrivateKey):
			raise Exception('DSA key auth not implemented!')

		else:
			raise Exception('Unknown or unsupported private key type: %s' % type(privkey))

		return key

from amurex.crypto.keys.rsa import SSHKeyRSA
from amurex.crypto.keys.curve25519 import SSHKeyED25519
from amurex.crypto.keys.ecdsa import SSHKeyECDSA

AMUREX_HOST_KEY_ALGORITHMS:Dict[str, SSHKeyAlgo] = {
	'ssh-ed25519' : SSHKeyED25519,
	'ecdsa-sha2-nistp521' : SSHKeyECDSA,
	'ecdsa-sha2-nistp384' : SSHKeyECDSA,
	'ecdsa-sha2-nistp256' : SSHKeyECDSA, 
	'rsa-sha2-512' : SSHKeyRSA,
	'rsa-sha2-256' : SSHKeyRSA,
	'ssh-rsa' : SSHKeyRSA,
	#'ssh-dss' : None, # TODO: Implement this
}