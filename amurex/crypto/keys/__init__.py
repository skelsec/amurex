import base64
from http import server
import io
from amurex.crypto import SSHAlgo
from amurex.protocol.messages import SSHString
#### TODO: implement this

class SSHKeyAlgo(SSHAlgo):
	def __init__(self, name):
		SSHAlgo.__init__(self, name)

	@staticmethod
	def load_pubkey_from_server(servermsg):
		keytype = SSHString.from_buff(io.BytesIO(servermsg))
		keyobj = AMUREX_HOST_KEY_ALGORITHMS[keytype]
		return keyobj.from_bytes(servermsg)
	
	@staticmethod
	def load_pubkey_from_string_b64(keytype, b64s):
		return SSHKeyAlgo.load_pubkey_from_bytes(keytype, base64.b64decode(b64s))

	@staticmethod
	def load_pubkey_from_bytes(keytype, data):
		keyobj = AMUREX_HOST_KEY_ALGORITHMS[keytype]
		return keyobj.from_bytes(data)


from amurex.crypto.keys.rsa import SSHKeyRSA
from amurex.crypto.keys.curve25519 import SSHKeyED25519
from amurex.crypto.keys.ecdsa import SSHKeyECDSA

AMUREX_HOST_KEY_ALGORITHMS = {
	'ssh-ed25519' : SSHKeyED25519, #wait until cryptography can do verification...
	#'ecdsa-sha2-nistp521' : SSHKeyECDSA,
	#'ecdsa-sha2-nistp384' : SSHKeyECDSA,
	#'ecdsa-sha2-nistp256' : SSHKeyECDSA, 
	#'rsa-sha2-512' : SSHKeyRSA,
	#'rsa-sha2-256' : SSHKeyRSA,
	#'ssh-rsa' : SSHKeyRSA,
	#'ssh-dss' : None,
}