import io
import traceback
from amurex.crypto.keys import SSHKeyAlgo
from amurex.protocol.messages import SSHString
from amurex.crypto.mpint import inflate_long, deflate_long
from amurex.crypto.extras.pure25519.ed25519 import VerifyingKey


class SSHKeyED25519(SSHKeyAlgo):
	def __init__(self):
		SSHKeyAlgo.__init__(self, 'ssh-ed25519')
		self.pubkey   = None
		self.privkey  = None

	def verify_server_signature(self, signature, raw_pubkey_msg):
		try:
			buff = io.BytesIO(signature)
			SSHString.from_buff(buff)
			signature = SSHString.from_buff(buff)
			result = self.pubkey.verify(signature, raw_pubkey_msg)
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
		return SSHKeyED25519.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		keytype = SSHString.from_buff(buff)
		key = SSHKeyED25519()
		key.pubkey = VerifyingKey(SSHString.from_buff(buff))
		return key

	
	#def to_bytes(self):
	#	data = b''
	#	data += SSHString.to_bytes('ssh-ed25519')
	#	data += SSHString.to_bytes(deflate_long(self.exponent))
	#	data += SSHString.to_bytes(deflate_long(self.modulus))
	#	return data
