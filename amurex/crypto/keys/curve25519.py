import base64
import io
import traceback
from amurex.crypto.keys import SSHKeyAlgo
from amurex.protocol.messages import SSHString
from amurex.crypto.mpint import inflate_long, deflate_long
from amurex.crypto.extras.pure25519.ed25519 import VerifyingKey, SigningKey
from cryptography.hazmat.primitives.asymmetric import ed25519 as ced25519
from cryptography.hazmat.primitives import serialization



class SSH_ED25519_SIGNATURE:
	def __init__(self):
		self.sigtype = None
		self.sigdata = None

	@staticmethod
	def from_bytes(data):
		return SSH_ED25519_SIGNATURE.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		cert = SSH_ED25519_SIGNATURE()
		cert.sigtype = SSHString.from_buff(buff ,as_string=True)
		cert.sigdata = SSHString.from_buff(buff)
		return cert

	def to_bytes(self):
		data  = SSHString.to_bytes(self.sigtype)
		data += SSHString.to_bytes(self.sigdata)
		return data

class SSHKeyED25519VerifyKey:
	def __init__(self):
		self.keytype = None
		self.vks = None
		self.verifykey:VerifyingKey = None

	def verify_server_signature(self, signature, raw_pubkey_msg):
		try:
			sig = SSH_ED25519_SIGNATURE.from_bytes(signature)
			self.verifykey.verify(sig.sigdata, raw_pubkey_msg)
			return True
		except Exception as e:
			traceback.print_exc()
			return False
	
	def to_knownhostline(self):
		data = self.to_bytes()
		return 'ssh-ed25519', base64.b64encode(data).decode()

	@staticmethod
	def from_bytes(data):
		return SSHKeyED25519VerifyKey.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		keytype = SSHString.from_buff(buff, as_string=True)
		key = SSHKeyED25519VerifyKey()
		key.keytype = keytype
		key.vks = SSHString.from_buff(buff)
		key.verifykey = VerifyingKey(key.vks)
		return key

	def to_bytes(self):
		data = b''
		data += SSHString.to_bytes('ssh-ed25519')
		data += SSHString.to_bytes(self.vks)
		return data

	def to_pubkeyblob(self):
		data  = SSHString.to_bytes('ssh-ed25519')
		data += SSHString.to_bytes(self.to_bytes())
		return data

class SSHKeyED25519(SSHKeyAlgo):
	def __init__(self):
		SSHKeyAlgo.__init__(self)
		self.pubkey    = None
		self.privkey   = None
		self.verifykey:SSHKeyED25519VerifyKey = None
	
	def sign(self, data, keytype = ''):
		x = self.privkey.sign(data)
		sig = SSH_ED25519_SIGNATURE()
		sig.sigtype = 'ssh-ed25519'
		sig.sigdata = x
		return sig.to_bytes()


	def to_knownhostline(self):
		return self.verifykey.to_knownhostline()

	def verify_server_signature(self, signature:bytes, raw_pubkey_msg:bytes):
		return self.verifykey.verify_server_signature(signature, raw_pubkey_msg)

	def load_pubkey_bytes(self, data:bytes):
		return self.load_pubkey_buffer(io.BytesIO(data))

	def load_pubkey_buffer(self, buff: io.BytesIO):
		self.verifykey = SSHKeyED25519VerifyKey.from_buffer(buff)
		return self.verifykey

	def load_privkey(self, privkey: ced25519.Ed25519PrivateKey):
		self.privkey = privkey
		verifykeybytes = privkey.public_key().public_bytes(
			serialization.Encoding.Raw,
			serialization.PublicFormat.Raw,
		)
		self.verifykey = SSHKeyED25519VerifyKey()
		self.verifykey.vks = verifykeybytes
		self.verifykey.verifykey = VerifyingKey(verifykeybytes) #because this key format has verify api unlike cryptography

	def to_pubkeyblob(self):
		return self.verifykey.to_pubkeyblob()