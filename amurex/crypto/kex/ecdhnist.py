from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from amurex.crypto.kex import SSHKEXAlgo
from amurex.protocol.messages import SSH_MSG_KEXECDH_INIT, SSH_MSG_KEXECDH_REPLY, SSHString
from hmac import compare_digest
from amurex.crypto.mpint import deflate_long, inflate_long

class SSHKEXNISTBase(SSHKEXAlgo):
	def __init__(self, hashobj, curve):
		SSHKEXAlgo.__init__(self)
		self.hashobj = hashobj
		self.curve = curve
		self.key = None
		self.__qc = None
		self.__qs = None
		self.__iteration = 0

	def init(self, selected_method, client_banner, server_banner, client_kex, server_kex, host_key):
		self.selected_method = selected_method
		self.client_banner = client_banner
		self.server_banner = server_banner
		self.client_kex = client_kex
		self.server_kex = server_kex
		self.host_key = host_key

	
	async def authenticate(self, server_msg = None):
		try:
			if self.__iteration == 0 and server_msg is None:
				self.__iteration = 1
				self.key = ec.generate_private_key(self.curve, default_backend())
				self.__qc = self.key.public_key().public_bytes(
					serialization.Encoding.X962,
					serialization.PublicFormat.UncompressedPoint,
				)
				msg = SSH_MSG_KEXECDH_INIT(self.__qc)
				return msg.to_bytes(), False, None

			if self.__iteration == 1:
				smsg = SSH_MSG_KEXECDH_REPLY.from_bytes(server_msg)
				smsg.ks
				
				self.__qs = ec.EllipticCurvePublicKey.from_encoded_point(self.curve, smsg.qs)
				K = self.key.exchange(ec.ECDH(), self.__qs)
				
				self.shared_secret = SSHString.to_bytes(deflate_long(int.from_bytes(K, byteorder='big', signed=False)))
				to_hash =   SSHString.to_bytes(self.client_banner.strip())+\
							SSHString.to_bytes(self.server_banner.strip())+\
							SSHString.to_bytes(self.client_kex.rawdata)+\
							SSHString.to_bytes(self.server_kex.rawdata)+\
							SSHString.to_bytes(smsg.ks)+\
							SSHString.to_bytes(self.__qc)+\
							SSHString.to_bytes(smsg.qs)+\
							self.shared_secret

				self.exchange_hash = self.hashobj(to_hash).digest()
				return None, True, None


		except Exception as e:
			return None, True, e