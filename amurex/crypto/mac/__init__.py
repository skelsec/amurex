
class SSHMACAlgo:
	def __init__(self, name, blocksize):
		self.name = name
		self.blocksize = blocksize

	def init_keys(self, key):
		self.key = key[:self.blocksize]

	def digest(self, msg:bytes, sequence_no:int) -> bytes:
		raise NotImplementedError()
	
	def verify(self, msg:bytes, macdata:bytes, sequence_no:int) -> bool:
		raise NotImplementedError()

from typing import Dict
from amurex.crypto.mac.hmacsha1 import SSHMACHMACSHA1
from amurex.crypto.mac.hmacsha256 import SSHMACHMACSHA256
from amurex.crypto.mac.hmacsha512 import SSHMACHMACSHA512

AMUREX_MAC_ALGORITHMS: Dict[str, SSHMACAlgo] = {
	'hmac-sha2-512' : SSHMACHMACSHA512,
	'hmac-sha2-256' : SSHMACHMACSHA256,
	'hmac-sha1': SSHMACHMACSHA1,
	
}