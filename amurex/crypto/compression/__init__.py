
class SSHCompression:
	def __init__(self, name:str):
		self.name = name
	
	def compress(self, data:bytes) -> bytes:
		return data

	def decompress(self, data:bytes) -> bytes:
		return data

from typing import Dict
from amurex.crypto.compression.none import SSHCompressionNone
from amurex.crypto.compression.compzlib import SSHCompressionZLIB


AMUREX_COMPRESSION_ALGORITHMS:Dict[str, SSHCompression] = {
	'zlib' : SSHCompressionZLIB,
	'none' : SSHCompressionNone,
}