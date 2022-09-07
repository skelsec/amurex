from amurex.crypto.compression import SSHCompression
import zlib

class SSHCompressionZLIB(SSHCompression):
	def __init__(self):
		SSHCompression.__init__(self, 'zlib')

	def compress(self, data:bytes) -> bytes:
		compobj = zlib.compressobj(9)
		return compobj.compress(data) + compobj.flush(zlib.Z_FULL_FLUSH)

	def decompress(self, data:bytes) -> bytes:
		compobj = zlib.decompressobj(9)
		return compobj.decompress(data)
