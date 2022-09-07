from amurex.crypto.compression import SSHCompression


class SSHCompressionNone(SSHCompression):
	def __init__(self):
		SSHCompression.__init__(self, 'none')

	def compress(self, data:bytes) -> bytes:
		return data

	def decompress(self, data:bytes) -> bytes:
		return data