from amurex.crypto.mac import SSHMACAlgo
import hmac
# https://www.ietf.org/rfc/rfc6668.html

class SSHMACHMACSHA512(SSHMACAlgo):
	def __init__(self):
		super().__init__('hmac-sha2-512', 64)
		self.key = None

	def digest(self, msg:bytes, sequence_no:int) -> bytes:
		seq = sequence_no.to_bytes(4, byteorder='big', signed=False)
		macdata = hmac.new(self.key, seq + msg, digestmod='sha512').digest()
		return macdata
	
	def verify(self, msg:bytes, macdata:bytes, sequence_no:int) -> bytes:
		seq = sequence_no.to_bytes(4, byteorder='big', signed=False)
		newmacdata = hmac.new(self.key, seq + msg, digestmod='sha512').digest()
		return hmac.compare_digest(macdata, newmacdata)
		