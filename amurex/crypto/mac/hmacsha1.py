from amurex.crypto.mac import SSHMACAlgo
import hmac

class SSHMACHMACSHA1(SSHMACAlgo):
	def __init__(self):
		super().__init__('hmac-sha1', 20)
		self.key = None

	def digest(self, msg:bytes, sequence_no:int) -> bytes:
		seq = sequence_no.to_bytes(4, byteorder='big', signed=False)
		macdata = hmac.new(self.key, seq + msg, digestmod='sha1').digest()
		return macdata
	
	def verify(self, msg:bytes, macdata:bytes, sequence_no:int) -> bytes:
		seq = sequence_no.to_bytes(4, byteorder='big', signed=False)
		newmacdata = hmac.new(self.key, seq + msg, digestmod='sha1').digest()
		return hmac.compare_digest(macdata, newmacdata)
		