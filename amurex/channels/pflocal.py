
import asyncio
from sys import byteorder
import traceback
from amurex.channels import SSHChannel
from amurex.protocol.messages import SSH_MSG_CHANNEL_CLOSE, SSH_MSG_CHANNEL_OPEN, SSH_MSG_GLOBAL_REQUEST, SSHString, parse_ssh_payload, SSHMessageNumber, SSH_MSG_KEXINIT, \
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_OPEN_FAILURE, SSH_MSG_CHANNEL_WINDOW_ADJUST,\
		SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EXTENDED_DATA


class SSHLocalPortForward(SSHChannel):
	def __init__(self, recipientid, raddr, rport, laddr="", lport=0):
		data = b''
		data += SSHString.to_bytes(raddr)
		data += rport.to_bytes(4, byteorder='big', signed=False)
		data += SSHString.to_bytes(laddr)
		data += lport.to_bytes(4, byteorder='big', signed=False)
		SSHChannel.__init__(self, 'direct-tcpip', recipientid, 0x100000, 65535, data = data)
		self.iq_q:asyncio.Queue = None
		self.out_q:asyncio.Queue = None
	
	async def channel_eof(self):
		if self.out_q is not None:
			await self.out_q.put(b'')
		await self.close()
		
	async def data_in(self, datatype:int, data:bytes):
		if self.out_q is not None:
			#print('PF out: %s' % data)
			await self.out_q.put(data)
		else:
			print(data)

	async def __queue_writer(self):
		try:
			while True:
				data = await self.iq_q.get()
				if data == b'':
					return
				#print('PF in: %s' % data)
				await self.data_out(data)
		
		except Exception as e:
			await self.out_q.put(b'')
			await self.close()

	async def setup_queue(self):
		await asyncio.wait([self.channel_opened_evt.wait(), self.channel_closed_evt.wait()], return_when=asyncio.FIRST_COMPLETED)
		if self.channel_closed_evt.is_set():
			return None, Exception('Connection error')
		self.iq_q = asyncio.Queue()
		self.out_q = asyncio.Queue()
		self.qwriter_task = asyncio.create_task(self.__queue_writer())
		return True, None
