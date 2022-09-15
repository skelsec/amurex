
import asyncio
import traceback
from amurex.channels import SSHChannel
from amurex.protocol.messages import SSH_MSG_CHANNEL_OPEN, SSHString, parse_ssh_payload, SSHMessageNumber, SSH_MSG_KEXINIT, \
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_OPEN_FAILURE, SSH_MSG_CHANNEL_WINDOW_ADJUST,\
		SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EXTENDED_DATA

class SSHShellSession(SSHChannel):
	def __init__(self, recipientid, encoding='utf-8'):
		SSHChannel.__init__(self, 'session', recipientid, 0x200000, 0x8000)
		self.reader_task = None
		self.encoding = encoding
		self.stdin = asyncio.Queue()
		self.stdout = asyncio.Queue()
		self.stderr = asyncio.Queue()
	
	def decode_data(self, data:bytes):
		if self.encoding is None or self.encoding == '' or self.encoding.lower() == 'raw':
			return data
		return data.decode(self.encoding)
	

	async def close(self):
		if self.reader_task is not None:
			self.reader_task.cancel()
		self.stderr.put_nowait(b'')
		self.stdout.put_nowait(b'')
		await self.channel_close()

	async def __handle_in(self):
		while True:
			data = await self.stdin.get()
			if isinstance(data, bytes) is False:
				data = data.encode()
			await self.data_out(data, None, skip_windowcheck=True)
	
	async def channel_opened(self, msg:SSH_MSG_CHANNEL_OPEN_CONFIRMATION):
		try:
			self.reader_task = asyncio.create_task(self.__handle_in())
			await self.channel_request('shell', True, b'')
		except Exception as e:
			traceback.print_exc()

	async def data_in(self, datatype:int, data:bytes):
		if datatype is None:
			await self.stdout.put(self.decode_data(data))
		else:
			await self.stdout.put(self.decode_data(data))