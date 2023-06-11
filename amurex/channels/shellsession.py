
import asyncio
import traceback
from amurex.channels import SSHChannel
from amurex.protocol.messages import SSH_MSG_CHANNEL_OPEN_CONFIRMATION

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

	async def channel_init(self, *args, **kwargs):
		try:
			self.reader_task = asyncio.create_task(self.__handle_in())
			return await self.channel_request('shell', True, b'')
		except Exception as e:
			return None, e
	
	async def channel_close(self, server_side:bool=False):
		self.stderr.put_nowait(b'')
		self.stdout.put_nowait(b'')
		self.stdin.put_nowait(b'')
		if self.reader_task is not None:
			self.reader_task.cancel()

	async def __handle_in(self):
		try:
			while True:
				data = await self.stdin.get()
				if data == b'':
					break
				if isinstance(data, bytes) is False:
					data = data.encode()
				await self.channel_data_out(data)
		except asyncio.CancelledError:
			pass
		except Exception as e:
			traceback.print_exc()
		finally:
			await self.close()

	async def channel_data_in(self, datatype:int, data:bytes):
		if datatype is None:
			await self.stdout.put(self.decode_data(data))
		else:
			await self.stdout.put(self.decode_data(data))