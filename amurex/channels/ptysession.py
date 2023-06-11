import asyncio
from amurex.channels import SSHChannel
from amurex.protocol.messages import SSHString

class SSHPTYSession(SSHChannel):
	def __init__(self, recipientid, term = 'vt100', row_width=80, row_height=24, pixel_width=640, pixel_height=480):
		SSHChannel.__init__(self, 'session', recipientid, 0x200000, 0x8000)
		self.term = term
		self.row_width = row_width
		self.row_height = row_height
		self.pixel_width = pixel_width
		self.pixel_height = pixel_height
		self.stdin = asyncio.Queue()
		self.stdout = asyncio.Queue()
		self.stderr = asyncio.Queue()
		self.selected_operation = None

	async def channel_close(self, server_side:bool=False):
		self.stderr.put_nowait(b'')
		self.stdout.put_nowait(b'')
	
	async def channel_init(self, *args, **kwargs):
		try:
			self.reader_task = asyncio.create_task(self.__handle_in())
			data = b''
			data += SSHString.to_bytes(self.term)
			data += self.row_width.to_bytes(4, byteorder='big', signed=False)
			data += self.row_height.to_bytes(4, byteorder='big', signed=False)
			data += self.pixel_width.to_bytes(4, byteorder='big', signed=False)
			data += self.pixel_height.to_bytes(4, byteorder='big', signed=False)
			data += SSHString.to_bytes(b'\x00') # terminal modes
			return await self.channel_request('pty-req', True, data)
		except Exception as e:
			return None, e
	
	async def resize_pty(self, row_width, row_height, pixel_width=640, pixel_height=480):
		self.row_width = row_width
		self.row_height = row_height
		self.pixel_width = pixel_width
		self.pixel_height = pixel_height
		data = b''
		data += self.row_width.to_bytes(4, byteorder='big', signed=False)
		data += self.row_height.to_bytes(4, byteorder='big', signed=False)
		data += self.pixel_width.to_bytes(4, byteorder='big', signed=False)
		data += self.pixel_height.to_bytes(4, byteorder='big', signed=False)
		return await self.channel_request('window-change', False, data)
	
	async def get_shell(self):
		if self.selected_operation is not None:
			return None, Exception('Operation already selected')
		self.selected_operation = 'shell'
		return await self.channel_request('shell', True, b'')

	async def execute_command(self, cmd):
		if self.selected_operation is not None:
			return None, Exception('Operation already selected')
		self.selected_operation = 'exec'
		data = SSHString.to_bytes(cmd)
		return await self.channel_request('exec', True, data)

	async def __handle_in(self):
		while True:
			data = await self.stdin.get()
			if isinstance(data, bytes) is False:
				data = data.encode()
			await self.channel_data_out(data)

	async def channel_data_in(self, datatype:int, data:bytes):
		if datatype is None:
			await self.stdout.put(data)
		else:
			await self.stdout.put(data)