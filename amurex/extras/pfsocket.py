import asyncio
import traceback

class SSHPortfowardLocalSocket:
	def __init__(self, raddr, rport, laddr, lport, sshconnection):
		self.raddr = raddr
		self.rport = rport
		self.laddr = laddr
		self.lport = lport
		self.sshconnection = sshconnection
		self.buffersize = 10240

	async def __handle_writer(self, writer, pfo):
		try:
			while True:
				data = await pfo.out_q.get()
				#print('writer data: %s' % data)
				writer.write(data)
				await writer.drain()
				if data == b'':
					return
		finally:
			writer.close()
	
	async def handle_client(self, reader:asyncio.StreamReader, writer:asyncio.StreamWriter):
		writer_task = None
		pfo = None
		try:
			pfo, err = await self.sshconnection.portforward_local_queue(str(self.raddr), self.rport)
			if err is not None:
				pfo = None
				raise err
			
			writer_task = asyncio.create_task(self.__handle_writer(writer, pfo))
			while True:
				data = await reader.read(self.buffersize)
				#print('reader data: %s' % data)
				await pfo.iq_q.put(data)
				if data == b'':
					break

		except Exception as e:
			traceback.print_exc()
		finally:
			if writer_task is not None:
				writer_task.cancel()
			if pfo is not None:
				await pfo.close()
			if writer is not None:
				writer.close()
	
	async def run(self):
		server_coro = asyncio.start_server(self.handle_client, host=self.laddr, port=self.lport)
		await server_coro