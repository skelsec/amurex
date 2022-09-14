
import asyncio
import ipaddress
import traceback
from asysocks.protocol.socks5 import SOCKS5Method, SOCKS5AddressType, SOCKS5ReplyType, SOCKS5Reply, SOCKS5Nego, SOCKS5NegoReply, SOCKS5Request, SOCKS5Command

class SSHPortfowardDynamicSOCKS:
	def __init__(self, laddr, lport, sshconnection):
		self.laddr = laddr
		self.lport = lport
		self.sshconnection = sshconnection
		self.__connections = {}
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
			nego = await SOCKS5Nego.from_streamreader(reader)
			if nego.VER != 5:
				raise Exception('SOCKS client sent incorrect version!')

			if SOCKS5Method.NOAUTH not in nego.METHODS:
				raise Exception('Client doesnt support noauth!')
			negreply = SOCKS5NegoReply()
			negreply.VER = 5
			negreply.METHOD = SOCKS5Method.NOAUTH
			writer.write(negreply.to_bytes())
			await writer.drain()

			sreq = await SOCKS5Request.from_streamreader(reader)
			if sreq.CMD != SOCKS5Command.CONNECT:
				raise Exception('Client wanted to do %s, but only CONNECT is supported!' % sreq.CMD)
			
			pfo, err = await self.sshconnection.portforward_local_queue(str(sreq.DST_ADDR), sreq.DST_PORT)
			if err is not None:
				pfo = None
				raise err

			srep = SOCKS5Reply.construct(SOCKS5ReplyType.SUCCEEDED, ipaddress.ip_address("0.0.0.0"), 0)
			writer.write(srep.to_bytes())
			await writer.drain()
			
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
