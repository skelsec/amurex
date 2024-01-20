import traceback
import asyncio
from amurex.client import SSHClient

async def reader(inq, stop_evt):
	while not stop_evt.is_set():
		data = await inq.get()
		if data == b'':
			stop_evt.set()
			return
		print(data)
	
async def get_steam_reader(pipe) -> asyncio.StreamReader:
	loop = asyncio.get_event_loop()
	reader = asyncio.StreamReader(loop=loop)
	protocol = asyncio.StreamReaderProtocol(reader)
	await loop.connect_read_pipe(lambda: protocol, pipe)
	return reader


async def amain():
	try:
		client, err = await SSHClient.from_params(
			'127.0.0.1', 
			username = 'webdev', 
			password = 'webdev', 
			verify=False
		)
		if err is not None:
			raise err
		
		async with client:
			print('Connect Done!')
			
			sftp, err = await client.get_sftp()
			if err is not None:
				raise err
			
			async with sftp:
				#_, err = await sftp.mkdir('testdir')
				#if err is not None:
				#	raise err
				#
				#_, err = await sftp.rmdir('testdir')
				#if err is not None:
				#	raise err
				#
				#_, err = await sftp.rmdir('testdir')
				#if err is not None:
				#	raise err
				#
				#cwd, err = await sftp.cwd()
				#if err is not None:
				#	raise err
				#print(cwd)

				dire, err = await sftp.opendir('/home')
				if err is not None:
					print(err)
					raise err
				async for entry, err in dire.ls_obj_r():
					if err is not None:
						print(err)
						raise err
					print(entry)

		print('Done!')
	except Exception as e:
		traceback.print_exc()



def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()