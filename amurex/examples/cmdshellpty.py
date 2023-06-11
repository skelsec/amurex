import sys
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
	client, err = await SSHClient.connect(
		'127.0.0.1', 
		username = 'webdev', 
		password = 'webdev', 
		verify=False
	)
	if err is not None:
		raise err
	print('Connect Done!')
	
	pty, err = await client.get_ptysession()
	if err is not None:
		raise err
	
	_, err = await pty.get_shell()
	if err is not None:
		raise err
	
	stop_evt = asyncio.Event()
	x1 = asyncio.create_task(reader(pty.stdout, stop_evt))
	x2 = asyncio.create_task(reader(pty.stderr, stop_evt))
	
	
	ui = await get_steam_reader(sys.stdin)
	while not stop_evt.is_set():
		data = await ui.read(1)
		await pty.stdin.put(data)


def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()