import asyncio
from amurex.client import SSHClient

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

def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()