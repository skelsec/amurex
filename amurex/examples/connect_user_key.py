import asyncio
from amurex.client import SSHClient

async def amain():
	client, err = await SSHClient.from_params(
		'127.0.0.1', 
	    username='webdev', 
	    private_key='/home/webdev/.ssh/id_rsa',
	    known_hosts='/home/webdev/.ssh/known_hosts', 
	    verify=True
	)
	if err is not None:
		raise err
	print('Connect Done!')

def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()