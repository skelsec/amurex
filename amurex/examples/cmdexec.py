import asyncio
from amurex.client import SSHClient

async def amain():
	cmd = 'ls -la /'
	client, err = await SSHClient.from_params(
		'127.0.0.1', 
		username = 'webdev', 
		password = 'webdev', 
		verify=False
	)
	if err is not None:
		raise err
	print('Connect Done!')
	
	stdout, stderr, err = await client.execute_command(cmd)
	if err is not None:
		raise err
	print(stdout)
	print(stderr)
	print('Execute Done!')


def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()