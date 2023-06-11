import traceback
import asyncio
from amurex.client import SSHClient

async def amain():
	try:
		client, err = await SSHClient.connect(
			'127.0.0.1', 
			username = 'webdev', 
			password = 'webdev', 
			verify=False
		)
		if err is not None:
			raise err
		
		async with client:			
			sftp, err = await client.get_sftp()
			if err is not None:
				raise err
			
			async with sftp:
				_, err = await sftp.download('/home/webdev/evil.pdf', '/home/webdev/Desktop/evil.pdf')
				if err is not None:
					raise err

		print('Done!')
	except Exception as e:
		traceback.print_exc()

def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()