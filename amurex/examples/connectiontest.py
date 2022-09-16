import asyncio
import sys
from amurex.common.settings import SSHClientSettings
from amurex.common.credential import SSHCredentialPrivKey
from amurex.common.credential import SSHCredentialPassword
from asysocks.unicomm.client import UniClient
from asysocks.unicomm.common.target import UniProto, UniTarget
from asyauth.common.credentials import UniCredential
from asyauth.common.constants import asyauthSecret
from amurex.clientconnection import SSHClientConnection

async def amain():
	async def reader(inq):
		while True:
			data = await inq.get()
			print(data)
	
	async def get_steam_reader(pipe) -> asyncio.StreamReader:
		loop = asyncio.get_event_loop()
		reader = asyncio.StreamReader(loop=loop)
		protocol = asyncio.StreamReaderProtocol(reader)
		await loop.connect_read_pipe(lambda: protocol, pipe)
		return reader

	
	
	credential2 = SSHCredentialPrivKey('webdev', '/home/webdev/.ssh/id_ecdsa', password = 'alma')
	target = UniTarget(
		'127.0.0.1',
		22,
		UniProto.CLIENT_TCP
	)
	credential1 = SSHCredentialPassword('webdev', 'notWorkingPass?!')
	settings = SSHClientSettings()
	settings.known_hosts.load_file('/home/webdev/.ssh/known_hosts')
	#settings.skip_hostkey_verification = True

	sshcli = SSHClientConnection([credential1, credential2], target, settings)
	_, err = await sshcli.connect()
	if err is not None:
		raise err
	print('Connect Done!')
	#await sshcli.open_channel('shell')
	#await sshcli.portforward_dynamic(8080)
	#await sshcli.portforward_local('google.com', 80, '', 8080)
	stdin, stdout, stderr = await sshcli.get_shell()
	x1 = asyncio.create_task(reader(stdout))
	x2 = asyncio.create_task(reader(stderr))
	ui = await get_steam_reader(sys.stdin)
	while True:
		data = await ui.readline()
		print(data)
		await stdin.put(data)

def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()