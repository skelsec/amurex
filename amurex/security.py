import os
from typing import List, cast

from asysocks.unicomm.common.target import UniProto, UniTarget
from amurex.clientconnection import SSHClientConnection
from amurex.common.settings import SSHClientSettings
from amurex.protocol.messages import SSH_MSG_KEXINIT


async def get_ssh_algos(host:str, port=22, timeout:int=10, proxies:List=None, targetobj:UniTarget = None):
    """Get the supported algorithms for the given host"""
    connection = None
    try:
        if targetobj is None:
            if host is None:
                raise Exception('Either targetobj or host must be provided!')
            targetobj = UniTarget(
                host,
                port,
                UniProto.CLIENT_TCP,
                timeout=timeout,
                proxies=proxies
            )
        
        settings = SSHClientSettings()
        settings.skip_hostkey_verification = True
        connection = SSHClientConnection(None, targetobj, settings)
        server_kex, err = await connection.connect(noauth=True)
        if err is not None:
            raise err
        server_kex = cast(SSH_MSG_KEXINIT, server_kex)
        return server_kex.to_dict(), None
    except Exception as e:
        return None, e
    finally:
        if connection is not None:
            await connection.close()
    
async def get_ssh_auth_methods(host:str, port=22, username:str = None, timeout:int=10, proxies:List=None, targetobj:UniTarget = None):
    """Lists the supported authentication methods for the given host"""
    try:
        connection = None
        if username is None:
            username = 'test_%s' % os.urandom(4).hex()
        if targetobj is None:
            if host is None:
                raise Exception('Either targetobj or host must be provided!')
            targetobj = UniTarget(
                host,
                port,
                UniProto.CLIENT_TCP,
                timeout=timeout,
                proxies=proxies
            )
        
        settings = SSHClientSettings()
        settings.skip_hostkey_verification = True
        connection = SSHClientConnection(None, targetobj, settings)
        server_kex, err = await connection.connect(noauth=True)
        if err is not None:
            raise err
        
        res, err = await connection.list_authentication_methods()
        if err is not None:
            raise err
        return res, None
        
    except Exception as e:
        return None, e
    finally:
        if connection is not None:
            await connection.close()

if __name__ == '__main__':
    import asyncio
    server_kex, err = asyncio.run(get_ssh_algos('127.0.0.1'))
    if err is not None:
        raise err
    
    print(server_kex)
    
    algos, err = asyncio.run(get_ssh_auth_methods('127.0.0.1'))
    if err is not None:
        raise err
    print(algos)