from amurex.crypto import SSHAlgo

#### TODO: implement this

class SSHKeyAlgo(SSHAlgo):
    def __init__(self, name):
        SSHAlgo.__init__(self, name)



AMUREX_HOST_KEY_ALGORITHMS = {
    'ssh-ed25519' : None,
    'ecdsa-sha2-nistp256' : None, 
    'ecdsa-sha2-nistp384' : None,
    'ecdsa-sha2-nistp521' : None,
    'rsa-sha2-512' : None,
    'rsa-sha2-256' : None,
    'ssh-rsa' : None,
    'ssh-dss' : None,
}