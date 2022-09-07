from amurex.crypto.keys import SSHKeyAlgo

class SSHKeyRSA(SSHKeyAlgo):
    def __init__(self):
        SSHKeyAlgo.__init__(self, 'ssh-rsa')


class SSHKeyRSA512(SSHKeyAlgo):
    def __init__(self):
        SSHKeyAlgo.__init__(self, 'rsa-sha2-512')