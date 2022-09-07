from amurex.crypto.kex import SSHKEXAlgo

# https://datatracker.ietf.org/doc/html/rfc8731
# https://datatracker.ietf.org/doc/html/rfc5656#section-4
# https://www.rfc-editor.org/rfc/rfc5656

class SSHKEXECDH(SSHKEXAlgo):
    def __init__(self):
        SSHKEXAlgo.__init__(self, 'diffie-hellman-group16-sha512')