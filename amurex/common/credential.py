from asyauth.common.constants import asyauthProtocol, asyauthSecret, asyauthSubProtocol
from asyauth.common.credentials import UniCredential
from amurex.crypto.keys import SSHKeyAlgo

class SSHCredentialPassword:
    def __init__(self, username, password, domain = None):
        UniCredential.__init__(
			self, 
			secret = password,
			username = username,
			domain = domain,
			stype = asyauthSecret.PASSWORD,
			protocol = asyauthProtocol.PLAIN,
			subprotocol = asyauthSubProtocol.NATIVE)

class SSHCredentialPrivKey:
    def __init__(self, username, privkey, password, domain = None):
        try:
            with open(privkey, 'rb') as f:
                privkey = f.read()
        except:
            pass

        UniCredential.__init__(
			self, 
			secret = privkey,
			username = username,
			domain = domain,
			stype = asyauthSecret.SSHPRIVKEY,
			protocol = asyauthProtocol.PLAIN,
			subprotocol = asyauthSubProtocol.NATIVE)
        self.privkeypass = password

    def build_context(self):
        return SSHKeyAlgo.load_privkey_file_bytes(self.secret, password=self.privkeypass)