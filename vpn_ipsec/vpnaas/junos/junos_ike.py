'''
Junos IKE configuration classes

'''

class SecurityIKE(object):
    '''
    '''

    def __init__(self):
        self.proposal = None
        self.policy = None
        self.gateway = None

class IKEProposal(object):
    '''
    '''

    def __init__(self, name):
        self.name = name
        self.authentication_method = None
        self.dh_group = None
        self.authentication_algorithm = None
        self.encryption_algorithm = None
        self.lifetime_seconds = -1

    authentication_method_values = ["dsa-signatures", "pre-shared-keys",
                                    "rsa-signatures"]
    '''
        Valid values for authentication-method field.
          dsa-signatures       DSA signatures
          pre-shared-keys      Preshared keys
          rsa-signatures       RSA signatures
    '''

    authentication_algorithm_values = ["md5", "sha-256", "sha1"]
    '''
        Valid values for authentication-algorithm field.
          md5                  MD5 authentication algorithm
          sha-256              SHA 256-bit authentication algorithm
          sha1                 SHA1 authentication algorithm
    '''

    dh_group_values = ["group1", "group14", "group2", "group5"]
    '''
        Valid values for dh_group field.
          group1               Diffie-Hellman Group 1
          group14              Diffie-Hellman Group 14
          group2               Diffie-Hellman Group 2
          group5               Diffie-Hellman Group 5
    '''

    encryption_algorithm_values = ["3des-cbc", "aes-128-cbc", "aes-192-cbc",
                                   "aes-256-cbc", "des-cbc"]
    '''
        Valid values for encryption_algorithm field.
          3des-cbc             3DES-CBC encryption algorithm
          aes-128-cbc          AES-CBC 128-bit encryption algorithm
          aes-192-cbc          AES-CBC 192-bit encryption algorithm
          aes-256-cbc          AES-CBC 256-bit encryption algorithm
          des-cbc              DES-CBC encryption algorithm
    '''
    
    lifetime_seconds_min_value = 180
    lifetime_seconds_max_value = 86400

class IKEPolicy(object):
    '''
    '''

    def __init__(self, name):
        self.name = name
        self.mode = None
        self.proposals = []
        self.pre_shared_key = None

    mode_values = ["aggressive", "main"]
    '''
        Valid values for mode field.
          aggressive           Aggressive mode
          main                 Main mode
    '''

    pre_shared_key_types = ["ascii-text", "hexadecimal"]
    '''
        pre_shared_key types.
          ascii-text           Format as text
          hexadecimal          Format as hexadecimal
    '''


class IKEGateway(object):
    '''
    '''

    def __init__(self, name):
        self.name = name
        self.ike_policy = None
        self.address = None
        self.dead_peer_detection = None
        self.local_identity = None
        self.external_interface = None

    '''
        For dead_peer_detection & local_identity see
        models above
    '''

class DeadPeerDetection(object):
    '''
    '''

    def __init__(self):
        self.always_send = False
        self.interval = -1
        self.threshold = -1

class LocalIdentity(object):
    '''
    '''

    def __init__(self):
        self.distinguished_name = False
        self.hostname = None
        self.inet = None
        self.inet6 = None
        self.user_at_hostname = None
