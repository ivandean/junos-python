'''
VPNaaS interface

'''

from lxml import etree
from ncclient.xml_ import new_ele, sub_ele

from junos.junos_ipsec import IPsecProposal, IPsecPolicy, IPsecVPNIKE, \
                             ProxyIdentity, IPsecVPN
from junos.junos_ike import IKEProposal, IKEPolicy, DeadPeerDetection, \
    LocalIdentity, IKEGateway
from junos.junos_sec_policies import SecurityPolicies, NetworkSecurityPolicy, \
    PolicyRule, Match
from junos.netconf_client import NetconfClient
from util import config_loader, data_validator, logger_util
from util.xml_parser import XMLParser


host = ''
port = 0
username = ''
password = ''
LOGGER = logger_util.LoggerUtil('debug')
    

def __security_ipsec_filter():
    config_filter = new_ele('configuration')
    sec = sub_ele(config_filter, 'security')
    sub_ele(sec, 'ipsec')
    return config_filter


def __interfaces_filter():
    config_filter = new_ele('configuration')
    sub_ele(config_filter, 'interfaces')
    return config_filter


def __security_policies_filter():
    config_filter = new_ele('configuration')
    sec = sub_ele(config_filter, 'security')
    sub_ele(sec, 'policies')
    return config_filter


def __load_config():
    global host, port, username, password
    
    config_reader = config_loader.ConfigLoader()
    host = config_reader.get_netconf(config_loader.SERVER_HOST)
    port = config_reader.get_netconf(config_loader.SERVER_PORT)
    username = config_reader.get_netconf(config_loader.SERVER_USER)
    password = config_reader.get_netconf(config_loader.SERVER_PASSWORD)


def create_ipsec_tunnel(proposal, policy, vpn):
    """Create an IPsec tunnel.
    
       proposal       has to be defined by add_ipsec_proposal
       policy         has to be defined by add_ipsec_policy
       vpn            has to be defined by add_ipsec_vpn
       
    """
    
    __load_config()
    
    # Field validation
    if proposal is None or not isinstance(proposal, IPsecProposal):
        msg = 'Invalid proposal.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if policy is None or not isinstance(policy, IPsecPolicy):
        msg = 'Invalid policy.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if vpn is None or not isinstance(vpn, IPsecVPN):
        msg = 'Invalid VPN.'
        LOGGER.error(msg)
        raise ValueError(msg)
    
    for proposal_name in policy.proposals:
        if proposal_name != proposal.name:
            msg = 'Policy proposal must be defined: ' + proposal_name
            LOGGER.error(msg)
            raise ValueError(msg)
    
    if vpn.ike.ipsec_policy.name != policy.name:
        msg = 'VPN IKE IPsec policy must be defined: '\
                            + vpn.ike.ipsec_policy.name
        LOGGER.error(msg)
        raise ValueError(msg)
            
    # XML build
    xml_parser = XMLParser(root_tag='security')
    ipsec_leaf = xml_parser.generate_new_subelement(xml_parser.get_root(),
                                                    'ipsec')
    proposal_leaf = xml_parser.generate_new_subelement(ipsec_leaf, 'proposal')
    
    xml_parser.generate_new_subelement(proposal_leaf, 'name', proposal.name)
    xml_parser.generate_new_subelement(proposal_leaf, 'protocol',
                                       proposal.protocol)
    xml_parser.generate_new_subelement(proposal_leaf,
                                       'authentication-algorithm',
                                       proposal.authentication_algorithm)
    xml_parser.generate_new_subelement(proposal_leaf, 'encryption-algorithm',
                                       proposal.encryption_algorithm)
    
    if proposal.lifetime_seconds != -1:
        xml_parser.generate_new_subelement(proposal_leaf, 'lifetime-seconds',
                             str(proposal.lifetime_seconds))
    else:
        xml_parser.generate_new_subelement(proposal_leaf, 'lifetime-kilobytes',
                             str(proposal.lifetime_kilobytes))
        
    policy_leaf = xml_parser.generate_new_subelement(ipsec_leaf, 'policy')
    xml_parser.generate_new_subelement(policy_leaf, 'name', policy.name)
    for p in policy.proposals:
        xml_parser.generate_new_subelement(policy_leaf, 'proposals', p)
        
    vpn_leaf = xml_parser.generate_new_subelement(ipsec_leaf, 'vpn')
    xml_parser.generate_new_subelement(vpn_leaf, 'name', vpn.name)
    xml_parser.generate_new_subelement(vpn_leaf, 'bind-interface',
                                       vpn.bind_interface)
    
    ike_leaf = xml_parser.generate_new_subelement(vpn_leaf, 'ike')
    xml_parser.generate_new_subelement(ike_leaf, 'gateway', vpn.ike.gateway)
    
    proxy_id_leaf = xml_parser.generate_new_subelement(ike_leaf,
                                                       'proxy-identity')
    xml_parser.generate_new_subelement(proxy_id_leaf, 'local',
                                       vpn.ike.proxy_id.local)
    xml_parser.generate_new_subelement(proxy_id_leaf, 'remote',
                                       vpn.ike.proxy_id.remote)
    xml_parser.generate_new_subelement(proxy_id_leaf, 'service',
                                       vpn.ike.proxy_id.service)
    
    xml_parser.generate_new_subelement(ike_leaf, 'ipsec-policy',
                                       vpn.ike.ipsec_policy.name)

    xml_parser.generate_new_subelement(vpn_leaf, 'establish-tunnels',
                                       vpn.establish_tunnels)

    
    # Netconf client calls
    nc_client = NetconfClient(host, port, username, password)
    LOGGER.debug('Sending new configuration:\n' + xml_parser.xml_tostring())
    nc_client.edit_config(xml_parser.get_root())
    

def add_ipsec_proposal(name, protocol, auth_alg, encryp_alg, ttl):
    """Add an IPsec proposal.
    
    protocol
        ah                   Authentication header
        esp                  Encapsulated Security Payload header
    auth_alg
        hmac-md5-96          HMAC-MD5-96 authentication algorithm
        hmac-sha1-96         HMAC-SHA1-96 authentication algorithm
    encryp_alg
        3des-cbc             3DES-CBC encryption algorithm
        aes-128-cbc          AES-CBC 128-bit encryption algorithm
        aes-192-cbc          AES-CBC 192-bit encryption algorithm
        aes-256-cbc          AES-CBC 256-bit encryption algorithm
        des-cbc              DES-CBC encryption algorithm
    ttl
        180..86400 seconds
        or
        64..4294967294 kilobytes
        
    """
    
    __load_config()
        
    # Field validation
    if name is None or len(name) == 0:
        msg = 'Invalid name value.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if protocol not in IPsecProposal.protocol_values:
        msg = 'Invalid protocol value.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if auth_alg not in IPsecProposal.authentication_algorithm_values:
        msg = 'Invalid auth_alg value.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if encryp_alg not in IPsecProposal.encryption_algorithm_values:
        msg = 'Invalid encryp_alg value.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if ttl.endswith(' seconds'):
        try:
            value = int(ttl[:-len(' seconds')], 10)
        except ValueError:
            msg = 'Invalid ttl value. It must be an integer.'
            LOGGER.error(msg)
            raise ValueError(msg)
        if value < IPsecProposal.lifetime_seconds_min_value\
            or value > IPsecProposal.lifetime_seconds_max_value:
            msg = 'Invalid ttl value. It must be between '\
                + IPsecProposal.lifetime_seconds_min_value + ' and '\
                + IPsecProposal.lifetime_seconds_max_value + '.'
            LOGGER.error(msg)
            raise ValueError(msg)
    elif ttl.endswith(' kilobytes'):
        try:
            value = int(ttl[:-len(' kilobytes')], 10)
        except ValueError:
            msg = 'Invalid ttl value. It must be an integer.'
            LOGGER.error(msg)
            raise ValueError(msg)
        if value < IPsecProposal.lifetime_kilobytes_min_value\
            or value > IPsecProposal.lifetime_kilobytes_max_value:
            msg = 'Invalid ttl value. It must be between '\
                + IPsecProposal.lifetime_kilobytes_min_value + ' and '\
                + IPsecProposal.lifetime_kilobytes_max_value + '.'
            LOGGER.error(msg)
            raise ValueError(msg)          
    else:
        msg = 'Invalid ttl value'
        LOGGER.error(msg)
        raise ValueError(msg)
    
    # Previous configuration checking
    nc_client = NetconfClient(host, port, username, password)
    prev_config = nc_client.get_config(__security_ipsec_filter())
    
    prev_config_parser = XMLParser(etree.tostring(prev_config,
                                                  pretty_print=False,
                                                  encoding=unicode))
    prev_props = prev_config_parser.get_elements('security/ipsec/proposal/name')
    for prev_prop in prev_props:
        if prev_prop.text == name:
            msg = 'Proposal name already exists: ' + name
            LOGGER.error(msg)
            raise ValueError(msg)

    # Model build
    iPsecProposal = IPsecProposal(name)
    iPsecProposal.protocol = protocol
    iPsecProposal.authentication_algorithm = auth_alg
    iPsecProposal.encryption_algorithm = encryp_alg
    if ttl.endswith(' seconds'):
        iPsecProposal.lifetime_seconds = int(ttl[:-len(' seconds')], 10)
    else:
        iPsecProposal.lifetime_kilobytes = int(ttl[:-len(' kilobytes')], 10)
        
    
    return iPsecProposal
    
    
def add_ipsec_policy(name, proposal_name):
    """Add IPsec policy.
    
    name
    proposal_name   has to be defined by add_ipsec_proposal
    
    """
    
    __load_config()
    
    # Field validation
    if name is None or name is "":
        msg = 'Invalid policy name.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if proposal_name is None or proposal_name is "":
        msg = 'Invalid proposal name.'
        LOGGER.error(msg)
        raise ValueError(msg)

    # Model build
    iPsecPolicy = IPsecPolicy(name)
    iPsecPolicy.proposals.append(proposal_name)


    return iPsecPolicy

    
def add_ipsec_vpn(name, bind_intf, ike, establish_tunnels):
    """Add IPsec VPN.
    
    ike                      has to be defined by add_ipsec_ike
    establish_tunnels
        immediately          Establish tunnels immediately
        on-traffic           Establish tunnels on traffic
    
    """
    
    __load_config()
    
    # Field validation
    if name is None or name is "":
        msg = 'Invalid name.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if bind_intf is None or bind_intf is "":
        msg = 'Invalid bind interface.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if ike is None or not isinstance(ike, IPsecVPNIKE):
        msg = 'Invalid IKE.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if establish_tunnels not in IPsecVPN.establish_tunnels_values:
        msg = 'Invalid establish_tunnels value.'
        LOGGER.error(msg)
        raise ValueError(msg)

    
    # Previous configuration checking
    nc_client = NetconfClient(host, port, username, password)
    prev_config = nc_client.get_config(__interfaces_filter())
    
    prev_config_parser = XMLParser(etree.tostring(prev_config,
                                                  pretty_print=False,
                                                  encoding=unicode))
    current_interfaces = prev_config_parser.get_elements(
                                        'interfaces/interface/name')
    found = False
    for interface in current_interfaces:
        if interface.text == bind_intf:
            found = True
            break
    
    if not found:
        msg = 'Bind interface does not exists: ' + bind_intf
        LOGGER.error(msg)
        raise ValueError(msg)

    # Model build
    iPsecVPN = IPsecVPN(name)
    iPsecVPN.bind_interface = bind_intf
    iPsecVPN.ike = ike
    iPsecVPN.establish_tunnels = establish_tunnels


    return iPsecVPN


def add_ipsec_ike(gateway, proxy_id, ipsec_policy):
    """Add IPsec IKE.
    
    proxy_id            has to be defined by add_ipsec_proxy_id
    ipsec_policy        has to be defined by add_ipsec_policy
    """
    
    __load_config()
   
    # Field validation
    if gateway is None or gateway is "":
        msg = 'Invalid gateway.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if proxy_id is None or not isinstance(proxy_id, ProxyIdentity):
        msg = 'Invalid proxy ID.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if ipsec_policy is None or ipsec_policy is "":
        msg = 'Invalid IPsec policy.'
        LOGGER.error(msg)
        raise ValueError(msg)

    # Model build
    iPsecVPNIKE = IPsecVPNIKE()
    iPsecVPNIKE.gateway = gateway
    iPsecVPNIKE.proxy_id = proxy_id
    iPsecVPNIKE.ipsec_policy = ipsec_policy


    return iPsecVPNIKE


def add_ipsec_proxy_id(local_ip, remote_ip, service):
    """Add IPsec proxy ID.
    
    service  Name of serivce that passes through, any enables all services
    
    """
    
    __load_config()
   
    # Field validation
    if local_ip is None or not data_validator.valid_ip_cidr(local_ip):
        msg = 'Invalid local IP address.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if remote_ip is None or not data_validator.valid_ip_cidr(remote_ip):
        msg = 'Invalid remote IP address.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if service not in ProxyIdentity.service_values:
        msg = 'Invalid service.'
        LOGGER.error(msg)
        raise ValueError(msg)

    # Model build
    proxyIdentity = ProxyIdentity()
    proxyIdentity.local = local_ip
    proxyIdentity.remote = remote_ip
    proxyIdentity.service = service

    return proxyIdentity


def create_ike(proposal, policy, gateway):
    """Create IKE.
    
    proposal    has to be defined by add_ike_proposal
    policy      has to be defined by add_ike_policy
    gateway     has to be defined by add_ike_gateway
    
    """
   
    __load_config()
    
    # Field validation
    if proposal is None or not isinstance(proposal, IKEProposal):
        msg = 'Invalid proposal.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if policy is None or not isinstance(policy, IKEPolicy):
        msg = 'Invalid policy.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if gateway is None or not isinstance(gateway, IKEGateway):
        msg = 'Invalid gateway.'
        LOGGER.error(msg)
        raise ValueError(msg)
    
    for proposal_name in policy.proposals:
        if proposal_name != proposal.name:
            msg = 'Policy proposal must be defined: ' + proposal_name
            LOGGER.error(msg)
            raise ValueError(msg)
    
    if gateway.ike_policy != policy.name:
        msg = 'IKE policy must be defined: ' + gateway.ipsec_policy.name
        LOGGER.error(msg)
        raise ValueError(msg)
            
    # XML build
    xml_parser = XMLParser(root_tag='security')
    ike_leaf = xml_parser.generate_new_subelement(xml_parser.get_root(), 'ike')
    proposal_leaf = xml_parser.generate_new_subelement(ike_leaf, 'proposal')
    
    xml_parser.generate_new_subelement(proposal_leaf, 'name', proposal.name)
    xml_parser.generate_new_subelement(proposal_leaf, 'authentication-method',
                                       proposal.authentication_method)
    xml_parser.generate_new_subelement(proposal_leaf, 'dh-group',
                                       proposal.dh_group)
    xml_parser.generate_new_subelement(proposal_leaf,
                                       'authentication-algorithm',
                                       proposal.authentication_algorithm)
    xml_parser.generate_new_subelement(proposal_leaf, 'encryption-algorithm',
                                       proposal.encryption_algorithm)
    xml_parser.generate_new_subelement(proposal_leaf, 'lifetime-seconds',
                             str(proposal.lifetime_seconds))
        
    policy_leaf = xml_parser.generate_new_subelement(ike_leaf, 'policy')
    xml_parser.generate_new_subelement(policy_leaf, 'name', policy.name)
    xml_parser.generate_new_subelement(policy_leaf, 'mode', policy.mode)
    for p in policy.proposals:
        xml_parser.generate_new_subelement(policy_leaf, 'proposals', p)
        
    pre_shared_key_leaf = xml_parser.generate_new_subelement(policy_leaf,
                                                             'pre-shared-key')
    # FIXME set pre-shared-key based on his type
    if True:
        xml_parser.generate_new_subelement(pre_shared_key_leaf, 'ascii-text',
                                           policy.pre_shared_key)
    else:
        xml_parser.generate_new_subelement(pre_shared_key_leaf, 'hexadecimal',
                                           policy.pre_shared_key)
    
    gateway_leaf = xml_parser.generate_new_subelement(ike_leaf, 'gateway')
    xml_parser.generate_new_subelement(gateway_leaf, 'name', gateway.name)
    xml_parser.generate_new_subelement(gateway_leaf, 'ike-policy',
                                       gateway.ike_policy)
    xml_parser.generate_new_subelement(gateway_leaf, 'address', gateway.address)
    
    dead_peer_detection_leaf = xml_parser.generate_new_subelement(gateway_leaf,
                                                       'dead-peer-detection')
    if gateway.dead_peer_detection.always_send:
        xml_parser.generate_new_subelement(dead_peer_detection_leaf,
                                           'always-send')
    xml_parser.generate_new_subelement(dead_peer_detection_leaf, 'interval',
                                    str(gateway.dead_peer_detection.interval))
    xml_parser.generate_new_subelement(dead_peer_detection_leaf, 'threshold',
                                    str(gateway.dead_peer_detection.threshold))
    
    local_identity_leaf = xml_parser.generate_new_subelement(gateway_leaf,
                                                       'local-identity')
    
    if gateway.local_identity.distinguished_name:
        xml_parser.generate_new_subelement(local_identity_leaf,
                                           'distinguished-name')
    
    xml_parser.generate_new_subelement(local_identity_leaf, 'hostname',
                                       gateway.local_identity.hostname)
    xml_parser.generate_new_subelement(local_identity_leaf, 'user-at-hostname',
                                       gateway.local_identity.user_at_hostname)
    
    inet_leaf = xml_parser.generate_new_subelement(local_identity_leaf, 'inet')
    if gateway.local_identity.inet is not None:
        xml_parser.generate_new_subelement(inet_leaf, 'identity-ipv4',
                                           gateway.local_identity.inet)
    elif gateway.local_identity.inet6 is not None:
        xml_parser.generate_new_subelement(inet_leaf, 'identity-ipv6',
                                           gateway.local_identity.inet6)
    
    xml_parser.generate_new_subelement(gateway_leaf, 'external-interface',
                                       gateway.external_interface)
    
    # Netconf client calls
    nc_client = NetconfClient(host, port, username, password)
    LOGGER.debug('Sending new configuration:\n' + xml_parser.xml_tostring())
    nc_client.edit_config(xml_parser.get_root())
    

def add_ike_proposal(name, auth_method, dh_group, auth_alg, encryp_alg, ttl):
    """Add IKE proposal.
    
    auth_alg
      md5                  MD5 authentication algorithm
      sha-256              SHA 256-bit authentication algorithm
      sha1                 SHA1 authentication algorithm

    dh_group
      group1               Diffie-Hellman Group 1
      group14              Diffie-Hellman Group 14
      group2               Diffie-Hellman Group 2
      group5               Diffie-Hellman Group 5

    auth_method
      dsa-signatures       DSA signatures
      pre-shared-keys      Preshared keys
      rsa-signatures       RSA signatures

    encryp_alg
      3des-cbc             3DES-CBC encryption algorithm
      aes-128-cbc          AES-CBC 128-bit encryption algorithm
      aes-192-cbc          AES-CBC 192-bit encryption algorithm
      aes-256-cbc          AES-CBC 256-bit encryption algorithm
      des-cbc              DES-CBC encryption algorithm

    ttl
      180..86400 seconds
      
    """
    
    __load_config()
   
    # Field validation
    if name is None or name is "":
        msg = 'Invalid name.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if auth_method not in IKEProposal.authentication_method_values:
        msg = 'Invalid authentication method.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if dh_group not in IKEProposal.dh_group_values:
        msg = 'Invalid DH group.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if auth_alg not in IKEProposal.authentication_algorithm_values:
        msg = 'Invalid authentication algorithm.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if encryp_alg not in IKEProposal.encryption_algorithm_values:
        msg = 'Invalid encryption algorithm.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if ttl is None:
        msg = 'Invalid service.'
        LOGGER.error(msg)
        raise ValueError(msg)
    else:
        if ttl < IKEProposal.lifetime_seconds_min_value\
            or ttl > IKEProposal.lifetime_seconds_max_value:
            msg = 'Invalid ttl value. It must be between '\
                + IKEProposal.lifetime_seconds_min_value + ' and '\
                + IKEProposal.lifetime_seconds_max_value + '.'
            LOGGER.error(msg)
            raise ValueError(msg)          

    # Model build
    ikeProposal = IKEProposal(name)
    ikeProposal.authentication_method = auth_method
    ikeProposal.dh_group = dh_group
    ikeProposal.authentication_algorithm = auth_alg
    ikeProposal.encryption_algorithm = encryp_alg
    ikeProposal.lifetime_seconds = ttl

    return ikeProposal


def add_ike_policy(name, mode, proposal_name, preshared_key):
    """Add IKE policy.
    
    mode
      aggressive           Aggressive mode
      main                 Main mode

    preshared_key
      ascii-text           Format as text
      hexadecimal          Format as hexadecimal
      
    """
    
    __load_config()
   
    # Field validation
    if name is None or name is "":
        msg = 'Invalid name.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if mode not in IKEPolicy.mode_values:
        msg = 'Invalid mode.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if proposal_name is None or proposal_name is "":
        msg = 'Invalid proposal name.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if preshared_key is None or preshared_key is "" \
        or data_validator.isAscii(preshared_key) \
        and data_validator.isHexadecimal(preshared_key):
        # TODO check key type and validity
        msg = 'Invalid preshared key.'
        LOGGER.error(msg)
        raise ValueError(msg)    

    # Model build
    ikePolicy = IKEPolicy(name)
    ikePolicy.mode = mode
    ikePolicy.proposal_name = proposal_name
    ikePolicy.pre_shared_key = preshared_key

    return ikePolicy


def add_ike_gateway(name, ike_policy, address, dead_peer_detection, local_id,
                    ext_intf):
    """Add IKE gateway.
    
    dead_peer_detection
        always-send          Send DPD messages periodically, regardless of
                             traffic
        interval             The interval at which to send DPD messages
                             (10..60 seconds)
        threshold            Maximum number of DPD retransmissions (1..5)
    local_id
        distinguished-name   Use a distinguished name specified in local
                             certificate
        hostname             Use a fully-qualified domain name
        inet                 Use an IPv4 address
        inet6                Use an IPv6 address
        user-at-hostname     Use an e-mail address
        
    """
       
    __load_config()
   
    # Field validation
    if ike_policy is None or ike_policy is "":
        msg = 'Invalid ike policy.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if address is None or not data_validator.valid_ip(address):
        msg = 'Invalid address.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if dead_peer_detection is None\
        or not isinstance(dead_peer_detection, DeadPeerDetection):
        msg = 'Invalid dead peer detection.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if local_id is None\
        or not isinstance(local_id, LocalIdentity):
        msg = 'Invalid local id.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if ext_intf is None or ext_intf is "":
        msg = 'Invalid external interface.'
        LOGGER.error(msg)
        raise ValueError(msg)
    
    # Previous configuration checking
    nc_client = NetconfClient(host, port, username, password)
    prev_config = nc_client.get_config(__interfaces_filter())
    
    prev_config_parser = XMLParser(etree.tostring(prev_config,
                                                  pretty_print=False,
                                                  encoding=unicode))
    current_interfaces = prev_config_parser.get_elements(
                                        'interfaces/interface/name')
    found = False
    for interface in current_interfaces:
        if interface.text == ext_intf:
            found = True
            break
    
    if not found:
        msg = 'External interface does not exists: ' + ext_intf
        LOGGER.error(msg)
        raise ValueError(msg)

    # Model build
    ikeGateway = IKEGateway(name)
    ikeGateway.ike_policy = ike_policy
    ikeGateway.address = address
    ikeGateway.dead_peer_detection = dead_peer_detection
    ikeGateway.local_identity = local_id
    ikeGateway.external_interface = ext_intf

    return ikeGateway


def generate_ike_key():
    """ Generate IKE key."""
    
    config_reader = config_loader.ConfigLoader()
    return config_reader.get_ike(config_loader.PRE_SHARED_KEY)
    

def create_sec_policies(from_zone_name, to_zone_name, policy_rule):
    """Create security policies.
    
    from_zone_name
    to_zone_name
    policy_name
    
    """
    
    __load_config()

    # Field validation
    if from_zone_name is None or from_zone_name is "":
        msg = 'Invalid "From Zone Name".'
        LOGGER.error(msg)
        raise ValueError(msg)
    if to_zone_name is None or to_zone_name is "":
        msg = 'Invalid "To Zone Name".'
        LOGGER.error(msg)
        raise ValueError(msg)
    if policy_rule is None\
        or not isinstance(policy_rule, PolicyRule):
        msg = 'Invalid policy_rule.'
        LOGGER.error(msg)
        raise ValueError(msg)

    # Model build
    networkSecurityPolicy = NetworkSecurityPolicy()
    networkSecurityPolicy.from_zone_name = from_zone_name
    networkSecurityPolicy.to_zone_name = to_zone_name
    networkSecurityPolicy.policy_rule = policy_rule

    securityPolicies = SecurityPolicies()
    securityPolicies.policies.append(networkSecurityPolicy)

    # XML build
    xml_parser = XMLParser(root_tag='security')
    policies_leaf = xml_parser.generate_new_subelement(xml_parser.get_root(),
                                                    'policies')
    for nsp in securityPolicies.policies:
        policy_leaf_out = xml_parser.generate_new_subelement(policies_leaf,
                                                             'policy')
        xml_parser.generate_new_subelement(policy_leaf_out, 'from-zone-name',
            nsp.from_zone_name)
        xml_parser.generate_new_subelement(policy_leaf_out, 'to-zone-name',
            nsp.to_zone_name)

        policy_leaf_in = xml_parser.generate_new_subelement(policy_leaf_out,
                                                            'policy')
        xml_parser.generate_new_subelement(policy_leaf_in, 'name',
                                           nsp.policy_rule.name)

        match_leaf = xml_parser.generate_new_subelement(policy_leaf_in, 
                                                        'match')
        xml_parser.generate_new_subelement(match_leaf, 'source-address',
            nsp.policy_rule.match.source_address)
        xml_parser.generate_new_subelement(match_leaf, 'destination-address',
            nsp.policy_rule.match.destination_address)
        xml_parser.generate_new_subelement(match_leaf, 'application',
            nsp.policy_rule.match.application)

        then_leaf = xml_parser.generate_new_subelement(policy_leaf_in, 'then')
        xml_parser.generate_new_subelement(then_leaf, nsp.policy_rule.action)

    # Netconf client calls
    nc_client = NetconfClient(host, port, username, password)
    LOGGER.debug('Sending new configuration:\n' + xml_parser.xml_tostring())
    nc_client.edit_config(xml_parser.get_root())


def add_sec_policy_rule(name, source_addr, destination_addr, app_type, action):
    """Add security policy rule.
    
    name
    source_addr
    destination_addr
    app_type
    action
    
    """
    
    __load_config()

    # Field validation
    if name is None or name is "":
        msg = 'Invalid name.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if source_addr is None or not data_validator.valid_ip_cidr(source_addr) \
        and source_addr not in Match.address_values:
        msg = 'Invalid source address.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if destination_addr is None \
        or not data_validator.valid_ip_cidr(destination_addr) \
        and destination_addr not in Match.address_values:
        msg = 'Invalid destination address.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if app_type not in Match.application_values:
        msg = 'Invalid application value.'
        LOGGER.error(msg)
        raise ValueError(msg)
    if action not in PolicyRule.action_values:
        msg = 'Invalid action value.'
        LOGGER.error(msg)
        raise ValueError(msg)

    # Model build
    match = Match()
    match.source_address = source_addr
    match.destination_address = destination_addr
    match.application = app_type

    policyRule = PolicyRule(name)
    policyRule.match = match
    policyRule.action = action

    return policyRule
