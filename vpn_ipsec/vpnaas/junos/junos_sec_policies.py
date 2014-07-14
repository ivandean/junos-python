'''
Junos Security Policies configuration classes

'''

class SecurityPolicies(object):

    def __init__(self):
        self.policies = []


class NetworkSecurityPolicy(object):

    def __init__(self):
        self.from_zone_name = None
        self.to_zone_name = None
        self.policy_rule = None
        
class PolicyRule(object):
    
    def __init__(self, name):
        self.name = name
        self.match = None
        self.action = None
        
    action_values = ['deny', 'reject', 'permit']
    '''
    Valid values for action field.
    '''
        
class Match(object):
    
    def __init__(self):
        self.source_address = None
        self.destination_address = None
        self.application = None
        
    address_values = ['any', 'any-ipv4', 'any-ipv6']
    '''
    Valid values for source_address and destination_address fields.
    
      <address>            Address from address book or static_nat or
                           incoming_nat address
      [                    Open a set of values
      any                  Any IPv4 or IPv6 address
      any-ipv4             Any IPv4 address
      any-ipv6             Any IPv6 address
    '''
    
    application_values = ['any',
                          'junos-aol',
                          'junos-bgp',
                          'junos-biff',
                          'junos-bootpc',
                          'junos-bootps',
                          'junos-chargen',
                          'junos-cifs',
                          'junos-cvspserver',
                          'junos-dhcp-client',
                          'junos-dhcp-relay',
                          'junos-dhcp-server',
                          'junos-discard',
                          'junos-dns-tcp',
                          'junos-dns-udp',
                          'junos-echo',
                          'junos-finger',
                          'junos-ftp',
                          'junos-gnutella',
                          'junos-gopher',
                          'junos-gre',
                          'junos-gtp',
                          'junos-h323',
                          'junos-http',
                          'junos-http-ext',
                          'junos-https',
                          'junos-icmp-all',
                          'junos-icmp-ping',
                          'junos-icmp6-all',
                          'junos-icmp6-dst-unreach-addr',
                          'junos-icmp6-dst-unreach-admin',
                          'junos-icmp6-dst-unreach-beyond',
                          'junos-icmp6-dst-unreach-port',
                          'junos-icmp6-dst-unreach-route',
                          'junos-icmp6-echo-reply',
                          'junos-icmp6-echo-request',
                          'junos-icmp6-packet-to-big',
                          'junos-icmp6-param-prob-header',
                          'junos-icmp6-param-prob-nexthdr',
                          'junos-icmp6-param-prob-option',
                          'junos-icmp6-time-exceed-reassembly',
                          'junos-icmp6-time-exceed-transit',
                          'junos-ident',
                          'junos-ike',
                          'junos-ike-nat',
                          'junos-imap',
                          'junos-imaps',
                          'junos-internet-locator-service',
                          'junos-irc',
                          'junos-l2tp',
                          'junos-ldap',
                          'junos-ldp-tcp',
                          'junos-ldp-udp',
                          'junos-lpr',
                          'junos-mail',
                          'junos-mgcp',
                          'junos-mgcp-ca',
                          'junos-mgcp-ua',
                          'junos-ms-rpc',
                          'junos-ms-rpc-epm',
                          'junos-ms-rpc-msexchange',
                          'junos-ms-rpc-msexchange-directory-nsp',
                          'junos-ms-rpc-msexchange-directory-rfr',
                          'junos-ms-rpc-msexchange-info-store',
                          'junos-ms-rpc-tcp',
                          'junos-ms-rpc-udp',
                          'junos-ms-sql',
                          'junos-msn',
                          'junos-nbds',
                          'junos-nbname',
                          'junos-netbios-session',
                          'junos-nfs',
                          'junos-nfsd-tcp',
                          'junos-nfsd-udp',
                          'junos-nntp',
                          'junos-ns-global',
                          'junos-ns-global-pro',
                          'junos-nsm',
                          'junos-ntalk',
                          'junos-ntp',
                          'junos-ospf',
                          'junos-pc-anywhere',
                          'junos-persistent-nat',
                          'junos-ping',
                          'junos-pingv6',
                          'junos-pop3',
                          'junos-pptp',
                          'junos-printer',
                          'junos-r2cp',
                          'junos-radacct',
                          'junos-radius',
                          'junos-realaudio',
                          'junos-rip',
                          'junos-routing-inbound',
                          'junos-rsh',
                          'junos-rtsp',
                          'junos-sccp',
                          'junos-sctp-any',
                          'junos-sip',
                          'junos-smb',
                          'junos-smb-session',
                          'junos-smtp',
                          'junos-snmp-agentx',
                          'junos-snpp',
                          'junos-sql-monitor',
                          'junos-sqlnet-v1',
                          'junos-sqlnet-v2',
                          'junos-ssh',
                          'junos-stun',
                          'junos-sun-rpc',
                          'junos-sun-rpc-mountd',
                          'junos-sun-rpc-mountd-tcp',
                          'junos-sun-rpc-mountd-udp',
                          'junos-sun-rpc-nfs',
                          'junos-sun-rpc-nfs-access',
                          'junos-sun-rpc-nfs-tcp',
                          'junos-sun-rpc-nfs-udp',
                          'junos-sun-rpc-portmap',
                          'junos-sun-rpc-portmap-tcp',
                          'junos-sun-rpc-portmap-udp',
                          'junos-sun-rpc-status',
                          'junos-sun-rpc-status-tcp',
                          'junos-sun-rpc-status-udp',
                          'junos-sun-rpc-tcp',
                          'junos-sun-rpc-udp',
                          'junos-sun-rpc-ypbind',
                          'junos-sun-rpc-ypbind-tcp',
                          'junos-sun-rpc-ypbind-udp',
                          'junos-syslog',
                          'junos-tacacs',
                          'junos-tacacs-ds',
                          'junos-talk',
                          'junos-tcp-any',
                          'junos-telnet',
                          'junos-tftp',
                          'junos-udp-any',
                          'junos-uucp',
                          'junos-vdo-live',
                          'junos-vnc',
                          'junos-wais',
                          'junos-who',
                          'junos-whois',
                          'junos-winframe',
                          'junos-wxcontrol',
                          'junos-x-windows',
                          'junos-xnm-clear-text',
                          'junos-xnm-ssl',
                          'junos-ymsg'
                         ]
    '''
    Valid values for application field.
    '''
