'''
Junos IPSec configuration classes

'''

class SecurityIPsec(object):
    '''
    Security IPsec configuration class. See: http://www.juniper.net/techpubs/
        en_US/junos12.2/information-products/topic-collections/
        junos-xml-ref-config/index.html
    '''

    def __init__(self):
        self.proposal = None
        self.policy = None
        self.vpn = None
        

class IPsecProposal(object):
    '''
    Security IPsec proposal.
    '''
    
    def __init__(self, name):
        self.name = name
        self.protocol = None
        self.authentication_algorithm = None
        self.encryption_algorithm = None
        self.lifetime_seconds = -1
        self.lifetime_kilobytes = -1
        
    protocol_values = ["ah", "esp"]
    '''
    Valid values for protocol field.
    
        ah                   Authentication header
        esp                  Encapsulated Security Payload header
    '''

    authentication_algorithm_values = ["hmac-md5-96", "hmac-sha1-96"]
    '''
    Valid values for authentication_algorithm field.
    
        hmac-md5-96          HMAC-MD5-96 authentication algorithm
        hmac-sha1-96         HMAC-SHA1-96 authentication algorithm
    '''
   
            
    encryption_algorithm_values = [
                                   "3des-cbc",
                                   "aes-128-cbc",
                                   "aes-192-cbc",
                                   "aes-256-cbc",
                                   "des-cbc"
                                  ]
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
    lifetime_kilobytes_min_value = 64
    lifetime_kilobytes_max_value = 4294967294
         
class IPsecPolicy(object):
    '''
    Security IPsec policy.
    '''
    
    def __init__(self, name):
        self.name = name
        self.proposals = []


class IPsecVPN(object):
    '''
    Security IPsec VPN.
    '''
    
    def __init__(self, name):
        self.name = name
        self.bind_interface = None
        self.ike = None
        self.establish_tunnels = None
        
    establish_tunnels_values = ["immediately", "on-traffic"]
    '''
    Valid values for establish_tunnels field.
    
        immediately          Establish tunnels immediately
        on-traffic           Establish tunnels on traffic
    '''


class IPsecVPNIKE(object):
    '''
    IKE.
    '''
    
    def __init__(self):
        self.gateway = None
        self.proxy_identity = None
        self.ipsec_policy = None
        
class ProxyIdentity(object):
    '''
    Proxy Identity
    '''
    
    def __init__(self):
        self.local = None
        self.remote = None
        self.service = None
        
    service_values = [
        "TCP-15203",
        "TCP-3010",
        "TCP-55004",
        "TCP-8000",
        "TCP-8004",
        "TCPCOMP",
        "TCP_10000",
        "TCP_10501",
        "TCP_11000-11599",
        "TCP_11100-11200",
        "TCP_11200",
        "TCP_13200",
        "TCP_13220",
        "TCP_13230",
        "TCP_14230",
        "TCP_14240",
        "TCP_15203",
        "TCP_16000-17000",
        "TCP_16272",
        "TCP_16700",
        "TCP_16827",
        "TCP_16869",
        "TCP_16920",
        "TCP_17000-18000",
        "TCP_17467",
        "TCP_17481",
        "TCP_17599",
        "TCP_17600",
        "TCP_17600-17800",
        "TCP_17605",
        "TCP_17630",
        "TCP_17648",
        "TCP_17668",
        "TCP_17687",
        "TCP_17700",
        "TCP_2000-4000",
        "TCP_20055",
        "TCP_20068",
        "TCP_2010-2030",
        "TCP_22",
        "TCP_2270",
        "TCP_2275",
        "TCP_2775",
        "TCP_2775-3775",
        "TCP_3000-4000",
        "TCP_30000",
        "TCP_30000-40000",
        "TCP_3001",
        "TCP_3010",
        "TCP_31115",
        "TCP_3339",
        "TCP_3600",
        "TCP_3700-3900",
        "TCP_3706",
        "TCP_3710",
        "TCP_3750-3755",
        "TCP_3901",
        "TCP_3928",
        "TCP_3980",
        "TCP_4000",
        "TCP_5000",
        "TCP_5000-6000",
        "TCP_5003",
        "TCP_5005",
        "TCP_5010",
        "TCP_5015",
        "TCP_5016",
        "TCP_5017",
        "TCP_5018",
        "TCP_5019",
        "TCP_5020",
        "TCP_5022",
        "TCP_5023",
        "TCP_5024",
        "TCP_5042",
        "TCP_5061",
        "TCP_5071",
        "TCP_55001",
        "TCP_6000-7000",
        "TCP_6000-8000",
        "TCP_6006",
        "TCP_6196",
        "TCP_6200",
        "TCP_6692",
        "TCP_6699",
        "TCP_6900",
        "TCP_6928",
        "TCP_6969",
        "TCP_7000_8000",
        "TCP_7004",
        "TCP_7234",
        "TCP_7500-7600",
        "TCP_7523",
        "TCP_7535",
        "TCP_7536",
        "TCP_7902",
        "TCP_8000-9000",
        "TCP_8008",
        "TCP_8010",
        "TCP_8046",
        "TCP_8089",
        "TCP_8098",
        "TCP_8224",
        "TCP_8253",
        "TCP_8400",
        "TCP_8401",
        "TCP_8500",
        "TCP_8600",
        "TCP_8700",
        "TCP_8900-9100",
        "TCP_9000-10000",
        "TCP_9025",
        "TCP_9072",
        "TCP_9400",
        "TCP_9401",
        "TCP_9600-9700",
        "TCP_9742",
        "TCP_9877",
        "TCP_9886",
        "TCP_9887",
        "TCP_ALL",
        "UDP_3000_4000",
        "any",
        "junos-aol",
        "junos-bgp",
        "junos-biff",
        "junos-bootpc",
        "junos-bootps",
        "junos-chargen",
        "junos-cvspserver",
        "junos-dhcp-client",
        "junos-dhcp-relay",
        "junos-dhcp-server",
        "junos-discard",
        "junos-dns-tcp",
        "junos-dns-udp",
        "junos-echo",
        "junos-finger",
        "junos-ftp",
        "junos-gnutella",
        "junos-gopher",
        "junos-gprs-gtp-c",
        "junos-gprs-gtp-c-tcp",
        "junos-gprs-gtp-c-udp",
        "junos-gprs-gtp-u",
        "junos-gprs-gtp-u-tcp",
        "junos-gprs-gtp-u-udp",
        "junos-gprs-gtp-v0",
        "junos-gprs-gtp-v0-tcp",
        "junos-gprs-gtp-v0-udp",
        "junos-gprs-sctp",
        "junos-gre",
        "junos-h323",
        "junos-http",
        "junos-http-ext",
        "junos-https",
        "junos-icmp-all",
        "junos-icmp-ping",
        "junos-icmp6-all",
        "junos-icmp6-dst-unreach-addr",
        "junos-icmp6-dst-unreach-admin",
        "junos-icmp6-dst-unreach-beyond",
        "junos-icmp6-dst-unreach-port",
        "junos-icmp6-dst-unreach-route",
        "junos-icmp6-echo-reply",
        "junos-icmp6-echo-request",
        "junos-icmp6-packet-to-big",
        "junos-icmp6-param-prob-header",
        "junos-icmp6-param-prob-nexthdr",
        "junos-icmp6-param-prob-option",
        "junos-icmp6-time-exceed-reassembly",
        "junos-icmp6-time-exceed-transit",
        "junos-ident",
        "junos-ike",
        "junos-ike-nat",
        "junos-imap",
        "junos-imaps",
        "junos-internet-locator-service",
        "junos-irc",
        "junos-l2tp",
        "junos-ldap",
        "junos-ldp-tcp",
        "junos-ldp-udp",
        "junos-lpr",
        "junos-mail",
        "junos-mgcp-ca",
        "junos-mgcp-ua",
        "junos-ms-rpc-epm",
        "junos-ms-rpc-iis-com-1",
        "junos-ms-rpc-iis-com-adminbase",
        "junos-ms-rpc-msexchange-directory-nsp",
        "junos-ms-rpc-msexchange-directory-rfr",
        "junos-ms-rpc-msexchange-info-store",
        "junos-ms-rpc-tcp",
        "junos-ms-rpc-udp",
        "junos-ms-rpc-uuid-any-tcp",
        "junos-ms-rpc-uuid-any-udp",
        "junos-ms-rpc-wmic-admin",
        "junos-ms-rpc-wmic-admin2",
        "junos-ms-rpc-wmic-mgmt",
        "junos-ms-rpc-wmic-webm-level1login",
        "junos-ms-sql",
        "junos-msn",
        "junos-nbds",
        "junos-nbname",
        "junos-netbios-session",
        "junos-nfs",
        "junos-nfsd-tcp",
        "junos-nfsd-udp",
        "junos-nntp",
        "junos-ns-global",
        "junos-ns-global-pro",
        "junos-nsm",
        "junos-ntalk",
        "junos-ntp",
        "junos-ospf",
        "junos-pc-anywhere",
        "junos-persistent-nat",
        "junos-ping",
        "junos-pingv6",
        "junos-pop3",
        "junos-pptp",
        "junos-printer",
        "junos-r2cp",
        "junos-radacct",
        "junos-radius",
        "junos-realaudio",
        "junos-rip",
        "junos-rsh",
        "junos-rtsp",
        "junos-sccp",
        "junos-sctp-any",
        "junos-sip",
        "junos-smb",
        "junos-smb-session",
        "junos-smtp",
        "junos-snmp-agentx",
        "junos-snpp",
        "junos-sql-monitor",
        "junos-sqlnet-v1",
        "junos-sqlnet-v2",
        "junos-ssh",
        "junos-stun",
        "junos-sun-rpc-mountd-tcp",
        "junos-sun-rpc-mountd-udp",
        "junos-sun-rpc-nfs-tcp",
        "junos-sun-rpc-nfs-udp",
        "junos-sun-rpc-portmap-tcp",
        "junos-sun-rpc-portmap-udp",
        "junos-sun-rpc-status-tcp",
        "junos-sun-rpc-status-udp",
        "junos-sun-rpc-tcp",
        "junos-sun-rpc-udp",
        "junos-sun-rpc-ypbind-tcp",
        "junos-sun-rpc-ypbind-udp",
        "junos-syslog",
        "junos-tacacs",
        "junos-tacacs-ds",
        "junos-talk",
        "junos-tcp-any",
        "junos-telnet",
        "junos-tftp",
        "junos-udp-any",
        "junos-uucp",
        "junos-vdo-live",
        "junos-vnc",
        "junos-wais",
        "junos-who",
        "junos-whois",
        "junos-winframe",
        "junos-wxcontrol",
        "junos-x-windows",
        "junos-xnm-clear-text",
        "junos-xnm-ssl",
        "junos-ymsg"
        ]
    '''
    Valid values for proxy_identity_service field.
    '''
