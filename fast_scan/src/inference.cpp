#include "inference.hpp"


PortInfo::PortInfo() {
        _apps.fill(nullptr);
    }

void PortInfo::set(L4Proto proto, const char* app) {
    _apps[idx(proto)] = app;
    _valid = true;
}

const char* PortInfo::get(L4Proto proto) const {
    return _apps[idx(proto)];
}

bool PortInfo::valid() const {
    return _valid;
}


// PortTable methods
void PortTable::set(uint16_t port, std::initializer_list<L4Proto> protos, const char* app) {
    PortInfo& info = _table[port];
    for (L4Proto proto : protos) {
        info.set(proto, app);
    }
}

const PortInfo* PortTable::lookup(uint16_t sport, uint16_t dport) const {
    uint16_t key = sport < dport ? sport : dport;
    return _table[key].valid() ? &_table[key] : nullptr;
}


void init_port_table(PortTable& ports) {
    using P = L4Proto;
    // Well-known ports
    // https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
    ports.set(7,{P::TCP, P::UDP }, "echo");
    ports.set(9,{P::TCP, P::UDP, P::SCTP }, "discard");
    // ports.set(11,{P::TCP, P::UDP }, "systat");
    ports.set(13,{P::TCP, P::UDP }, "daytime");
    // ports.set(17,{P::TCP, P::UDP }, "qotd");
    // ports.set(18,{P::TCP, P::UDP }, "msp");
    ports.set(19,{P::TCP, P::UDP }, "chargen");
    ports.set(20,{P::TCP, P::SCTP }, "ftp-data");
    ports.set(21,{P::TCP, P::SCTP }, "ftp");
    ports.set(22,{P::TCP, P::SCTP }, "ssh");
    ports.set(23,{P::TCP }, "telnet");
    // ports.set(24,{P::TCP }, "priv-mail");
    ports.set(25,{P::TCP }, "smtp");
    ports.set(37,{P::TCP, P::UDP }, "time");
    // ports.set(42,{P::UDP }, "nameserver");
    ports.set(43,{P::TCP }, "whois");
    ports.set(49,{P::TCP, P::UDP }, "tacacs");
    ports.set(53,{P::TCP, P::UDP }, "dns");
    ports.set(67,{P::UDP }, "dhcp"); // server
    ports.set(68,{P::UDP }, "dhcp"); // client
    ports.set(69,{P::UDP }, "tftp");
    ports.set(70,{P::TCP }, "gopher");
    // ports.set(71,{P::TCP, P::UDP }, "netrjs");
    // ports.set(72,{P::TCP, P::UDP }, "netrjs");
    // ports.set(73,{P::TCP, P::UDP }, "netrjs");
    // ports.set(74,{P::TCP, P::UDP }, "netrjs");
    ports.set(79,{P::TCP }, "finger");
    ports.set(80,{P::TCP, P::UDP, P::SCTP }, "http");
    ports.set(88,{P::TCP, P::UDP }, "kerberos");
    // ports.set(95,{P::TCP }, "supdup");
    // ports.set(101,{P::TCP }, "hostname");
    // ports.set(102,{P::TCP }, "iso-tsap");
    ports.set(104,{P::TCP, P::UDP }, "dicom");
    // ports.set(105,{P::TCP }, "csnet-ns");
    // ports.set(107,{P::TCP, P::UDP }, "rtelnet");
    // ports.set(108,{P::TCP, P::UDP }, "snagas");
    ports.set(109,{P::TCP }, "pop");
    ports.set(110,{P::TCP }, "pop");
    // ports.set(111,{P::TCP, P::UDP }, "rpcbind");
    // ports.set(112,{P::TCP, P::UDP }, "mcidas");
    // ports.set(113,{P::TCP }, "ident");
    ports.set(115,{P::TCP }, "sftp");
    // ports.set(117,{P::TCP, P::UDP }, "uucp-path");
    // ports.set(118,{P::TCP, P::UDP }, "sql");
    ports.set(119,{P::TCP }, "nntp");
    ports.set(123,{P::UDP }, "ntp");
    // ports.set(126,{P::TCP, P::UDP }, "lmsocialserver");
    // ports.set(135,{P::TCP, P::UDP }, "epmap");
    // ports.set(137,{P::TCP, P::UDP }, "netbios-ns");
    // ports.set(138,{P::UDP }, "netbios-dgm");
    // ports.set(139,{P::TCP }, "netbios-ssn");
    ports.set(143,{P::TCP }, "imap");
    // ports.set(152,{P::TCP, P::UDP }, "bftp");
    ports.set(153,{P::TCP, P::UDP }, "sgmp");
    // ports.set(156,{P::TCP, P::UDP }, "sqlsrv");
    ports.set(161,{P::UDP }, "snmp");
    // ports.set(162,{P::TCP, P::UDP }, "snmptrap");
    // ports.set(170,{P::TCP, P::UDP }, "print-srv");
    // ports.set(175,{P::TCP, P::UDP }, "vmnet");
    ports.set(177,{P::TCP, P::UDP }, "xdmcp");
    ports.set(179,{P::TCP, P::SCTP }, "bgp");
    ports.set(194,{P::TCP, P::UDP }, "irc");
    ports.set(199,{P::TCP, P::UDP }, "smux");
    // ports.set(201,{P::TCP, P::UDP }, "at-rtmp");
    // ports.set(209,{P::TCP }, "qmtp");
    // ports.set(210,{P::TCP, P::UDP }, "z39.50");
    ports.set(213,{P::TCP, P::UDP }, "ipx");
    // ports.set(218,{P::TCP, P::UDP }, "mpp");
    // ports.set(220,{P::TCP, P::UDP }, "imap3");
    // ports.set(259,{P::TCP, P::UDP }, "esro-gen");
    // ports.set(262,{P::TCP, P::UDP }, "arcisdms");
    // ports.set(264,{P::TCP, P::UDP }, "bgmp");
    // ports.set(280,{P::TCP, P::UDP }, "http-mgmt");
    // ports.set(308,{P::TCP, P::UDP }, "novastorbakcup");
    // ports.set(311,{P::TCP }, "asip-webadmin");
    // ports.set(318,{P::TCP, P::UDP }, "pkix-timestamp");
    ports.set(319,{P::UDP }, "ptp"); // event
    ports.set(320,{P::UDP }, "ptp"); // general
    // ports.set(323,{P::TCP }, "rpki");
    // ports.set(350,{P::TCP, P::UDP }, "matip-type-a");
    // ports.set(351,{P::TCP, P::UDP }, "matip-type-b");
    // ports.set(356,{P::TCP, P::UDP }, "cloanto-net-1");
    // ports.set(366,{P::TCP, P::UDP }, "odmr");
    // ports.set(369,{P::TCP, P::UDP }, "rpc2portmap");
    // ports.set(370,{P::TCP, P::UDP }, "codaauth2");
    ports.set(371,{P::TCP, P::UDP }, "clearcase");
    // ports.set(376,{P::TCP, P::UDP }, "amiganetfs");
    // ports.set(383,{P::TCP, P::UDP }, "hp-collector");
    // ports.set(384,{P::TCP, P::UDP }, "hp-managed-node");
    // ports.set(387,{P::TCP, P::UDP }, "aurp");
    // ports.set(388,{P::TCP }, "unidata-ldm");
    ports.set(389,{P::TCP }, "ldap");
    // ports.set(399,{P::TCP, P::UDP }, "iso-tsap-c2");
    // ports.set(401,{P::TCP, P::UDP }, "ups");
    // ports.set(427,{P::TCP, P::UDP }, "svrloc");
    ports.set(443,{P::TCP, P::UDP, P::SCTP }, "https");
    // ports.set(444,{P::TCP, P::UDP }, "snpp");
    ports.set(445,{P::TCP, P::UDP }, "smb");
    ports.set(464,{P::TCP, P::UDP }, "kpasswd");
    ports.set(465,{P::TCP }, "smtps");
    ports.set(475,{P::TCP, P::UDP }, "tcpnethaspsrv");
    ports.set(497,{P::TCP, P::UDP }, "retrospect");
    ports.set(500,{P::UDP }, "isakmp");
    ports.set(502,{P::TCP, P::UDP }, "modbus");
    // ports.set(504,{P::TCP, P::UDP }, "citadel");
    // ports.set(510,{P::TCP, P::UDP }, "admd");
    // ports.set(512,{P::TCP }, "rexec");
    // ports.set(512,{P::UDP }, "biff");
    ports.set(513,{P::TCP }, "rlogin");
    ports.set(513,{P::UDP }, "who");
    ports.set(514,{P::UDP }, "syslog");
    ports.set(515,{P::TCP }, "ldp");
    // ports.set(517,{P::UDP }, "talk");
    // ports.set(518,{P::UDP }, "ntalk");
    ports.set(520,{P::TCP }, "efs");
    ports.set(520,{P::UDP }, "rip");
    ports.set(521,{P::UDP }, "ripng");
    ports.set(524,{P::TCP, P::UDP }, "ncp");
    ports.set(530,{P::TCP, P::UDP }, "rpc");
    // ports.set(532,{P::TCP }, "netnews");
    // ports.set(533,{P::UDP }, "netwall");
    // ports.set(540,{P::TCP }, "uucp");
    // ports.set(542,{P::TCP, P::UDP }, "commerce");
    // ports.set(543,{P::TCP }, "klogin");
    // ports.set(544,{P::TCP }, "kshell");
    ports.set(546,{P::TCP, P::UDP }, "dhcpv6"); // client
    ports.set(547,{P::TCP, P::UDP }, "dhcpv6"); // server
    ports.set(548,{P::TCP }, "afp");
    // ports.set(550,{P::TCP, P::UDP }, "new-rwho");
    ports.set(554,{P::TCP, P::UDP }, "rtsp");
    // ports.set(556,{P::TCP, P::UDP }, "remotefs");
    // ports.set(560,{P::UDP }, "rmonitor");
    // ports.set(561,{P::UDP }, "monitor");
    // ports.set(563,{P::TCP, P::UDP }, "nntps");
    // ports.set(587,{P::TCP }, "submission");
    // ports.set(591,{P::TCP }, "http-alt");
    // ports.set(593,{P::TCP, P::UDP }, "http-rpc-epmap");
    // ports.set(601,{P::TCP, P::UDP }, "syslog-conn");
    // ports.set(604,{P::TCP }, "tunnel-profile");
    // ports.set(623,{P::TCP, P::UDP }, "asf-rmcp");
    ports.set(631,{P::TCP, P::UDP }, "ipp");
    // ports.set(635,{P::TCP, P::UDP }, "rlzdbase");
    // ports.set(636,{P::TCP }, "ldaps");
    ports.set(639,{P::TCP, P::UDP }, "msdp");
    // ports.set(641,{P::TCP, P::UDP }, "supportsoft");
    // ports.set(643,{P::TCP, P::UDP }, "sanity");
    // ports.set(646,{P::TCP, P::UDP }, "ldp-dtls");
    // ports.set(647,{P::TCP }, "dhcp-failover");
    // ports.set(648,{P::TCP }, "rrp");
    // ports.set(651,{P::TCP, P::UDP }, "ieee-mms");
    // ports.set(653,{P::TCP, P::UDP }, "ssnrc-data"); // SupportSoft Nexus Remote Command (data)
    // ports.set(657,{P::TCP, P::UDP }, "ibm-rmc");
    // ports.set(660,{P::TCP }, "mac-srvr-admin");
    // ports.set(662,{P::TCP, P::UDP }, "nfsv3-statd");
    // ports.set(666,{P::TCP, P::UDP }, "doom");
    ports.set(674,{P::TCP }, "acap");
    // ports.set(684,{P::TCP, P::UDP }, "corba-iiop");
    // ports.set(688,{P::TCP, P::UDP }, "realm-rusd");
    // ports.set(690,{P::TCP, P::UDP }, "vatp");
    // ports.set(691,{P::TCP }, "msexch-routing");
    // ports.set(694,{P::TCP, P::UDP }, "ha-cluster"); //Linux-HA high-availability heartbeat 
    // ports.set(695,{P::TCP, P::UDP }, "ieee-mms-ssl");
    ports.set(698,{P::UDP }, "olsr");
    // ports.set(700,{P::TCP }, "epp");
    ports.set(701,{P::TCP }, "lmp");
    // ports.set(702,{P::TCP }, "iris-beep");
    // ports.set(706,{P::TCP }, "silc");
    // ports.set(711,{P::TCP }, "cisco-tdp");
    // ports.set(712,{P::TCP }, "tbrpf");
    ports.set(749,{P::TCP, P::UDP }, "kerberos");
    ports.set(750,{P::UDP }, "kerberos");
    // ports.set(753,{P::TCP, P::UDP }, "rrh");
    // ports.set(754,{P::TCP, P::UDP }, "tell");
    // ports.set(800,{P::TCP, P::UDP }, "mdbs-daemon");
    ports.set(802,{P::TCP, P::UDP }, "modbus");
    ports.set(829,{P::TCP }, "cmp");
    // ports.set(830,{P::TCP, P::UDP }, "netconf-ssh");
    // ports.set(831,{P::TCP, P::UDP }, "netconf-beep");
    // ports.set(832,{P::TCP, P::UDP }, "netconfsoaphttp");
    // ports.set(833,{P::TCP, P::UDP }, "netconfsoapbeep");
    // ports.set(847,{P::TCP }, "dhcp-failover2");
    // ports.set(848,{P::TCP, P::UDP }, "gdoi");
    ports.set(853,{P::TCP }, "dns"); // over tls
    ports.set(853,{P::UDP }, "dns"); // over quic
    ports.set(860,{P::TCP }, "iscsi");
    // ports.set(861,{P::TCP, P::UDP }, "owamp-control");
    ports.set(862,{P::TCP, P::UDP }, "twamp.control");
    ports.set(873,{P::TCP }, "rsync");
    // ports.set(892,{P::TCP, P::UDP }, "nfsv3-mountd");
    // ports.set(953,{P::TCP }, "rndc");
    // ports.set(989,{P::TCP, P::UDP }, "ftps-data");
    // ports.set(990,{P::TCP, P::UDP }, "ftps");
    // ports.set(991,{P::TCP, P::UDP }, "nas");
    // ports.set(992,{P::TCP, P::UDP }, "telnets");
    // ports.set(993,{P::TCP }, "imaps");
    ports.set(995,{P::TCP, P::UDP }, "pop");


    // Registered ports
    // ports.set(1027,{P::UDP }, "")
    // ports.set(1058,{P::TCP, P::UDP }, "nim");
    // ports.set(1059,{P::TCP, P::UDP }, "nimreg");
    ports.set(1080,{P::TCP, P::UDP }, "socks");
    // ports.set(1085,{P::TCP, P::UDP }, "webobjects");
    // ports.set(1098,{P::TCP, P::UDP }, "rmiactivation");
    // ports.set(1099,{P::TCP }, "rmiregistry");
    ports.set(1113,{P::UDP }, "ltp");
    // ports.set(1144,{P::TCP, P::UDP }, "fuscript");
    // ports.set(1167,{P::TCP, P::UDP, P::SCTP }, "cisco-ipsla");
    ports.set(1194,{P::TCP, P::UDP }, "openvpn");
    // ports.set(1214,{P::TCP, P::UDP }, "kazaa");
    // ports.set(1270,{P::TCP, P::UDP }, "scom");
    // ports.set(1293,{P::TCP, P::UDP }, "ipsec");
    // ports.set(1319,{P::TCP, P::UDP }, "amx-icsp");
    // ports.set(1337,{P::TCP, P::UDP }, "menandmice-dns");
    // ports.set(1341,{P::TCP, P::UDP }, "qubes");
    ports.set(1344,{P::TCP, P::UDP }, "icap");
    ports.set(1352,{P::TCP, P::UDP }, "rpc"); // hcl notes/domino
    // ports.set(1360,{P::TCP, P::UDP }, "mimer-sql");
    // ports.set(1414,{P::TCP, P::UDP }, "mqseries");
    // ports.set(1417,{P::TCP, P::UDP }, "timbuktu-svc-1");
    // ports.set(1418,{P::TCP, P::UDP }, "timbuktu-svc-2");
    // ports.set(1419,{P::TCP, P::UDP }, "timbuktu-svc-3");
    // ports.set(1420,{P::TCP, P::UDP }, "timbuktu-svc-4");
    // ports.set(1431,{P::TCP }, "rgtp");
    // ports.set(1443,{P::TCP, P::UDP }, "mssql");
    // ports.set(1444,{P::TCP, P::UDP }, "mssql");
    // ports.set(1512,{P::TCP, P::UDP }, "wins");
    // ports.set(1524,{P::TCP, P::UDP }, "ingres");
    // ports.set(1533,{P::TCP, P::UDP }, "sqlnet");
    // ports.set(1547,{P::TCP, P::UDP }, "laplink");
    // ports.set(1589,{P::TCP, P::UDP }, "vqp");
    // ports.set(1701,{P::TCP, P::UDP }, "l2f");
    // ports.set(1719,{P::UDP }, "h323q931");
    ports.set(1720,{P::TCP, P::UDP }, "h323");
    ports.set(1723,{P::TCP, P::UDP }, "pptp");
    // ports.set(1755,{P::TCP, P::UDP }, "ms-streaming");
    ports.set(1812,{P::TCP, P::UDP }, "radius");
    // ports.set(1813,{P::TCP, P::UDP }, "radius-acct");
    // ports.set(1863,{P::TCP, P::UDP }, "msnp");
    ports.set(1883,{P::TCP, P::UDP }, "mqtt");
    ports.set(1900,{P::UDP }, "ssdp");
    // ports.set(1935,{P::TCP, P::UDP }, "");
    ports.set(1985,{P::TCP, P::UDP }, "hsrp");
    ports.set(1998,{P::TCP, P::UDP }, "xot");
    ports.set(2000,{P::TCP, P::UDP }, "sccp");
    ports.set(2049,{P::TCP, P::UDP, P::SCTP }, "nfs");
    // ports.set(2083,{P::TCP, P::UDP }, "radsec");
    ports.set(2123,{P::TCP, P::UDP }, "gtp");
    // ports.set(2142,{P::TCP, P::UDP }, "tdmoip");
    ports.set(2152,{P::TCP, P::UDP }, "gtp");
    // ports.set(2181,{P::TCP, P::UDP }, "eforward");
    ports.set(2427,{P::TCP, P::UDP }, "mgcp");
    // ports.set(2459,{P::TCP, P::UDP }, "xrpl");
    // ports.set(2535,{P::TCP, P::UDP }, "madcap");
    // ports.set(2628,{P::TCP, P::UDP }, "dict");
    // ports.set(2727,{P::TCP, P::UDP }, "mgcp-callagent");
    ports.set(2775,{P::TCP, P::UDP }, "smpp");
    // ports.set(3020,{P::TCP, P::UDP }, "cifs");
    ports.set(3225,{P::TCP, P::UDP }, "fcip");
    ports.set(3478,{P::TCP, P::UDP }, "stun");
    ports.set(3689,{P::TCP, P::UDP }, "daap");
    // ports.set(3880,{P::TCP, P::UDP }, "igrs");
    ports.set(3868,{P::TCP, P::SCTP }, "diameter");
    // ports.set(4321,{P::TCP, P::UDP }, "rwhois");
    ports.set(4460,{P::TCP, P::UDP }, "nts");
    ports.set(4569,{P::UDP }, "iax2");
    // ports.set(4604,{P::TCP }, "irp");
    // ports.set(4753,{P::TCP, P::UDP }, "simon");
    ports.set(5004,{P::TCP, P::UDP, P::DCCP }, "rtp");
    ports.set(5005,{P::TCP, P::UDP, P::DCCP }, "rtcp");
    ports.set(5060,{P::TCP, P::UDP }, "sip");
    ports.set(5061,{P::TCP }, "sip"); // TLS
    ports.set(5246,{P::UDP }, "capwap"); // control
    ports.set(5247,{P::UDP }, "capwap.data"); // data
    ports.set(5269,{P::TCP }, "xmpp"); // server to server
    ports.set(5280,{P::TCP }, "xmpp");
    ports.set(5298,{P::TCP, P::UDP }, "xmpp");
    ports.set(5349,{P::TCP }, "stun"); // TLS
    ports.set(5353,{P::UDP }, "mdns");
    // ports.set(5568,{P::TCP, P::UDP }, "sdt");
    ports.set(5683,{P::UDP }, "coap");
    ports.set(5684,{P::TCP }, "coap");
    // ports.set(6086,{P::TCP }, "pdtp");
    // ports.set(6513,{P::TCP }, "netconf"); // over tls
    ports.set(6514,{P::TCP }, "syslog"); // over tls
};