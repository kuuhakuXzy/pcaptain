#include <pcap.h>
#include <assert.h>

enum InferBit : uint8_t
{
    BIT_TCP = 1 << 3,  // 1000
    BIT_UDP = 1 << 2,  // 0100
    BIT_SCTP = 1 << 1, // 0010
    BIT_DCCP = 1 << 0  // 0001
};

struct PortInfo {
    uint8_t bits;
    const char* tcp_app;
    const char* udp_app;
    const char* sctp_app;
    const char* dccp_app;
};

inline PortInfo PORT_TABLE[65536];
inline bool PORT_VALID[65536];

inline void set(uint16_t port, uint8_t bits, const char* app) {
    // Optional but strongly recommended: validate bits
    assert(bits & (BIT_TCP | BIT_UDP | BIT_SCTP | BIT_DCCP));

    PortInfo& info = PORT_TABLE[port];

    if (bits & BIT_TCP) {
        info.bits |= BIT_TCP;
        info.tcp_app = app;
    }
    if (bits & BIT_UDP) {
        info.bits |= BIT_UDP;
        info.udp_app = app;
    }
    if (bits & BIT_SCTP) {
        info.bits |= BIT_SCTP;
        info.sctp_app = app;
    }
    if (bits & BIT_DCCP) {
        info.bits |= BIT_DCCP;
        info.dccp_app = app;
    }

    PORT_VALID[port] = true;
}

// I using Wiki for these values. If you find any mistake, please report an issue.
// https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
inline void init_port_table()
{
    // Well-known ports
    // set(1, BIT_TCP, "tcpmux");
    set(7, BIT_TCP | BIT_UDP, "echo");
    set(9, BIT_TCP | BIT_UDP | BIT_SCTP, "discard");
    // set(11, BIT_TCP | BIT_UDP, "systat");
    set(13, BIT_TCP | BIT_UDP, "daytime");
    // set(17, BIT_TCP | BIT_UDP, "qotd");
    // set(18, BIT_TCP | BIT_UDP, "msp");
    set(19, BIT_TCP | BIT_UDP, "chargen");
    set(20, BIT_TCP | BIT_SCTP, "ftp-data");
    set(21, BIT_TCP | BIT_SCTP, "ftp");
    set(22, BIT_TCP | BIT_SCTP, "ssh");
    set(23, BIT_TCP, "telnet");
    // set(24, BIT_TCP, "priv-mail");
    set(25, BIT_TCP, "smtp");
    set(37, BIT_TCP | BIT_UDP, "time");
    // set(42, BIT_UDP, "nameserver");
    set(43, BIT_TCP, "whois");
    set(49, BIT_TCP | BIT_UDP, "tacacs");
    set(53, BIT_TCP | BIT_UDP, "dns");
    set(67, BIT_UDP, "dhcp"); // server
    set(68, BIT_UDP, "dhcp"); // client
    set(69, BIT_UDP, "tftp");
    set(70, BIT_TCP, "gopher");
    // set(71, BIT_TCP | BIT_UDP, "netrjs");
    // set(72, BIT_TCP | BIT_UDP, "netrjs");
    // set(73, BIT_TCP | BIT_UDP, "netrjs");
    // set(74, BIT_TCP | BIT_UDP, "netrjs");
    set(79, BIT_TCP, "finger");
    set(80, BIT_TCP | BIT_UDP | BIT_SCTP, "http");
    set(88, BIT_TCP | BIT_UDP, "kerberos");
    // set(95, BIT_TCP, "supdup");
    // set(101, BIT_TCP, "hostname");
    // set(102, BIT_TCP, "iso-tsap");
    set(104, BIT_TCP | BIT_UDP, "dicom");
    // set(105, BIT_TCP, "csnet-ns");
    // set(107, BIT_TCP | BIT_UDP, "rtelnet");
    // set(108, BIT_TCP | BIT_UDP, "snagas");
    set(109, BIT_TCP, "pop");
    set(110, BIT_TCP, "pop");
    // set(111, BIT_TCP | BIT_UDP, "rpcbind");
    // set(112, BIT_TCP | BIT_UDP, "mcidas");
    // set(113, BIT_TCP, "ident");
    set(115, BIT_TCP, "sftp");
    // set(117, BIT_TCP | BIT_UDP, "uucp-path");
    // set(118, BIT_TCP | BIT_UDP, "sql");
    set(119, BIT_TCP, "nntp");
    set(123, BIT_UDP, "ntp");
    // set(126, BIT_TCP | BIT_UDP, "lmsocialserver");
    // set(135, BIT_TCP | BIT_UDP, "epmap");
    // set(137, BIT_TCP | BIT_UDP, "netbios-ns");
    // set(138, BIT_UDP, "netbios-dgm");
    // set(139, BIT_TCP, "netbios-ssn");
    set(143, BIT_TCP, "imap");
    // set(152, BIT_TCP | BIT_UDP, "bftp");
    set(153, BIT_TCP | BIT_UDP, "sgmp");
    // set(156, BIT_TCP | BIT_UDP, "sqlsrv");
    set(161, BIT_UDP, "snmp");
    // set(162, BIT_TCP | BIT_UDP, "snmptrap");
    // set(170, BIT_TCP | BIT_UDP, "print-srv");
    // set(175, BIT_TCP | BIT_UDP, "vmnet");
    set(177, BIT_TCP | BIT_UDP, "xdmcp");
    set(179, BIT_TCP | BIT_SCTP, "bgp");
    set(194, BIT_TCP | BIT_UDP, "irc");
    set(199, BIT_TCP | BIT_UDP, "smux");
    // set(201, BIT_TCP | BIT_UDP, "at-rtmp");
    // set(209, BIT_TCP, "qmtp");
    // set(210, BIT_TCP | BIT_UDP, "z39.50");
    set(213, BIT_TCP | BIT_UDP, "ipx");
    // set(218, BIT_TCP | BIT_UDP, "mpp");
    // set(220, BIT_TCP | BIT_UDP, "imap3");
    // set(259, BIT_TCP | BIT_UDP, "esro-gen");
    // set(262, BIT_TCP | BIT_UDP, "arcisdms");
    // set(264, BIT_TCP | BIT_UDP, "bgmp");
    // set(280, BIT_TCP | BIT_UDP, "http-mgmt");
    // set(308, BIT_TCP | BIT_UDP, "novastorbakcup");
    // set(311, BIT_TCP, "asip-webadmin");
    // set(318, BIT_TCP | BIT_UDP, "pkix-timestamp");
    set(319, BIT_UDP, "ptp"); // event
    set(320, BIT_UDP, "ptp"); // general
    // set(323, BIT_TCP, "rpki");
    // set(350, BIT_TCP | BIT_UDP, "matip-type-a");
    // set(351, BIT_TCP | BIT_UDP, "matip-type-b");
    // set(356, BIT_TCP | BIT_UDP, "cloanto-net-1");
    // set(366, BIT_TCP | BIT_UDP, "odmr");
    // set(369, BIT_TCP | BIT_UDP, "rpc2portmap");
    // set(370, BIT_TCP | BIT_UDP, "codaauth2");
    set(371, BIT_TCP | BIT_UDP, "clearcase");
    // set(376, BIT_TCP | BIT_UDP, "amiganetfs");
    // set(383, BIT_TCP | BIT_UDP, "hp-collector");
    // set(384, BIT_TCP | BIT_UDP, "hp-managed-node");
    // set(387, BIT_TCP | BIT_UDP, "aurp");
    // set(388, BIT_TCP, "unidata-ldm");
    set(389, BIT_TCP, "ldap");
    // set(399, BIT_TCP | BIT_UDP, "iso-tsap-c2");
    // set(401, BIT_TCP | BIT_UDP, "ups");
    // set(427, BIT_TCP | BIT_UDP, "svrloc");
    set(443, BIT_TCP | BIT_UDP | BIT_SCTP, "https");
    // set(444, BIT_TCP | BIT_UDP, "snpp");
    set(445, BIT_TCP | BIT_UDP, "smb");
    set(464, BIT_TCP | BIT_UDP, "kpasswd");
    set(465, BIT_TCP, "smtps");
    set(475, BIT_TCP | BIT_UDP, "tcpnethaspsrv");
    set(497, BIT_TCP | BIT_UDP, "retrospect");
    set(500, BIT_UDP, "isakmp");
    set(502, BIT_TCP | BIT_UDP, "modbus");
    // set(504, BIT_TCP | BIT_UDP, "citadel");
    // set(510, BIT_TCP | BIT_UDP, "admd");
    // set(512, BIT_TCP, "rexec");
    // set(512, BIT_UDP, "biff");
    set(513, BIT_TCP, "rlogin");
    set(513, BIT_UDP, "who");
    set(514, BIT_UDP, "syslog");
    set(515, BIT_TCP, "ldp");
    // set(517, BIT_UDP, "talk");
    // set(518, BIT_UDP, "ntalk");
    set(520, BIT_TCP, "efs");
    set(520, BIT_UDP, "rip");
    set(521, BIT_UDP, "ripng");
    set(524, BIT_TCP | BIT_UDP, "ncp");
    set(530, BIT_TCP | BIT_UDP, "rpc");
    // set(532, BIT_TCP, "netnews");
    // set(533, BIT_UDP, "netwall");
    // set(540, BIT_TCP, "uucp");
    // set(542, BIT_TCP | BIT_UDP, "commerce");
    // set(543, BIT_TCP, "klogin");
    // set(544, BIT_TCP, "kshell");
    set(546, BIT_TCP | BIT_UDP, "dhcpv6"); // client
    set(547, BIT_TCP | BIT_UDP, "dhcpv6"); // server
    set(548, BIT_TCP, "afp");
    // set(550, BIT_TCP | BIT_UDP, "new-rwho");
    set(554, BIT_TCP | BIT_UDP, "rtsp");
    // set(556, BIT_TCP | BIT_UDP, "remotefs");
    // set(560, BIT_UDP, "rmonitor");
    // set(561, BIT_UDP, "monitor");
    // set(563, BIT_TCP | BIT_UDP, "nntps");
    // set(587, BIT_TCP, "submission");
    // set(591, BIT_TCP, "http-alt");
    // set(593, BIT_TCP | BIT_UDP, "http-rpc-epmap");
    // set(601, BIT_TCP | BIT_UDP, "syslog-conn");
    // set(604, BIT_TCP, "tunnel-profile");
    // set(623, BIT_TCP | BIT_UDP, "asf-rmcp");
    set(631, BIT_TCP | BIT_UDP, "ipp");
    // set(635, BIT_TCP | BIT_UDP, "rlzdbase");
    // set(636, BIT_TCP, "ldaps");
    set(639, BIT_TCP | BIT_UDP, "msdp");
    // set(641, BIT_TCP | BIT_UDP, "supportsoft");
    // set(643, BIT_TCP | BIT_UDP, "sanity");
    // set(646, BIT_TCP | BIT_UDP, "ldp-dtls");
    // set(647, BIT_TCP, "dhcp-failover");
    // set(648, BIT_TCP, "rrp");
    // set(651, BIT_TCP | BIT_UDP, "ieee-mms");
    // set(653, BIT_TCP | BIT_UDP, "ssnrc-data"); // SupportSoft Nexus Remote Command (data)
    // set(657, BIT_TCP | BIT_UDP, "ibm-rmc");
    // set(660, BIT_TCP, "mac-srvr-admin");
    // set(662, BIT_TCP | BIT_UDP, "nfsv3-statd");
    // set(666, BIT_TCP | BIT_UDP, "doom");
    set(674, BIT_TCP, "acap");
    // set(684, BIT_TCP | BIT_UDP, "corba-iiop");
    // set(688, BIT_TCP | BIT_UDP, "realm-rusd");
    // set(690, BIT_TCP | BIT_UDP, "vatp");
    // set(691, BIT_TCP, "msexch-routing");
    // set(694, BIT_TCP | BIT_UDP, "ha-cluster"); //Linux-HA high-availability heartbeat 
    // set(695, BIT_TCP | BIT_UDP, "ieee-mms-ssl");
    set(698, BIT_UDP, "olsr");
    // set(700, BIT_TCP, "epp");
    set(701, BIT_TCP, "lmp");
    // set(702, BIT_TCP, "iris-beep");
    // set(706, BIT_TCP, "silc");
    // set(711, BIT_TCP, "cisco-tdp");
    // set(712, BIT_TCP, "tbrpf");
    set(749, BIT_TCP | BIT_UDP, "kerberos");
    set(750, BIT_UDP, "kerberos");
    // set(753, BIT_TCP | BIT_UDP, "rrh");
    // set(754, BIT_TCP | BIT_UDP, "tell");
    // set(800, BIT_TCP | BIT_UDP, "mdbs-daemon");
    set(802, BIT_TCP | BIT_UDP, "modbus");
    set(829, BIT_TCP, "cmp");
    // set(830, BIT_TCP | BIT_UDP, "netconf-ssh");
    // set(831, BIT_TCP | BIT_UDP, "netconf-beep");
    // set(832, BIT_TCP | BIT_UDP, "netconfsoaphttp");
    // set(833, BIT_TCP | BIT_UDP, "netconfsoapbeep");
    // set(847, BIT_TCP, "dhcp-failover2");
    // set(848, BIT_TCP | BIT_UDP, "gdoi");
    set(853, BIT_TCP, "dns"); // over tls
    set(853, BIT_UDP, "dns"); // over quic
    set(860, BIT_TCP, "iscsi");
    // set(861, BIT_TCP | BIT_UDP, "owamp-control");
    set(862, BIT_TCP | BIT_UDP, "twamp.control");
    set(873, BIT_TCP, "rsync");
    // set(892, BIT_TCP | BIT_UDP, "nfsv3-mountd");
    // set(953, BIT_TCP, "rndc");
    // set(989, BIT_TCP | BIT_UDP, "ftps-data");
    // set(990, BIT_TCP | BIT_UDP, "ftps");
    // set(991, BIT_TCP | BIT_UDP, "nas");
    // set(992, BIT_TCP | BIT_UDP, "telnets");
    // set(993, BIT_TCP, "imaps");
    set(995, BIT_TCP | BIT_UDP, "pop");


    // Registered ports
    // set(1027, BIT_UDP, "")
    // set(1058, BIT_TCP | BIT_UDP, "nim");
    // set(1059, BIT_TCP | BIT_UDP, "nimreg");
    set(1080, BIT_TCP | BIT_UDP, "socks");
    // set(1085, BIT_TCP | BIT_UDP, "webobjects");
    // set(1098, BIT_TCP | BIT_UDP, "rmiactivation");
    // set(1099, BIT_TCP, "rmiregistry");
    set(1113, BIT_UDP, "ltp");
    // set(1144, BIT_TCP | BIT_UDP, "fuscript");
    // set(1167, BIT_TCP | BIT_UDP | BIT_SCTP, "cisco-ipsla");
    set(1194, BIT_TCP | BIT_UDP, "openvpn");
    // set(1214, BIT_TCP | BIT_UDP, "kazaa");
    // set(1270, BIT_TCP | BIT_UDP, "scom");
    // set(1293, BIT_TCP | BIT_UDP, "ipsec");
    // set(1319, BIT_TCP | BIT_UDP, "amx-icsp");
    // set(1337, BIT_TCP | BIT_UDP, "menandmice-dns");
    // set(1341, BIT_TCP | BIT_UDP, "qubes");
    set(1344, BIT_TCP | BIT_UDP, "icap");
    set(1352, BIT_TCP | BIT_UDP, "rpc"); // hcl notes/domino
    // set(1360, BIT_TCP | BIT_UDP, "mimer-sql");
    // set(1414, BIT_TCP | BIT_UDP, "mqseries");
    // set(1417, BIT_TCP | BIT_UDP, "timbuktu-svc-1");
    // set(1418, BIT_TCP | BIT_UDP, "timbuktu-svc-2");
    // set(1419, BIT_TCP | BIT_UDP, "timbuktu-svc-3");
    // set(1420, BIT_TCP | BIT_UDP, "timbuktu-svc-4");
    // set(1431, BIT_TCP, "rgtp");
    // set(1443, BIT_TCP | BIT_UDP, "mssql");
    // set(1444, BIT_TCP | BIT_UDP, "mssql");
    // set(1512, BIT_TCP | BIT_UDP, "wins");
    // set(1524, BIT_TCP | BIT_UDP, "ingres");
    // set(1533, BIT_TCP | BIT_UDP, "sqlnet");
    // set(1547, BIT_TCP | BIT_UDP, "laplink");
    // set(1589, BIT_TCP | BIT_UDP, "vqp");
    // set(1701, BIT_TCP | BIT_UDP, "l2f");
    // set(1719, BIT_UDP, "h323q931");
    set(1720, BIT_TCP | BIT_UDP, "h323");
    set(1723, BIT_TCP | BIT_UDP, "pptp");
    // set(1755, BIT_TCP | BIT_UDP, "ms-streaming");
    set(1812, BIT_TCP | BIT_UDP, "radius");
    // set(1813, BIT_TCP | BIT_UDP, "radius-acct");
    // set(1863, BIT_TCP | BIT_UDP, "msnp");
    set(1883, BIT_TCP | BIT_UDP, "mqtt");
    set(1900, BIT_UDP, "ssdp");
    // set(1935, BIT_TCP | BIT_UDP, "");
    set(1985, BIT_TCP | BIT_UDP, "hsrp");
    set(1998, BIT_TCP | BIT_UDP, "xot");
    set(2000, BIT_TCP | BIT_UDP, "sccp");
    set(2049, BIT_TCP | BIT_UDP | BIT_SCTP, "nfs");
    // set(2083, BIT_TCP | BIT_UDP, "radsec");
    set(2123, BIT_TCP | BIT_UDP, "gtp");
    // set(2142, BIT_TCP | BIT_UDP, "tdmoip");
    set(2152, BIT_TCP | BIT_UDP, "gtp");
    // set(2181, BIT_TCP | BIT_UDP, "eforward");
    set(2427, BIT_TCP | BIT_UDP, "mgcp");
    // set(2459, BIT_TCP | BIT_UDP, "xrpl");
    // set(2535, BIT_TCP | BIT_UDP, "madcap");
    // set(2628, BIT_TCP | BIT_UDP, "dict");
    // set(2727, BIT_TCP | BIT_UDP, "mgcp-callagent");
    set(2775, BIT_TCP | BIT_UDP, "smpp");
    // set(3020, BIT_TCP | BIT_UDP, "cifs");
    set(3225, BIT_TCP | BIT_UDP, "fcip");
    set(3478, BIT_TCP | BIT_UDP, "stun");
    set(3689, BIT_TCP | BIT_UDP, "daap");
    // set(3880, BIT_TCP | BIT_UDP, "igrs");
    set(3868, BIT_TCP | BIT_SCTP, "diameter");
    // set(4321, BIT_TCP | BIT_UDP, "rwhois");
    set(4460, BIT_TCP | BIT_UDP, "nts");
    set(4569, BIT_UDP, "iax2");
    // set(4604, BIT_TCP, "irp");
    // set(4753, BIT_TCP | BIT_UDP, "simon");
    set(5004, BIT_TCP | BIT_UDP | BIT_DCCP, "rtp");
    set(5005, BIT_TCP | BIT_UDP | BIT_DCCP, "rtcp");
    set(5060, BIT_TCP | BIT_UDP, "sip");
    set(5061, BIT_TCP, "sip"); // TLS
    set(5246, BIT_UDP, "capwap"); // control
    set(5247, BIT_UDP, "capwap.data"); // data
    set(5269, BIT_TCP, "xmpp"); // server to server
    set(5280, BIT_TCP, "xmpp");
    set(5298, BIT_TCP | BIT_UDP, "xmpp");
    set(5349, BIT_TCP, "stun"); // TLS
    set(5353, BIT_UDP, "mdns");
    // set(5568, BIT_TCP | BIT_UDP, "sdt");
    set(5683, BIT_UDP, "coap");
    set(5684, BIT_TCP, "coap");
    // set(6086, BIT_TCP, "pdtp");
    // set(6513, BIT_TCP, "netconf"); // over tls
    set(6514, BIT_TCP, "syslog"); // over tls
}

inline const PortInfo *lookup_port(uint16_t sport, uint16_t dport)
{
    uint16_t key = sport < dport ? sport : dport;
    return PORT_VALID[key] ? &PORT_TABLE[key] : nullptr;
}

inline const char* lookup_app(const PortInfo* info, uint8_t bit) {
    if (bit == BIT_TCP)  return info->tcp_app;
    if (bit == BIT_UDP)  return info->udp_app;
    if (bit == BIT_SCTP) return info->sctp_app;
    if (bit == BIT_DCCP) return info->dccp_app;
    return nullptr;
}