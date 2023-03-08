
#include "config.h"

#define QICONN_H_GLOBINST
#define READBMP_H_GLOBINST
#include "readbmp/readbmp.h"

#include <signal.h>
#include <string.h> // memset
#include <unistd.h> // close(int fd)

#include <iomanip>

namespace readbmp {
    using namespace std;
    using namespace qiconn;

    map<int,int> attrstats;

    void dump_attrstats (ostream &out, map<int,int> &a) {
out << "-------------------------------------------------" << endl;
	for (map<int,int>::iterator mi = a.begin() ; mi != a.end() ; mi++) {
	    cout << setw(4) << mi->first << " -> " << mi->second << endl;
	}
out << "-------------------------------------------------" << endl;
    }

    class SimpleCPool : public ConnectionPool {
	protected:
	    virtual void treat_signal (void);
	public:
	    SimpleCPool (void) : ConnectionPool () {}
	    virtual ~SimpleCPool () {}
	    virtual int select_poll (struct timeval *timeout) {
		return ConnectionPool::select_poll (timeout);
	    }
	    void askforexit (const char * reason);
    };

    void SimpleCPool::askforexit (const char * reason) {
	exitselect = true;
	time_t t;
	time (&t);
	struct tm tm;
	gmtime_r(&t, &tm);

	cerr 
	    << "[" << setfill('0')
	       << setw(2) << tm.tm_mday << '/'
	       << setw(2) << tm.tm_mon+1 << '/'
	       << setw(4) << tm.tm_year + 1900 << ':'
	       << setw(2) << tm.tm_hour << ':'
	       << setw(2) << tm.tm_min << ':'
	       << setw(2) << tm.tm_sec << "] "
	    << "[CP :-: SimpleCPool] "
	    << " asked to exit : "
	    << reason << endl;
    }

    void SimpleCPool::treat_signal (void) {
int i;
for (i=0 ; i<256 ; i++) {
    if (pend_signals [i] != 0)
	cerr << "got signal " << i << " " << pend_signals [i] << " times" << endl;
}
	if (pend_signals [SIGQUIT] != 0) {
	    askforexit ("got signal SIGQUIT");
	    pend_signals [SIGQUIT] = 0;
	}
	if (pend_signals [SIGINT] != 0) {
	    askforexit ("got signal SIGINT");
	    pend_signals [SIGINT] = 0;
	}
	ConnectionPool::treat_signal();
    } 


    string time_ttos (const time_t &t) {
	char buf[64];
	struct tm tt;
	gmtime_r (&t, &tt);
	strftime (buf, 63, "%Y/%m/%d-%H:%M:%S", &tt);
	return (string) buf;
    }

    class ReadBMP : public SocketConnection {
	public:

	    string message;
	    size_t uncount;

	    typedef enum {
		INHEADER,
		INMESSAGE
	    } RStatus;

	    RStatus rstatus;

	    int h_version;
	    size_t h_msglength;
	    int h_msgtype;

	    int nbmessage;
	    int maxreceivedmessage;
	    int exitfromhere;

	    ReadBMP  (int fd, struct sockaddr_storage const &client_addr)
		: SocketConnection (fd, client_addr),
		uncount(0) ,
		rstatus(INHEADER),
		h_version(0),
		h_msglength(0),
		h_msgtype(0),
		nbmessage(0),
		maxreceivedmessage(1000),
		exitfromhere(0)
	    {
		setrawmode ();
	    }
	    virtual ~ReadBMP (void) {}

	    inline int extract_1B (const unsigned char *p) {
		return (int)(*p);
	    }
	    inline int extract_2B (const unsigned char *p) {
		return (((int)(*p))<<8) + (int)(*(p+1));
	    }
	    inline int extract_4B (const unsigned char *p) {
		return	  (((int)(*(p+0)))<<24)
			+ (((int)(*(p+1)))<<16)
			+ (((int)(*(p+2)))<<8)
			+   (int)(*(p+3));
	    }
	    inline int extract_2Bswapped (const unsigned char *p) {
		return (((int)(*(p+1)))<<8) + (int)(*(p));
	    }
	    inline int extract_4Bswapped (const unsigned char *p) {
		return	  (((int)(*(p+3)))<<24)
			+ (((int)(*(p+2)))<<16)
			+ (((int)(*(p+1)))<<8)
			+   (int)(*(p+0));
	    }
	    inline void extract_IPv4 (const unsigned char *p, struct sockaddr_storage &sin_store) {
		memset (&sin_store, 0, sizeof(sin_store));
		sockaddr_in &sin = *(sockaddr_in *) &sin_store;
		sin.sin_family = AF_INET;
		memcpy (&sin.sin_addr, p, 46);
	    }
	    inline void extract_IPv6 (const unsigned char *p, struct sockaddr_storage &sin_store) {
		memset (&sin_store, 0, sizeof(sin_store));
		sockaddr_in6 &sin = *(sockaddr_in6 *) &sin_store;
		sin.sin6_family = AF_INET6;
		memcpy (&sin.sin6_addr, p, 16);
	    }
	    bool PerPeerIsIPv6 (int flag) {
		return (flag & 0x1) ? true : false;
	    }


	    size_t extract_bgp_head (int &bgp_type, int &bgp_length, size_t offset) {
		if (message.size()-offset<19) {
cerr << "extract_bgp_head error: msg too short" << endl;
                    return message.size();
                }
		unsigned const char *p = (unsigned const char *)message.c_str() + offset;
		bool bgpmarkerisgood = true;
		for (int i=0 ; i<16 ; i++) {
		    if (*(p+i) != 0xff) {
			bgpmarkerisgood = false;
			break;
		    }
		}
		if (bgpmarkerisgood != true) {
cerr << "extract_bgp_head error: bad BGP marker ?!" << endl;
cerr << hexdump(message.substr(offset, 19)) << endl << endl;
		    return message.size();
		}
		bgp_length = extract_2B (p+16);
		bgp_type = extract_1B (p+18);
		return offset + 19;
	    }

	    inline bool bgp_attr_isoptional     (int a) { return (a & 0x80) ? true : false; }
	    inline bool bgp_attr_iswellknown    (int a) { return (a & 0x80) ? false : true; }
	    inline bool bgp_attr_istransitive   (int a) { return (a & 0x40) ? true : false; }
	    inline bool bgp_attr_ispartial      (int a) { return (a & 0x20) ? true : false; }
	    inline bool bgp_attr_isextendedsize (int a) { return (a & 0x10) ? true : false; }

	    string origintos (int o) {
		switch (o) {
		    case 0: return "IGP";
		    case 1: return "EGP";
		    case 2: return "UNKNOWN";
		    default: return "OUTOFRFC4271SCOPE";
		}
	    }

	    size_t extract_bgp_update (int bgp_message_length, size_t offset) {
		if ((int)(message.size()-offset) < bgp_message_length-19) {
cerr << "extract_bgp_update error: msg too short" << endl;
                    return message.size();
		}
		unsigned const char *p = (unsigned const char *)message.c_str() + offset;

		int rlength = extract_2B (p);
		if ((rlength != 0) && (rlength < 4096)) {
cout << "  Withdrawn Routes :" << endl;// << hexdump(message.substr(offset, rlength)) << endl << endl;
		}
		p += 2 + rlength;
		offset += 2 + rlength;

		int alength = extract_2B (p);
		p += 2;
		unsigned const char *q = p + alength;
		if ((alength != 0) && (alength < 4096)) {
cout << "  Path Attribute :" << endl;// << hexdump(message.substr(offset+2, alength)) << endl << endl;
		    if (offset+2+alength > message.size()) {
cerr << "extract_bgp_update Path Attribute error: msg too short" << endl;
			return message.size();
		    }
		    while (p < q) {
			int attr_flags, attr_type, attr_len;
			attr_flags = extract_1B(p); p++;
			attr_type = extract_1B(p); p++;
			if (bgp_attr_isextendedsize(attr_flags))
			    attr_len = extract_2B(p), p+=2;
			else
			    attr_len = extract_1B(p), p++;

			int attr_origin = -1;
			struct sockaddr_storage attr_next_hop;
			unsigned int attr_local_pref, attr_med;
			int attr_originator_id;

			attrstats[attr_type]++;
			switch (attr_type) {

			    case 1: // origin
				attr_origin = extract_1B(p);
				if (attr_len != 1) {
cerr << "extract_bgp_update Path Attribute origin has size not 1 but " << alength << endl;
				}
				p += attr_len;
cout << "          origin: " << origintos(attr_origin) << endl;
				break;

			    case 2: // as_path
//cerr << "          as_path: " << endl << hexdump(message.substr(p-(unsigned const char *)message.c_str(),attr_len)) << endl;
				{
cout << "          aspath: ";
				    unsigned const char *qq = p+attr_len;
				    while (p<qq) {
					int as_path_type = extract_1B(p); p++;
if (as_path_type == 1) /* AS_SET */ cout << " { ";
					int nb_as = extract_1B(p); p++;
					for (int i=0 ; (i<nb_as) && (p<qq) ; i++) {
					    // JDJDJDJD capabilities parsing is missing here
					    int as = extract_4B(p); p+=4;
cout << as << " ";
					}
if (as_path_type == 1) /* AS_SET */ cout << "} ";
				    }
cout << endl;
				    p = qq;
				}
				break;

			    case 3: // next_hop
				extract_IPv4 (p, attr_next_hop); p+=4;
cout << "          next_hop: " << attr_next_hop << endl;
				break;

			    case 4: // med multi-exit-discriminator
				attr_med = extract_4B(p); p+=4;
cout << "          med: " << attr_med << endl;
				break;

			    case 5: // local_pref
				attr_local_pref = extract_4B(p); p+=4;
cout << "          local_pref: " << attr_local_pref << endl;
				break;

			    case 8: // communities
				{   unsigned const char *qq = p+attr_len;
cout << "          communities: ";
				    while (p<qq) {
cout << (unsigned int)extract_2B(p) << ":" << (unsigned int)extract_2B(p+2) << " "; p+=4;
				    }
cout << endl;
				}
				break;

			    case 9: // originator_id
				attr_originator_id = extract_4B(p); p+=4;
cout << "          originator_id: " << intIPv4tos(attr_originator_id) << endl;
				break;

			    case 16: // extended communities  // oh boy !
				{   unsigned const char *qq = p+attr_len;
//cout << "          extended_communities:" << endl << hexdump(message.substr(p-(unsigned const char *)message.c_str(),attr_len)) << endl;
cout << "          extended_communities: " << endl;
				    while (p<qq) {
					int extcom_typeHi, extcom_typeLo;
					int extcom_global_adm, extcom_local_adm;
					unsigned char opaque[6];
					extcom_typeHi = extract_1B (p); p++;
					extcom_typeLo = extract_1B (p); p++;
					switch (extcom_typeHi) {
					    case 0x00:	// transitive 2Bytes-AS-specific 
					    case 0x40:	// untransitive 2Bytes-AS-specific
						extcom_global_adm = extract_2B(p); p+=2;
						extcom_local_adm = extract_4B(p); p+=4;
cout << "               " << ((0x40 & extcom_typeHi)?"":"transitive ") << "2Bytes-AS-specific "
					   << extcom_global_adm << ":" << extcom_local_adm;
						break;
					    case 0x01:	// transitive IPv4-addr-specific
					    case 0x41:	// untransitive IPv4-addr-specific
						extcom_global_adm = extract_4B(p); p+=4;
						extcom_local_adm = extract_2B(p); p+=2;
cout << "               " << ((0x40 & extcom_typeHi)?"":"transitive ") << "IPv4-addr-specific "
					   << extcom_global_adm << ":" << extcom_local_adm;
						break;
					    case 0x03:	// transitive Opaque
					    case 0x43:	// untransitive Opaque
						memcpy (opaque, p, 6); p+=6;
cout << "               " << ((0x40 & extcom_typeHi)?"":"transitive ") << "Opaque ";
						for (int i=0 ; i<6; i++) { cout << setbase(16) << setfill('0') << setw(2) << (unsigned int)opaque[i] << setbase(10); if ((i%4 == 3) && (i!=6))cout << ':'; }
						break;
					    default:	// unknown
						memcpy (opaque, p, 6); p+=6;
cout << "               " << ((0x40 & extcom_typeHi)?"":"transitive ") << "unknown ";
						for (int i=0 ; i<6; i++) { cout << setbase(16) << setfill('0') << setw(2) << (unsigned int)opaque[i] << setbase(10); if ((i%4 == 3) && (i!=6))cout << ':'; }
						break;
					}
					if (extcom_typeLo == 0x2) {
					    if ((extcom_typeHi == 0x0) || (extcom_typeHi == 0x2))
						cout << " route-target-community AS-authority";
					    else if (extcom_typeHi == 0x1)
						cout << " route-target-community IP-authority";
					} else if (extcom_typeLo == 0x3) {
					    if ((extcom_typeHi == 0x0) || (extcom_typeHi == 0x2))
						cout << " route-origin-community AS-authority";
					    else if (extcom_typeHi == 0x1)
						cout << " route-origin-community IP-authority";
					}
					cout << endl;
				    }
				}
				break;

			    case 32: // large_communities
				{   unsigned const char *qq = p+attr_len;
//cout << "          large_communities: " << endl << hexdump(message.substr(p-(unsigned const char *)message.c_str(),attr_len)) << endl;
cout << "          large_communities: ";
				    while (p<qq) {
cout << (unsigned int)extract_4B(p) << ":"
     << (unsigned int)extract_4B(p+4) << ":"
     << (unsigned int)extract_4B(p+8) << " "; p+=12;
				    }
cout << endl;
//exitfromhere ++;
				}
				break;

			    case 66: // wtf ???
cout << "          type_66 : " << endl << hexdump(message.substr(p-(unsigned const char *)message.c_str(),attr_len)) << endl;
				p += attr_len;
//exitfromhere ++;
				break;

			    default:
cout << "          attr type: " << attr_type << " len: " << attr_len << endl;
				p += attr_len;
			}
		    }
		}
		p = q;
		offset += 2 + alength;

		int nlength = bgp_message_length -23 -rlength -alength;
		if ((nlength > 0) && (nlength < 4096)) {
cout << "  Network Layer Reachability Information :" << endl;// << hexdump(message.substr(offset, nlength)) << endl << endl;
		    unsigned const char *q = (unsigned const char *)message.c_str() + message.size();
		    while (p<q) {
			int prefix_len = extract_1B (p); p++;
			if (prefix_len > 32) {
    cerr << "extract_bgp_update : some prefix_len > 32 at Network Layer Reachability Information = " << prefix_len << endl;
			    return message.size();
			}
			struct sockaddr_storage a;
			memset (&a, 0, sizeof(a));
			sockaddr_in &sin = *(sockaddr_in *) &a;
			sin.sin_family = AF_INET;
			if (prefix_len != 0) {
			    int nbbytes = 1+((prefix_len-1)>>3);
			    memcpy (&sin.sin_addr, p, nbbytes);
			    p += nbbytes;
			}
cout << "          + " << a << "/" << prefix_len << endl;
		    }
		}
		offset += nlength;
		return offset;
	    }

	    size_t extract_tlv (string &tlv_type, string &tlv_content, size_t offset) {
// cout << hexdump(message.substr(offset)) << endl << endl;
		if (message.size()-offset<4) {
cerr << "extract_tlv error: msg too short" << endl;
		    return message.size();
		}
		unsigned const char *p = (unsigned const char *)message.c_str() + offset;
//		int type = (((int)(*p)) << 8) + (int)(*(p+1)),
//		     len = (((int)(*(p+2))) << 8) + (int)(*(p+3));
		int type = extract_2B (p),
		     len = extract_2B (p+2);
		switch (type) {
		    case 1:
			tlv_type = "sysDescr";
			break;
		    case 2:
			tlv_type = "sysName";
			break;
		    case 0:
			tlv_type = "utf8s";
			break;
		    default:
			tlv_type = "unknown";
			break;
		}
		tlv_content = message.substr (4+offset, len);
		offset += 4+len;
		return offset;
    	    }

	    void treat_4_initiation_msg (void) {
		size_t offset = 0;
		string tlv_type, tlv_content;
		while (offset < message.size()) {
		    offset = extract_tlv (tlv_type, tlv_content, offset);
		    cout << "   init : " << tlv_type << "->" << tlv_content << endl;
		}
	    }


	    typedef struct {
		int Peer_Type;
		int Peer_Flags;
		unsigned int Peer_Distinguisher;    // JDJDJDJD devrait faire 8 octets ?
		struct sockaddr_storage Peer_Address;
		unsigned int Peer_AS;
		unsigned int Peer_BGP_ID;
		time_t Timestamp;
		int Timestamp_musec;
	    } Per_Peer;

	    size_t extract_per_peer (Per_Peer &peer, size_t offset) {
		if (message.size()-offset<42) {
cerr << "extract_per_peer error: msg too short" << endl;
		    return message.size();
		}
		unsigned const char *p = (unsigned const char *)message.c_str() + offset;
		peer.Peer_Type = extract_1B (p);
		peer.Peer_Flags = extract_1B (p+1);
		//peer.Peer_Distinguisher = extract_4B (p+2);
		if (PerPeerIsIPv6(peer.Peer_Flags))
		    extract_IPv6 (p+10, peer.Peer_Address);
		else
		    extract_IPv4 (p+10+12, peer.Peer_Address); // the IPv4 addr is at the end of addr space (?)
		peer.Peer_AS = extract_4B (p+26);   // 10 + 16
		peer.Peer_BGP_ID = extract_4B (p+30);
		peer.Timestamp = extract_4B (p+34);
		peer.Timestamp_musec = extract_4B (p+38);
		return offset + 42;
	    }

	    string intIPv4tos (int n) {
		stringstream s;
		s << ((n & 0xff000000) >> 24) << "."
		  << ((n &   0xff0000) >> 16) << "."
		  << ((n &     0xff00) >> 8) << "."
		  <<  (n &       0xff);
		return s.str();
	    }

	    void treat_0_routemonitoring_msg (void) {
		size_t offset = 0;
		Per_Peer peer;
		offset = extract_per_peer (peer, offset);
cout << "  per-peer : " << peer.Peer_Address << " AS" << peer.Peer_AS << " id:" << intIPv4tos(peer.Peer_BGP_ID) << " " << time_ttos(peer.Timestamp) << endl;

		int bgp_type = -1, bgp_length = -1;
			offset = extract_bgp_head (bgp_type, bgp_length, offset);
cout << "          BGP_type = " << bgp_type << endl
     << "          BGP_leng = " << bgp_length; if (bgp_length>19) cout << " " << bgp_length-19 << " remaining ..." << endl; else cout << endl;

// cout << hexdump(message.substr(offset)) << endl << endl;
		if (bgp_type != 2) {
cerr << "treat_0_routemonitoring_msg : error we should have a bgp update but got : " << bgp_type << endl;
		}
		extract_bgp_update (bgp_length, offset);
	    }

	    void treat_2_peerdown_msg (void) {
		size_t offset = 0;
		Per_Peer peer;
		offset = extract_per_peer (peer, offset);
cout << "  per-peer : " << peer.Peer_Address << " AS" << peer.Peer_AS << " id:" << intIPv4tos(peer.Peer_BGP_ID) << " " << time_ttos(peer.Timestamp) << endl;

cout << hexdump(message.substr(offset)) << endl << endl;
		unsigned const char *p = (unsigned const char *)message.c_str() + offset;
		int reason = extract_1B (p);
cout << "    reason : " << reason << endl;

		int bgp_type = -1, bgp_length = -1;

		switch (reason) {

		    case 1: // The local system closed the session.
cout << "             The local system closed the session" << endl;
cout << "          BGP BPU sent : " << endl;
cout << hexdump(message.substr(offset+1)) << endl << endl;
			offset = extract_bgp_head (bgp_type, bgp_length, offset+1);
cout << "             BGP_type = " << bgp_type << endl
     << "             BGP_leng = " << bgp_length; if (bgp_length>19) cout << " " << bgp_length-19 << " remaining ..." << endl; else cout << endl;
			break;

		    case 2: // 
cout << "             The local system closed the session" << endl;
cout << "             finite state machine event = " << extract_2B (p+1) << endl;
			break;

		    case 3:
cout << "             The remote system closed the session" << endl;
cout << "          BGP BPU sent : " << endl;
cout << hexdump(message.substr(offset+1)) << endl << endl;
			offset = extract_bgp_head (bgp_type, bgp_length, offset+1);
cout << "             BGP_type = " << bgp_type << endl
     << "             BGP_leng = " << bgp_length; if (bgp_length>19) cout << " " << bgp_length-19 << " remaining ..." << endl; else cout << endl;
			break;

		    case 4:
cout << "             The remote system closed the session without notification" << endl;
			break;

		    case 5:
cout << "             concerned peer will not be advertised in this BMP session" << endl;
			break;

		    default:
			break;
		}

	    }

	    void treat_3_peerup_msg (void) {
		size_t offset = 0;
		Per_Peer peer;
		offset = extract_per_peer (peer, offset);
cout << "  per-peer : " << peer.Peer_Address << " AS" << peer.Peer_AS << " id:" << intIPv4tos(peer.Peer_BGP_ID) << " " << time_ttos(peer.Timestamp) << endl;

		unsigned const char *p = (unsigned const char *)message.c_str() + offset;
		struct sockaddr_storage local_addr;
		int lport, dport;

		if (message.size()-offset < 16) {	// JDJDJDJD: this doesn't account for opensent/receive msg
cerr << "treat_3_peerup_msg error: msg too short" << endl;
		    return;
		}

//cout << hexdump(message.substr(offset)) << endl << endl;

		int bgp_type = -1, bgp_length = -1;

		if (PerPeerIsIPv6(peer.Peer_Flags))
                    extract_IPv6 (p, local_addr);
                else
                    extract_IPv4 (p+12, local_addr);
		lport = extract_2Bswapped (p+16);	// with FRR we have to swap this ?
		dport = extract_2Bswapped (p+18);	// with FRR we have to swap this ?
cout << "  loc-addr : " << local_addr << ":" << lport  << endl;
cout << "    d-addr : " << peer.Peer_Address << ":" << dport  << endl;
cout << "      open sent :" << endl;
cout << hexdump(message.substr(offset+20, 19)) << endl << endl;	    // JDJDJDJD: DID NOT YET HAVE A DECENT SAMPLE
			offset = extract_bgp_head (bgp_type, bgp_length, offset+20);
cout << "             BGP_type = " << bgp_type << endl
     << "             BGP_leng = " << bgp_length; if (bgp_length>19) cout << " " << bgp_length-19 << " remaining ..." << endl; else cout << endl;

		offset += bgp_length-19;
cout << "      open receiver :" << endl;
cout << hexdump(message.substr(offset, 19)) << endl << endl;
			offset = extract_bgp_head (bgp_type, bgp_length, offset);
cout << "             BGP_type = " << bgp_type << endl
     << "             BGP_leng = " << bgp_length; if (bgp_length>19) cout << " " << bgp_length-19 << " remaining ..." << endl; else cout << endl;
cout << "      open receiver :" << endl;
	    }

	    void treatmessage (void) {
		switch (h_msgtype) {
		    case 0: cout << "Route Monitoring       " << " " << h_msglength << endl; break;
		    case 1: cout << "Statistics Report      " << " " << h_msglength << endl; break;
		    case 2: cout << "Peer Down Notification " << " " << h_msglength << endl; break;
		    case 3: cout << "Peer Up Notification   " << " " << h_msglength << endl; break;
		    case 4: cout << "Initiation Message     " << " " << h_msglength << endl; break;
		    case 5: cout << "Termination Message    " << " " << h_msglength << endl; break;
		    case 6: cout << "Route Mirroring Message" << " " << h_msglength << endl; break;
		    default:
			cerr << "message in connu msgtype=" << h_msgtype << " " << h_msglength << endl; break;
		}

		switch (h_msgtype) {
		    case 4:
			treat_4_initiation_msg();
			break;
		    case 3:
			treat_3_peerup_msg();
			break;
		    case 2:
			treat_2_peerdown_msg();
			break;
		    case 0:
			treat_0_routemonitoring_msg();
		    default:
			break;
		}

		nbmessage ++;
cout << "  nbmessage = " << nbmessage << endl;
if (nbmessage % 1000 == 0) {
    dump_attrstats (cout, attrstats);
}
if ( ((maxreceivedmessage != -1) && (nbmessage > maxreceivedmessage)) || (exitfromhere > 20)) { flush() ; schedule_for_destruction(); exit(0); };
	    }

	    virtual void lineread (void) {
		string::iterator si = bufin.begin();
		size_t i=0, tots = bufin.size();
		while (i < tots) {
		    switch (rstatus) {
			case INHEADER:
			    switch (uncount) {
				case 0:
				    // on est au tout debut du header, on efface la ou on va ecrire
				    h_version = 0;
				    h_msglength = 0;
				    h_msgtype = 0;
				    h_version = (int)(unsigned char)(*si);
				    uncount ++;
				    break;
				case 1:
				case 2:
				case 3:
				    h_msglength += (int)(unsigned char)(*si);
				    h_msglength <<= 8;
				    uncount ++;
				    break;
				case 4:
				    h_msglength += (int)(unsigned char)(*si);
				    uncount ++;
				    break;
				case 5:
				    h_msgtype = (int)(unsigned char)(*si);
cout << endl << "bmp header :  version " << h_version << "   len " << h_msglength << "   type " << h_msgtype << endl;
				    rstatus = INMESSAGE;
				    uncount = h_msglength - 6; // on enleve la taille du header
				    message.clear();
				    break;
				default:
cerr << "mais qu'est ce qu'on fout la ??? [1]" << endl;
exit(0);
			    }
			    break;
			case INMESSAGE:
			    if (uncount > 0) {
				message += (*si);
				uncount--;
				if (uncount ==0) {
				    rstatus = INHEADER;
				    treatmessage();
				}
			    } else {
cerr << "mais qu'est ce qu'on fout la [2] ???" << endl;
exit(0);
			    }
			    break;
			default:
cerr << "mais qu'est ce qu'on fout la [3] ???" << endl;
exit(0);
		    }
		    i++, si++;
		}
	    }

	    virtual void oldlineread (void) {
		string::iterator si;
		int n = 0;
		for (si=bufin.begin() ; si!=bufin.end() ; si++) {
		    cout << setw(2) << setbase(16) << setfill('0') << (int)(unsigned char)(*si) << ' ' ;
		    n++;
		    if (n == 32) {
			n=0;
			cout << endl;
		    }
		}
		cout << " | " << setbase(10) << bufin.size() << endl << endl;
	    }
	    virtual const char * gettype (void) { return "ReadBMP"; }
    };

    class ReadBMPBinder : public ListeningSocket
    {
	public:
	    virtual ~ReadBMPBinder (void) {}
	    ReadBMPBinder (int fd, int port, const char * addr = NULL) : ListeningSocket (fd, "httppbinder") {
		stringstream newname;
		if (addr == NULL)
		    newname << "*";
		else
		    newname << addr;
		newname << ":" << port;
		setname (newname.str());
	    }
	    virtual SocketConnection* connection_binder (int fd, struct sockaddr_storage const &client_addr) {
		return new ReadBMP (fd, client_addr);
	    }
	    virtual void poll (void) {}
	    virtual const char * gettype (void) { return "ReadBMPBinder"; }
    };

}


using namespace std;
using namespace qiconn;
using namespace readbmp;

SimpleCPool cpool;

typedef pair<string,int> AddressPort;

map <string,string> properties;	// JDJDJDJDJD usage futur ?

int main (int nb, char ** cmde) {

    int    port_bmp = 5027;
    list<AddressPort> listening_addresses;
    list<AddressPort> toconnect_addresses;
    list<int> listsockets;

    bool debug_multiple_scheddestr = false;
    // ----------------------------------------------------------------------------------------------------------

    bool inproperties = false;
    int maxreceivedmessage = -1;

    int i;
    for (i=1 ; i<nb ; i++) {
      if (!inproperties) {
	if (strncmp (cmde[i], "--help", 6) == 0) {
	    cout << cmde[0] << "   \\" << endl
			    << "      [--bind=[address][:port]]  \\" << endl	// JDJDJDJDJD this doesn't work with [IPv6]:port
			    << "      [--connect=[address][:port]]  \\" << endl	// JDJDJDJDJD this doesn't work with [IPv6]:port
			    << "      [--maxmessage=xxx]" << endl
			    << "      [--properties|-p] [prop[=true]] [prop=value] ";
	    return 0;
	} else if (strncmp (cmde[i], "--bind=", 7) == 0) {
	    string scheme(cmde[i]+7);
	    size_t p = scheme.find(':');    // JDJDJDJDJD this doesn't work with [IPv6]:port
	    if (p == string::npos) {	// we have only an addr ?
		listening_addresses.push_back(AddressPort(scheme, port_bmp));
	    } else {
		if (p>0)
		    listening_addresses.push_back(AddressPort(scheme.substr(0,p), atoi (scheme.substr(p+1).c_str())));
		else
		    listening_addresses.push_back(AddressPort("0.0.0.0", atoi (scheme.substr(p+1).c_str())));
	    }
	} else if (strncmp (cmde[i], "--connect=", 10) == 0) {
	    string scheme(cmde[i]+10);
	    size_t p = scheme.find(':');    // JDJDJDJDJD this doesn't work with [IPv6]:port
	    if (p == string::npos) {	// we have only an addr ?
		toconnect_addresses.push_back(AddressPort(scheme, port_bmp));
	    } else {
		if (p>0)
		    toconnect_addresses.push_back(AddressPort(scheme.substr(0,p), atoi (scheme.substr(p+1).c_str())));
		else
		    toconnect_addresses.push_back(AddressPort("0.0.0.0", atoi (scheme.substr(p+1).c_str())));
	    }
	} else if (strncmp (cmde[i], "--maxmessage=", 13) == 0) {
	    maxreceivedmessage = atol (cmde[i]+13);
	} else if ((strcmp (cmde[i],"-p") == 0) || (strcmp(cmde[i], "--properties"))) {
	    inproperties = true;
	    continue;
	} else {
	    cerr << "unknown option : " << cmde[i] << endl;
	}
      } else {	// here below inproperties is true !
	if (!isalnum (cmde[i][0])) {
	    cerr << "bad property-name : " << cmde[i] << endl;
	    continue;
	}
	size_t j=0;
	while ((cmde[i][j] != 0) && (cmde[i][j]!='=')) j++;
	if (cmde[i][j] != '=') {    // we have a simple property-name !
	    properties[cmde[i]] = string("y");	// we set it true
	    continue;
	}
	properties[string(cmde[i],j)] = string(cmde[i]+j+1);
      }
    }
    // ----------------------------------------------------------------------------------------------------------

//    if (listening_addresses.empty())
//	listening_addresses.push_back(AddressPort("0.0.0.0",80));

    // we bind before dropping privileges
    {	list<AddressPort>::iterator li;
	for (li=listening_addresses.begin() ; li!=listening_addresses.end() ; li++) {
	    int port = li->second;
	    string &address = li->first;

    cerr << "binding [" << address << "]:[" << port << "]" << endl;

	    int type;
	    if (address.find(':') != string::npos)
		type = AF_INET6;
	    else
		type = AF_INET;

	    int s = server_pool (port, address.c_str(), type);
	    if (s < 0) {
		cerr << "could not instanciate listening socket, bailing out !" << endl;
		for (list<int>::iterator li=listsockets.begin() ; li!=listsockets.end() ; li++)
		    ::close (*li);
		return -1;
	    }

	    listsockets.push_back(s);
	}
    }

    // JDJDJDJD : here be some code for dropping privileges ... not yet needed if we listen only user ports

    cpool.set_debug_multiple_scheddestr (debug_multiple_scheddestr);
    cpool.init_signal ();
    cpool.add_signal_handler (SIGQUIT);
    cpool.add_signal_handler (SIGINT);

    {	list<AddressPort>::iterator li;
	list<int>::iterator lj;
	for (li=listening_addresses.begin(),lj=listsockets.begin() ; (li!=listening_addresses.end()) && (lj!=listsockets.end()) ; li++,lj++) {
	    int port = li->second;
	    string &address = li->first;

	    ReadBMPBinder *ls = new ReadBMPBinder (*lj, port, address.c_str());
	    if (ls == NULL) {
		cerr << "could not instanciate ReadBMPBinder, bailing out !" << endl;
		for (list<int>::iterator li=listsockets.begin() ; li!=listsockets.end() ; li++)
		    ::close (*li);
		return -1;
	    }

	    cpool.push (ls);

	}
    }

    // we connect to remote BMP speakers
    {	list<AddressPort>::iterator li;
	for (li=toconnect_addresses.begin() ; li!=toconnect_addresses.end() ; li++) {
	    int port = li->second;
	    string &address = li->first;

    cerr << "connecting to [" << address << "]:[" << port << "]" << endl;

//	    int type;	// JDJDJDJD : okay this is in fact _ugly_ and IPv4 only .... init_connect below needs to be refunded ... 
//	    if (address.find(':') != string::npos)
//		type = AF_INET6;
//	    else
//		type = AF_INET;

	    struct sockaddr_in      sock_addr_bmp;
	    struct sockaddr_storage sock_stor_bmp;
	    int fd_bmp = init_connect (address.c_str(), port, &sock_addr_bmp);

	    // this should be some conversion utility : sockaddr_in + port  to sockaddr_storage
	    // sockaddr_in_to_storage (IPv4 only :( )
	    {
		memset (&sock_stor_bmp, 0, sizeof(sock_stor_bmp));

		if (sock_addr_bmp.sin_family == AF_INET) {
		    sockaddr_in &sock_stor_bmp_4 = *(sockaddr_in *) &sock_stor_bmp;
		    sock_stor_bmp_4.sin_family = sock_addr_bmp.sin_family;
		    sock_stor_bmp_4.sin_port = htons (port);
		    // this is the case where "addr" is a string with the address into it
		    // if (inet_aton(addr, &sock_stor_bmp_4.sin_addr) == (int)INADDR_NONE) {
		    //     int e = errno;
		    //     cerr << "gethostbyaddr (" << addr << " failed : " << strerror (e) << endl;
		    //     return -1;
		    // }
		    sock_stor_bmp_4.sin_addr = sock_addr_bmp.sin_addr;
		} else {
		    cerr << "sockaddr_in_to_storage error: cannot convert type \"" << sock_addr_bmp.sin_family << "\"" << endl;
		    return -1;
		}
	    }
		
	    if (fd_bmp < 0) {
		cerr << "could not connect to " << address << ":" << port << " ..." << endl;
		continue;
	    }

	    ReadBMP* pdummybmp = new ReadBMP(fd_bmp, sock_stor_bmp);
	    if (pdummybmp == NULL) {
cerr << "failed to instantiate ReadBMP for " << address << ":" << port << endl;
		continue;
	    }

	    pdummybmp->maxreceivedmessage = maxreceivedmessage;

	    pdummybmp->register_into_pool (&cpool);
	}
    }

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 1000;

    cpool.select_loop (timeout);

    cerr << "terminating" << endl;

    cpool.closeall ();

    return 0;
}


