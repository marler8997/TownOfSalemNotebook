#include <stdio.h>
#include <pcap.h>

#ifdef WIN32
  #include <winsock2.h>
  #define NL "\r\n"
#elif POSIX
  #define NL "\n"
#else
  #error Unknown platform
#endif

#define log(fmt,...) printf(fmt NL,##__VA_ARGS__)
#define error(fmt,...) printf("Error: "fmt NL,##__VA_ARGS__)

char errbuf[PCAP_ERRBUF_SIZE];

bpf_u_int32* ipv4AddressesHostOrder;
bpf_u_int32* ipv4AddressesNetworkOrder;
bpf_u_int32 ipv4AddressCount;

const char* addressFamilyString(int af)
{
  switch(af) {
  case AF_INET: return "AF_INET";
  case AF_INET6: return "AF_INET6";
  default: return "?";
  }
}

#define HOST_ORDER_IPV4_SPRINTF(out, ip) \
  sprintf(out, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
	  

#define MAX_ADDR_STRING 64
char* ipv4ToString(bpf_u_int32 ip)
{
  static char staticBuffer[MAX_ADDR_STRING];
  HOST_ORDER_IPV4_SPRINTF(staticBuffer, ip);
  return staticBuffer;
}

void afInetAddrToString(struct sockaddr* addr, char* out)
{
  bpf_u_int32 addrValue = ntohl(((struct sockaddr_in*)addr)->sin_addr.s_addr);
  HOST_ORDER_IPV4_SPRINTF(out, addrValue);
}
void afInet6AddrToString(struct sockaddr* addr, char* out)
{
  sprintf(out, "(some ipv6 address)");
}


void addrToString(struct sockaddr* addr, char* out)
{
  if(addr->sa_family == AF_INET) {
    afInetAddrToString(addr, out);
  } else if(addr->sa_family == AF_INET6) {
    afInet6AddrToString(addr, out);
  } else {
    sprintf(out, "(unknown addr family %d)", addr->sa_family);
  }
}

unsigned char ipv4SubnetBitCount(bpf_u_int32 netmask)
{
  unsigned char ret = 32;
  for(; ret > 0; ret--, netmask>>=1) {
    if(netmask & 1) {
      return ret;
    }
  }
  return 0;
}


/*
bpf_u_int32 parseSubnet(const char* str)
{
  
}
*/
/*
bpf_u_int32 getIPv4Netmask(pcap_if_t* iface)
{
  pcap_addr_t* addr;
  for(addr = iface->addresses; addr; addr=addr->next) {
    if(addr->addr->sa_family == AF_INET && addr->netmask) {
      return addr->netmask;
    }
  }
  return 0;
}
*/

void printInterface(pcap_if_t* iface)
{
  printf("Name       : %s" NL, iface->name);
  printf("Description: %s" NL, iface->description);
  printf("Loopback   : %s" NL, (iface->flags&PCAP_IF_LOOPBACK) ? "yes":"no");
  
  {
    pcap_addr_t* addr;
    char addrString[MAX_ADDR_STRING];
    
    for(addr = iface->addresses; addr; addr=addr->next) {
      switch(addr->addr->sa_family) {
      case AF_INET:
	printf("IPv4 Address" NL);
	afInetAddrToString(addr->addr, addrString);
	printf("  IP       : %s" NL, addrString);
	if(addr->netmask) {
	  int subnetBitCount;
	  bpf_u_int32 tempAddr;
	  afInetAddrToString(addr->netmask, addrString);
	  printf("  Netmask  : %s" NL, addrString);

	  tempAddr = ntohl(((struct sockaddr_in*)addr->netmask)->sin_addr.s_addr);
	  subnetBitCount = ipv4SubnetBitCount(tempAddr);
	  tempAddr &= ntohl(((struct sockaddr_in*)addr->addr)->sin_addr.s_addr);

	  HOST_ORDER_IPV4_SPRINTF(addrString, tempAddr);
	  printf("  Subnet   : %s/%d" NL, addrString, subnetBitCount);
					      
	  
	  
	}
	if(addr->broadaddr) {
	  afInetAddrToString(addr->broadaddr, addrString);
	  printf("  Broadcast: %s" NL, addrString);
	}
	if(addr->dstaddr) {
	  afInetAddrToString(addr->dstaddr, addrString);
	  printf("  Broadcast: %s" NL, addrString);
	}
	break;
      case AF_INET6:
	printf("IPv6 Address" NL);
	afInet6AddrToString(addr->addr, addrString);
	printf("  IP       : %s" NL, addrString);
	break;
      default:
	printf("address" NL);
	break;
      }
    }
  }
}



#pragma pack(push,1)
typedef struct {
  u_char dst_addr[6];
  u_char src_addr[6];
  u_short llc_len;
} EthernetHeader;
typedef struct _IPHeader {
  u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
  u_char  tos;            // Type of service 
  u_short totalLength;           // Total length 
  u_short identification; // Identification
  u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
  u_char  ttl;            // Time to live
  u_char  proto;          // Protocol
  u_short crc;            // Header checksum
  bpf_u_int32  srcAddr;   // Source address
  bpf_u_int32  dstAddr;   // Destination address
  u_int   op_pad;         // Option + Padding
} IPHeader;
#pragma pack(pop)

#define ntohIPHeader(hdr)		    \
  hdr.totalLength = ntohs(hdr.totalLength); \
  /*hdr.srcAddr = ntohl(hdr.srcAddr);*/	    \
  /*hdr.dstAddr = ntohl(hdr.dstAddr);*/


u_char isInterfaceIP(bpf_u_int32 ip)
{
  int ipIndex;
  for(ipIndex = 0; ipIndex < ipv4AddressCount; ipIndex++) {
    if(ipv4AddressesNetworkOrder[ipIndex] == ip) {
      return 1; // ip found
    }
  }
  return 0; // ip not found
}

void handlePacket(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
  IPHeader* ipHeader;
  u_short srcPort;
  u_short dstPort;
  bpf_u_int32 srcIPNetworkOrder, dstIPNetworkOrder;
  u_char outgoing;

  if(header->len < sizeof(EthernetHeader) + sizeof(IPHeader)) {
    log("warning: packet length %d is too small", header->len);
    return;
  }
  
  ipHeader = (IPHeader*)(packet + sizeof(EthernetHeader));
  srcIPNetworkOrder = ipHeader->srcAddr;
  dstIPNetworkOrder = ipHeader->dstAddr;

  if(isInterfaceIP(srcIPNetworkOrder)) {
    outgoing = 1;
    printf("outgoing packet!" NL);
  } else if(isInterfaceIP(dstIPNetworkOrder)) {
    outgoing = 0;
    printf("incoming packet!" NL);
  } else {
    error("packet src ip and dst ip do not match any of the interface ips");
    return;
  }


  
  //ntohIPHeader(ipHeader);

  
  //HOST_ORDER_IPV4_SPRINTF(srcAddrString, ipHeader.srcAddr);
  //HOST_ORDER_IPV4_SPRINTF(dstAddrString, ipHeader.dstAddr);

  //log("%s > %s", srcAddrString, dstAddrString);
}


// Returns: 0 on success
int setFilter(pcap_t* pcap, const char* filter)
{
  struct bpf_program filterProgram;

  // Compile Filter
  if(pcap_compile(pcap, &filterProgram, filter, 1, 0) == -1) {
    error("pcap_compile '%s' failed: %s", filter, pcap_geterr(pcap));
    return 1;
  }

  if(pcap_setfilter(pcap, &filterProgram) == -1) {
    error("pcap_setfilter failed: %s", pcap_geterr(pcap));
    return 1;
  }

  return 0;
}


//#define PRE_FILTER "tcp and port 3600"
#define PRE_FILTER "tcp and port 80"

// Returns: 0 on success
int runSniffer(const char* interfaceName)
{
  pcap_t* pcap;
  int failed = 1;

  pcap = pcap_open_live(interfaceName, 65535, 1, 300, errbuf);
  if(pcap == NULL) {
    error("pcap_open_live failed: %s" NL, errbuf);
    goto DONE;
  }

  {
    int offset = 0;
    char * filter = malloc(sizeof(PRE_FILTER) +
			   (22 * ipv4AddressCount)); // " host XXX.XXX.XXX.XXX"
    offset = sprintf(filter, PRE_FILTER);
    {
      int ipIndex;
      for(ipIndex = 0; ipIndex < ipv4AddressCount; ipIndex++) {
	offset += sprintf(filter + offset, " host ");
	offset += HOST_ORDER_IPV4_SPRINTF(filter + offset, ipv4AddressesHostOrder[ipIndex]);
      }
    }

    printf("[DEBUG] pcap filter is '%s'" NL, filter);
    if(setFilter(pcap, "tcp and port 80")) {
      goto DONE;
    }    
  }
  

  log("[DEBUG] capturing...");
  pcap_loop(pcap, -1, handlePacket, NULL);
  log("[DEBUG] capture done");

 DONE:
  if(pcap) {
    pcap_close(pcap);
  }
  return failed;
}

void usage()
{
  printf("TownOfSalemSniffer.exe list (print interfaces)" NL);
  //printf("TownOfSalemSniffer.exe <subnet>" NL);
  printf("TownOfSalemSniffer.exe <interface-name>" NL);
}
int main(int argc, char* argv[])
{
  const char* firstArg;
  pcap_if_t* devs;

  if(argc <= 1) {
    usage();
    return 0;
  }

  firstArg = argv[1];

  if(strcmp(firstArg, "list") == 0) {
    if(pcap_findalldevs(&devs, errbuf) == -1) {
      error("pcap_findalldevs_ex failed: %s", errbuf);
      return 1;
    }

    {
      pcap_if_t* dev;
      int i = 1;
      for(dev = devs; dev; dev = dev->next,i++) {
	printf("--------------------------------------" NL);
	printInterface(dev);
      }

      pcap_freealldevs(devs);
      
      if(i == 1) {
	printf("No interfaces found.  Is WinPcap installed?" NL);
	return 1;
      }
      printf("--------------------------------------" NL);
    }
    return 0;
  }

  
  if(pcap_findalldevs(&devs, errbuf) == -1) {
    error("pcap_findalldevs_ex failed: %s", errbuf);
    return 1;
  }

  {
    pcap_if_t* dev;
    int devIndex = 1;
    for(dev = devs; dev; dev = dev->next,devIndex++) {
      if(strcmp(dev->name, firstArg) == 0) {

	// Get ipv4 addresses
	ipv4AddressCount = 0;
	{
	  pcap_addr_t* addr;
	  for(addr = dev->addresses; addr; addr=addr->next) {
	    if(addr->addr->sa_family == AF_INET) {
	      ipv4AddressCount++;
	    }
	  }
	  if(ipv4AddressCount == 0) {
	    error("Interface '%s' has no ipv4 addresses", dev->name);
	    return 1;
	  }
	  ipv4AddressesHostOrder = malloc(sizeof(bpf_u_int32) * (2*ipv4AddressCount));
	  ipv4AddressesNetworkOrder = ipv4AddressesHostOrder + ipv4AddressCount;
	  {
	    int ipIndex = 0;
	    for(addr = dev->addresses; addr; addr=addr->next) {
	      if(addr->addr->sa_family == AF_INET) {
		ipv4AddressesNetworkOrder[ipIndex] = ((struct sockaddr_in*)(addr->addr))->sin_addr.s_addr;
		ipv4AddressesHostOrder[ipIndex] = ntohl(ipv4AddressesNetworkOrder[ipIndex]);
		ipIndex++;
	      }
	    }
	  }
	}

	printf("You've selected to list on this network interface:" NL);
	printf("--------------------------------------" NL);
	printInterface(dev);
	printf("--------------------------------------" NL);
	printf(NL "Will filter packets on %d addresses:" NL, ipv4AddressCount);
	{
	  int ipIndex = 0;
	  for(; ipIndex < ipv4AddressCount; ipIndex++) {
	    printf("  %s" NL, ipv4ToString(ipv4AddressesHostOrder[ipIndex]));
	  }
	}
	break;
      }
    }

    pcap_freealldevs(devs);

    if(dev == NULL) {
      printf("interface '%s' is not found, run 'list' to see interfaces." NL, firstArg);
      return 1;
    }
    
  }

  
  
  return runSniffer(firstArg);
}
