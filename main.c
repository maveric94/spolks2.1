#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef WIN32
#include <winsock2.h>
#include <Mstcpip.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ws2tcpip.h>
#include "stdint.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

typedef SOCKET Socket;

#define CLOSE_SOCKET(a) closesocket(a)
#define ICMP_ECHO       8
#define ICMP_ECHOREPLY          0       /* Echo Reply                   */

typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;


struct ip {
	//#if BYTE_ORDER == LITTLE_ENDIAN 
	u_char	ip_hl : 4,		/* header length */
ip_v : 4;					/* version */
	//#endif
	//#if BYTE_ORDER == BIG_ENDIAN 
	//	u_char	ip_v : 4,			/* version */
	//	ip_hl : 4;		/* header length */
	//#endif
	u_char	ip_tos;			/* type of service */
	short	ip_len;			/* total length */
	u_short	ip_id;			/* identification */
	short	ip_off;			/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
	u_char	ip_ttl;			/* time to live */
	u_char	ip_p;			/* protocol */
	u_short	ip_sum;			/* checksum */
	struct	in_addr ip_src, ip_dst;	/* source and dest address */
};

struct icmp_ra_addr
{
	u_int32_t ira_addr;
	u_int32_t ira_preference;
};

struct icmp
{
	u_int8_t  icmp_type;	/* type of message, see below */
	u_int8_t  icmp_code;	/* type sub code */
	u_int16_t icmp_cksum;	/* ones complement checksum of struct */
	union
	{
		u_char ih_pptr;		 //ICMP_PARAMPROB
		struct in_addr ih_gwaddr;	/* gateway address */
		struct ih_idseq		/* echo datagram */
		{
			u_int16_t icd_id;
			u_int16_t icd_seq;
		} ih_idseq;
		u_int32_t ih_void;

		/* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
		struct ih_pmtu
		{
			u_int16_t ipm_void;
			u_int16_t ipm_nextmtu;
		} ih_pmtu;

		struct ih_rtradv
		{
			u_int8_t irt_num_addrs;
			u_int8_t irt_wpa;
			u_int16_t irt_lifetime;
		} ih_rtradv;
	} icmp_hun;
#define	icmp_pptr	icmp_hun.ih_pptr
#define	icmp_gwaddr	icmp_hun.ih_gwaddr
#define	icmp_id		icmp_hun.ih_idseq.icd_id
#define	icmp_seq	icmp_hun.ih_idseq.icd_seq
#define	icmp_void	icmp_hun.ih_void
#define	icmp_pmvoid	icmp_hun.ih_pmtu.ipm_void
#define	icmp_nextmtu	icmp_hun.ih_pmtu.ipm_nextmtu
#define	icmp_num_addrs	icmp_hun.ih_rtradv.irt_num_addrs
#define	icmp_wpa	icmp_hun.ih_rtradv.irt_wpa
#define	icmp_lifetime	icmp_hun.ih_rtradv.irt_lifetime
	union
	{
		struct
		{
			u_int32_t its_otime;
			u_int32_t its_rtime;
			u_int32_t its_ttime;
		} id_ts;
		struct
		{
			struct ip idi_ip;
			/* options and then 64 bits of data */
		} id_ip;
		struct icmp_ra_addr id_radv;
		u_int32_t   id_mask;
		u_int8_t    id_data[1];
	} icmp_dun;
#define	icmp_otime	icmp_dun.id_ts.its_otime
#define	icmp_rtime	icmp_dun.id_ts.its_rtime
#define	icmp_ttime	icmp_dun.id_ts.its_ttime
#define	icmp_ip		icmp_dun.id_ip.idi_ip
#define	icmp_radv	icmp_dun.id_radv
#define	icmp_mask	icmp_dun.id_mask
#define	icmp_data	icmp_dun.id_data
};



#endif

#ifdef __unix__


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>
#include <strings.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <float.h>

#define INVALID_SOCKET -1

typedef int Socket;
typedef struct in_addr in_addr;
#define CLOSE_SOCKET(a) close(a)

#endif


#define BUFSIZE 60*1024

int sendDescr;
int receiveDescr;


struct sockaddr_in servAddr;   
struct sockaddr_in fromAddr;  


int nsent = 0;                
int nreceived = 0;      

int icmpData_len = 56;          

u_int8_t ttl = 64;             
in_addr srcIP;            


void sendEcho(void);
u_int16_t in_cksum(u_int16_t *, int);
in_addr getSourceIP(in_addr destIP);
void startUp();
void cleanUp();
struct addrinfo *ResolveAddress(char *addr, char *port, int af, int type, int proto);


int main(int argc, char *argv[])
{
	if (argc != 2 && argc != 4 && argc != 6) 
	{
		perror("Invalid args.");
		exit(-1);
	}

	startUp();
	//char *a[] = { "prog", "www.google.com" };
	char *hostName = argv[1];

	struct hostent *hostInfo = gethostbyname(hostName);
	if (hostInfo == NULL)
	 {
		perror("gethostbyname() failed");
		exit(-1);
	}

	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sin_family = PF_INET;
	servAddr.sin_addr = *((struct in_addr *) hostInfo->h_addr);

	srcIP = getSourceIP(servAddr.sin_addr);     

	int i;
	for (i = 2; i < argc; i += 2)
	 {
		 if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) 
		 {
			int t = atoi(argv[i + 1]);
			if (t < 1 || t > 255) 
			{
				fprintf(stderr, "ttl %d out of range\n", t);
				exit(-1);
			}
			else
				ttl = t;
		}
		else if (strcmp(argv[i], "-src") == 0 && i + 1 < argc) 
		{
			in_addr a;
			a.s_addr = inet_addr(argv[i + 1]);
			if (a.s_addr == INADDR_NONE) 
			{
				fprintf(stderr, "Bad source IP, used default\n");
			}
			else
				srcIP = a;
		}
		else
		{
			fprintf(stderr, "Bad option: %s\n", argv[i]);
			exit(-1);
		}
	}

	printf("PING %s (%s) %d(%d) bytes of data.\n", hostName, inet_ntoa(servAddr.sin_addr), icmpData_len, icmpData_len + 28);
	printf("%s\n", inet_ntoa(srcIP));
	if ((sendDescr = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		perror("socket() failed");
		exit(-1);
	}

	const int optionValue = 1;
	if (setsockopt(sendDescr, IPPROTO_IP, IP_HDRINCL, (char *)&optionValue, sizeof(optionValue)) < 0) 
	{
		perror("setsockopt");
		exit(1);
	}

	if ((receiveDescr = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) 
	{
		perror("socket() failed");
		exit(-1);
	}

#ifdef _unix_
	setuid(getuid());
#endif

	int size = BUFSIZE;
	setsockopt(receiveDescr, SOL_SOCKET, SO_RCVBUF, (char *)&size, sizeof(size));

#ifdef WIN32
	//DWORD d;
	//if (WSAIoctl(
	//	receiveDescr,            // descriptor identifying a socket
	//	SIO_RCVALL,                       // dwIoControlCode
	//	NULL,                              // lpvInBuffer
	//	0,                                 // cbInBuffer
	//	NULL,                              // lpvOutBuffer output buffer
	//	0,            // size of output buffer  
	//	&d,    // number of bytes returned
	//	NULL, // OVERLAPPED structure
	//	NULL  // completion routine
	//	) == -1)
	//{
	//	int b = WSAGetLastError();
	//	b = b;
	//}

	struct addrinfo *local = ResolveAddress(NULL, "0", AF_INET, 0, 0);
	if (bind(receiveDescr, local->ai_addr, local->ai_addrlen) == SOCKET_ERROR)
	{
		return -1;;
	}
#endif


	socklen_t fromlen = sizeof(fromAddr);
	int recvSize;
	char recvBuf[BUFSIZE];
	int count = 1000;

	while (1)
	{
		if (count > 100)
		{
			sendEcho();
			count = 0;
		}
		else
		{
			count++;
		}
		fd_set fd;
		struct timeval tv;

		FD_ZERO(&fd);
		FD_SET(receiveDescr, &fd);
		tv.tv_sec = 0;
		tv.tv_usec = 10000;

		int selectResult = select(receiveDescr + 1, &fd, NULL, NULL, &tv);
		if (selectResult <= 0)
		{
			continue;
		}
		recvSize = recvfrom(receiveDescr, recvBuf, sizeof(recvBuf), 0, (struct sockaddr *) &fromAddr, &fromlen);

		if (recvSize < 0) 
		{
			if (errno == EINTR)
				continue;
			perror("recvfrom() failed");
			continue;
		}

		struct ip *ip = (struct ip *) recvBuf;
		int iplen = ip->ip_hl << 2;

		struct icmp *icmp = (struct icmp *) (recvBuf + iplen);
		int icmplen = recvSize - iplen;
		if (icmplen < 8)
			fprintf(stderr, "icmplen (%d) < 8", icmplen);

		if (icmp->icmp_type == ICMP_ECHOREPLY) 
		{
			printf("%d bytes from %s: icmp_seq=%u, ttl=%d\n", icmplen, inet_ntoa(fromAddr.sin_addr), icmp->icmp_seq, ip->ip_ttl);
			nreceived++;
		}
	}

	return 0;
}


struct addrinfo *ResolveAddress(char *addr, char *port, int af, int type, int proto)
{
	struct addrinfo hints,
		*res = NULL;
	int             rc;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags  = ((addr) ? 0 : AI_PASSIVE);
	hints.ai_family = af;
	hints.ai_socktype = type;
	hints.ai_protocol = proto;

	rc = getaddrinfo(addr, port, &hints, &res);
	if (rc != 0)
	{
		printf("Invalid address %s, getaddrinfo() failed with error code %d\n", addr, rc);
		return NULL;
	}
	else
		printf("ResolveAddress(): getnameinfo() is OK!\n");

	return res;
}

char sendBuf[BUFSIZE];

void sendEcho()
{
	struct ip ip;
	ip.ip_hl = 0x5;
	ip.ip_v = 0x4;
	ip.ip_tos = 0x0;
	ip.ip_id = htons(12830);
	ip.ip_off = 0x0;
	ip.ip_ttl = ttl;
	ip.ip_p = IPPROTO_ICMP;
	ip.ip_sum = 0x0;
	ip.ip_src = srcIP;
	ip.ip_dst.s_addr = servAddr.sin_addr.s_addr;        //inet_addr("172.16.1.204");

	ip.ip_len = sizeof(ip)+8 + icmpData_len;
	ip.ip_sum = in_cksum((u_int16_t *)& ip, sizeof(ip));
	memcpy(sendBuf, &ip, sizeof(ip));

	struct icmp *icmp = (struct icmp *) ((char *)sendBuf + sizeof(ip));

	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_seq = nsent++;

	int icmplen = 8 + icmpData_len;
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum((u_int16_t *)icmp, icmplen);
	int bytesSent = sendto(sendDescr, sendBuf, ip.ip_len, 0, (struct sockaddr *) &servAddr, sizeof(servAddr));
	if (bytesSent <= 0)
	{
		perror("sendto() failed");
		exit(-1);
	}
}

u_int16_t in_cksum(u_int16_t * addr, int len)
{
	u_int32_t sum = 0;

	// Calculate sum of all double-byte words
	while (len > 1) {
		sum += *addr++;
		len -= 2;
	}

	// add odd byte
	if (len == 1)
		sum += *(u_int8_t *)addr;

	sum = (sum >> 16) + (sum & 0xFFFF); // add carry
	sum += (sum >> 16);         // again

	u_int16_t result = ~sum;    // invert result
	return result;
}

in_addr getSourceIP(in_addr destIP)
{
	int udpDescr = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (udpDescr < 0)
	{
		perror("Create socket error");
		exit(-1);
	}

	struct sockaddr_in addr;
	addr.sin_family = PF_INET;
	addr.sin_addr.s_addr = destIP.s_addr;

	if (connect(udpDescr, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("connect()");
		exit(-1);
	}

	struct sockaddr_in destAddr;
	socklen_t addrLen = sizeof(destAddr);

	if (getsockname(udpDescr, (struct sockaddr *) &destAddr, &addrLen) < 0) {

		perror("getsockname()");
		exit(-1);
	}
	CLOSE_SOCKET(udpDescr);
	return destAddr.sin_addr;
}



#ifdef WIN32

void startUp()
{
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
}
void cleanUp()
{
	WSACleanup();
}

#endif

#ifdef __unix__

void startUp()
{
	return;
}
void cleanUp()
{
	return;
}

#endif


