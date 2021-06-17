#ifndef DNS_H
#define DNS_H
#include "cache.h"

#define MAX_QNAME_SIZE 2048
#define MAX_TIMESTAMP_SIZE 256

#define QTYPE_AAAA 28

#define RCODE_NO_ERROR			0
#define RCODE_FORMAT_ERROR		1
#define RCODE_SERV_FAIL			2
#define RCODE_NOT_IMPLEMENTED	4

#define QR_QUERY 0
#define QR_RESPONSE 1


#pragma pack(1)
typedef struct dns_header {
	u_int16_t id; /* a 16 bit identifier assigned by the client */

	u_int8_t	rd : 1;
	u_int8_t	tc : 1;
	u_int8_t	aa : 1;
	u_int8_t	opcode : 4;
	u_int8_t	qr : 1;

	u_int8_t	rcode : 4;
	u_int8_t	z : 3;
	u_int8_t	ra : 1;

	u_int16_t qdcount;
	u_int16_t ancount;
	u_int16_t nscount;
	u_int16_t arcount;
} DNS_HEADER;


#pragma pack()

typedef struct dns_question {
	char name[MAX_QNAME_SIZE];
	u_int16_t type;
	u_int16_t class;
}DNS_QUESTION;

typedef struct dns_resource_record {
	u_int16_t type;
	u_int32_t ttl;
	char* rdData;
	int ttlOffset;
}DNS_RESOURCE_RECORD;



typedef struct dns_t {
	char* dnsServerIP;
	int dnsServerPort;
	int logfd;
	CACHE* cache;
}DNS_T;

DNS_T* dns_init(char* dnsServerIP, char* dnsServerPort);
void dns_free(DNS_T *dns);

DNS_PACKET* dns_read_packet(int fd);
int	dns_write_packet(int fd, DNS_PACKET* packet);
void dns_free_packet(DNS_PACKET *packet);
DNS_PACKET* dns_copy_packet(DNS_PACKET* packet);

int		dns_log_format_time(time_t t, char* buf, int bufLen);
int		dns_log_time(char* buf, int bufLen);

int		dns_parse_request(DNS_T* dns, DNS_PACKET* packet, DNS_PACKET** cachePacket);
void	dns_response_error(int sock, DNS_T* dns, DNS_PACKET* packet, int rcode);
int		dns_parse_response(DNS_T* dns, DNS_PACKET* packet, int saveCache);

void	dns_write_log(int fd, const char* fmt, ...);
#endif

