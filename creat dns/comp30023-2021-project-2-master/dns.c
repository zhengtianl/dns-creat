
#include "dns.h"

ssize_t dns_read(int fd, char* buf, size_t bufSize)
{
	ssize_t readSize = 0;
	ssize_t result;

	while (1) {
		result = read(fd, buf + readSize, bufSize - readSize);
		if (result <= 0) return -1;
		readSize += result;
		if (readSize >= bufSize) break;
	}
	return 1;

}
ssize_t dns_write(int fd, char* buf, size_t bufSize)
{
	ssize_t readSize = 0;
	ssize_t result;

	while (1) {
		result = write(fd, buf + readSize, bufSize - readSize);
		if (result <= 0) return -1;
		readSize += result;
		if (readSize >= bufSize) break;
	}
	return 1;

}

//////////////////////////////////////////////////////////////////////////

DNS_T* dns_init(char* dnsServerIP, char* dnsServerPort)
{
	int logfd = open("dns_svr.log", O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (logfd == -1) {
		perror("open log file");
		return NULL;
	}
	DNS_T* dns = (DNS_T*)malloc(sizeof(DNS_T));
	memset(dns, 0, sizeof(DNS_T));
	if (dnsServerIP) {
		int ipLen = strlen(dnsServerIP);
		dns->dnsServerIP = malloc(ipLen + 1);
		memcpy(dns->dnsServerIP, dnsServerIP, ipLen);
		dns->dnsServerIP[ipLen] = 0;
	}
	if (dnsServerPort) {
		dns->dnsServerPort = atoi(dnsServerPort);
	}
	dns->logfd = logfd;
	dns->cache = cache_init();
	return dns;
}
void dns_free(DNS_T* dns)
{
	free(dns->dnsServerIP);
	close(dns->logfd);
	free(dns);
}


DNS_PACKET* dns_read_packet(int fd)
{
	u_int16_t nPacketLen = 0;
	if (dns_read(fd, (char*)&nPacketLen, sizeof(u_int16_t)) == -1) return NULL;
	u_int16_t hPacketLen = ntohs(nPacketLen);

	int bufSize = sizeof(u_int16_t) + hPacketLen;
	char* buf = malloc(bufSize);
	memcpy(buf, &nPacketLen, sizeof(u_int16_t));

	if (dns_read(fd, buf + sizeof(u_int16_t), hPacketLen) == -1) {
		free(buf);
		return NULL;
	}

	DNS_PACKET* packet = (DNS_PACKET*)malloc(sizeof(DNS_PACKET));
	memset(packet, 0, sizeof(DNS_PACKET));
	packet->buf = buf;
	packet->bufSize = bufSize;
	return packet;
}

int	dns_write_packet(int fd, DNS_PACKET* packet)
{
	return dns_write(fd, packet->buf, packet->bufSize);
}

void dns_free_packet(DNS_PACKET* packet)
{
	if (packet->ttlOffset) {
		free(packet->ttlOffset);
	}
	free(packet->buf);
	free(packet);
}

DNS_PACKET *dns_copy_packet(DNS_PACKET* packet)
{
	DNS_PACKET* newPacket = malloc(sizeof(DNS_PACKET));
	memset(newPacket, 0, sizeof(DNS_PACKET));
	int bufSize = packet->bufSize;
	newPacket->buf = malloc(bufSize);
	memcpy(newPacket->buf, packet->buf, bufSize);
	newPacket->bufSize = bufSize;
	newPacket->ttlOffsetNum = packet->ttlOffsetNum;
	if (packet->ttlOffset) {
		int len = sizeof(int) * packet->ttlOffsetNum;
		newPacket->ttlOffset = malloc(len);
		memcpy(newPacket->ttlOffset, packet->ttlOffset, len);
	}

	return newPacket;
}
int	dns_get_uint16_from_packet(char* packetBuf, int packetSize, int offset, u_int16_t* v)
{
	if (offset + sizeof(u_int16_t) > packetSize) return -1;
	if(v) *v = ntohs(*(u_int16_t*)(packetBuf + offset));
	offset += sizeof(u_int16_t);
	return offset;
}
int	dns_get_uint32_from_packet(char* packetBuf, int packetSize, int offset, u_int32_t* v)
{
	if (offset + sizeof(u_int32_t) > packetSize) return -1;
	*v = ntohl(*(u_int32_t*)(packetBuf + offset));
	offset += sizeof(u_int32_t);
	return offset;
}
DNS_HEADER* dns_get_header_from_packet(DNS_PACKET* packet)
{
	return (DNS_HEADER*)(packet->buf + sizeof(u_int16_t));
}

int	dns_log_format_time(time_t t, char* buf, int bufLen)
{
	struct tm* info = localtime(&t);
	return strftime(buf, bufLen, "%FT%T%z", info);
}
int	dns_log_time(char* buf, int bufLen)
{
	time_t t;
	time(&t);
	return dns_log_format_time(t, buf, bufLen);
}

int dns_parse_name_label(char* packetBuf, int packetSize, int offset, char *nameBuf,int nameBufLen)
{
	u_int8_t sectionLen;
	int nameLen = 0;
	while (1) {
		if (offset >= packetSize) return -1;
		sectionLen = (u_int8_t)packetBuf[offset++];
		if (sectionLen == 0) break;
		if (offset + sectionLen > packetSize) return -1;
		if (nameLen + sectionLen >= nameBufLen) return -1;
		if (nameBuf) {
			memcpy(nameBuf + nameLen, packetBuf + offset, sectionLen);
			offset += sectionLen;
			nameLen += sectionLen;
			if (nameLen + 1 >= nameBufLen) return -1;
			nameBuf[nameLen++] = '.';
		}
	}
	if (nameLen > 0) {
		nameLen--;
		if(nameBuf) nameBuf[nameLen] = 0;
	}

	return offset;
}
int dns_get_qname(DNS_T* dns, DNS_PACKET* packet, int offset, DNS_QUESTION* question)
{
	if (offset < 0) {
		offset = sizeof(u_int16_t) + sizeof(DNS_HEADER);
	}
	char* packetBuf = packet->buf;
	int packetSize = packet->bufSize;
	offset = dns_parse_name_label(packetBuf, packetSize, offset, question->name, sizeof(question->name));
	if (offset == -1) return -1;

	offset = dns_get_uint16_from_packet(packetBuf, packetSize, offset, &question->type);
	if (offset == -1) return -1;

	offset = dns_get_uint16_from_packet(packetBuf, packetSize, offset, &question->class);
	if (offset == -1) return -1;
	return offset;
}
int dns_parse_request(DNS_T *dns,DNS_PACKET* packet, DNS_PACKET** cachePacket)
{
	DNS_QUESTION question;
	int offset = dns_get_qname(dns, packet, -1, &question);
	if (offset < 0) return RCODE_FORMAT_ERROR;

	dns_write_log(dns->logfd, "requested %s\n", question.name);
	if (question.type != QTYPE_AAAA) {
		dns_write_log(dns->logfd, "unimplemented request\n");

		return RCODE_NOT_IMPLEMENTED;
	}

	if (cachePacket) {
		DNS_PACKET *cp = cache_get(dns->cache, question.name, dns->logfd);
		if (cp) {
			dns_get_header_from_packet(cp)->id = dns_get_header_from_packet(packet)->id;
		}
		*cachePacket = cp;
	}

	return RCODE_NO_ERROR;
}

void	dns_response_error(int sock, DNS_T* dns, DNS_PACKET* packet, int rcode)
{
	DNS_HEADER* header = dns_get_header_from_packet(packet);
	header->qr = QR_RESPONSE;
	header->rd = 0;
	header->rcode = rcode;
	dns_write_packet(sock, packet);
}
int	dns_parse_resource_record(DNS_T* dns, char* packetBuf, int packetSize, int offset, DNS_RESOURCE_RECORD* dnsRR)
{
	if (offset >= packetSize) return -1;
	u_int8_t flag = (packetBuf[offset] & 0xC0);
	if (flag == 0xC0) {
		offset += sizeof(u_int16_t);
 	}
	else if(flag == 0x00){
		offset = dns_parse_name_label(packetBuf, packetSize, offset, NULL, 0);
		if (offset == -1) return -1;
	}
	else {
		return -1;
	}
	offset = dns_get_uint16_from_packet(packetBuf, packetSize, offset, &dnsRR->type);
	if (offset == -1) return -1;

	offset = dns_get_uint16_from_packet(packetBuf, packetSize, offset, NULL);
	if (offset == -1) return -1;

	offset = dns_get_uint32_from_packet(packetBuf, packetSize, offset, &dnsRR->ttl);
	if (offset == -1) return -1;
	dnsRR->ttlOffset = offset - sizeof(u_int32_t);

	u_int16_t rdLength;
	offset = dns_get_uint16_from_packet(packetBuf, packetSize, offset, &rdLength);
	if (offset == -1) return -1;

	if (rdLength) {
		dnsRR->rdData = packetBuf + offset;
	}
	else {
		dnsRR->rdData = NULL;
	}
	offset += rdLength;
	return offset;
}

int	dns_parse_response(DNS_T *dns,DNS_PACKET *packet,int saveCache)
{
	DNS_HEADER* header = dns_get_header_from_packet(packet);
	int qcount = ntohs(header->qdcount);
	if(qcount != 1) return RCODE_FORMAT_ERROR;
	int offset = -1;
	DNS_QUESTION question;
	offset = dns_get_qname(dns, packet, offset, &question);
	if (offset < 0) return RCODE_FORMAT_ERROR;

	DNS_RESOURCE_RECORD* logDNSRR = NULL;
	int ancount = ntohs(header->ancount);
	if (ancount > 0) {
		int num = ancount + ntohs(header->nscount) + ntohs(header->arcount);
		int* ttlOffset = malloc(sizeof(int)*num);
		char strIP[INET6_ADDRSTRLEN];
		memset(strIP, 0, sizeof(strIP));
		DNS_RESOURCE_RECORD dnsRR;
		int i;
		int minTTL = 0;
		for (i = 0; i < num; i++) {
			offset = dns_parse_resource_record(dns, packet->buf, packet->bufSize, offset, &dnsRR);
			if (offset == -1) {
				free(ttlOffset);
				return RCODE_FORMAT_ERROR;
			}
			ttlOffset[i] = dnsRR.ttlOffset;
			if (i == 0) {
				if (dnsRR.type == QTYPE_AAAA) {
					inet_ntop(AF_INET6, dnsRR.rdData, strIP, INET6_ADDRSTRLEN);
				}
				minTTL = dnsRR.ttl;
			}
			else if(dnsRR.ttl > 0 && dnsRR.ttl < minTTL){
				minTTL = dnsRR.ttl;
			}
		}
		if (saveCache) {
			time_t t;
			time(&t);
			DNS_PACKET* cachePacket = dns_copy_packet(packet);
			cachePacket->ttlOffset = ttlOffset;
			cachePacket->ttlOffsetNum = num;
			cache_add(dns->cache, question.name, cachePacket, minTTL + t, dns->logfd);
		}
		if (strIP[0]) {
			dns_write_log(dns->logfd, "%s is at %s\n", question.name, strIP);
		}
	}
	return RCODE_NO_ERROR;
}


void dns_write_log(int fd,const char* fmt, ...)
{
	char buf[2048];
	int writeLen = dns_log_time(buf, MAX_TIMESTAMP_SIZE);
	buf[writeLen++] = ' ';
	va_list argp;
	va_start(argp, fmt);
	int ret = vsnprintf(buf + writeLen, sizeof(buf) - writeLen - 1, fmt, argp);
	va_end(argp);
	if (ret >= 0) {
		writeLen += ret;
	}
	write(fd, buf, writeLen);
}
