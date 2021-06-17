#include "dns.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
		printf("usage: phase1 query|response [input file]\n");
        return 1;
    }

    if (argc >= 3) {
        int fd = open(argv[2], O_RDONLY);
		if (fd != -1) {
            dup2(fd, STDIN_FILENO);
		}
    }
	DNS_T* dns = dns_init(NULL,NULL);
	DNS_PACKET* packet = dns_read_packet(STDIN_FILENO);
    int result = 0;
    if (strcmp(argv[1], "query") == 0) {
        result = dns_parse_request(dns, packet, NULL);
    }
	else if (strcmp(argv[1], "response") == 0) {
        result = dns_parse_response(dns, packet,0);
	}

    dns_free(dns);

    return result;
}
