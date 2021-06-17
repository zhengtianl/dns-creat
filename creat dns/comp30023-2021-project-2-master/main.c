
#include "dns.h"

#define CACHE
#define NONBLOCKING

void sigpipe_handler(int sig)
{

}

int open_listen()
{
	int listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1) {
		perror("socket");
		return -1;
	}
	int on = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));

	struct sockaddr_in server_sockaddr;
	server_sockaddr.sin_family = AF_INET;
	server_sockaddr.sin_port = htons(8053);
	server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	//bind
	if (bind(listenfd, (struct sockaddr*)&server_sockaddr, sizeof(server_sockaddr)) < 0)
	{
		perror("bind");
		close(listenfd);
		return -1;
	}
	//listen
	if (listen(listenfd, SOMAXCONN) < 0)
	{
		perror("listen");
		close(listenfd);
		return - 1;
	}
	return listenfd;
}

int	accept_socket(int listenfd)
{
	struct sockaddr_in client_addr;
	socklen_t length = sizeof(client_addr);
	int sock = accept(listenfd, (struct sockaddr*)&client_addr, &length);
	if (sock < 0) {
		perror("accept");
		return -1;
	}
	return sock;
}
int connect_socket(char *ip,int port)
{
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		perror("connect socket");
		return -1;
	}
	struct sockaddr_in server_address;
	memset(&server_address, 0,sizeof(server_address));
	server_address.sin_family = AF_INET;
	inet_pton(AF_INET, ip, &server_address.sin_addr);
	server_address.sin_port = htons(port);
	if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
		perror("connect");
		close(sock);
		return -1;
	}
	return sock;
}


typedef struct thread_param {
	DNS_T* dns;
	int sock;
}THREAD_PARAM;

void* handle_thread(void* arg)
{
	pthread_detach(pthread_self());

	THREAD_PARAM* param = (THREAD_PARAM*)arg;
	DNS_T* dns = param->dns;
	int clientSock = param->sock;
	int serverSock = -1;
	DNS_PACKET* serverPacket = NULL;
	DNS_PACKET* clientPacket = dns_read_packet(clientSock);
	if (!clientPacket) goto exit;
	DNS_PACKET* cachePacket = NULL;
	int rcode = dns_parse_request(dns, clientPacket, &cachePacket);
	if (rcode != RCODE_NO_ERROR) {
		dns_response_error(clientSock,dns, clientPacket,rcode);
		goto exit;
	}
	if (cachePacket) {
		dns_parse_response(dns, cachePacket, 0);
		dns_write_packet(clientSock, cachePacket);
		dns_free_packet(cachePacket);
	}
	else {
		serverSock = connect_socket(dns->dnsServerIP, dns->dnsServerPort);
		if (serverSock < 0 || dns_write_packet(serverSock, clientPacket) == -1) {
			dns_response_error(clientSock, dns, clientPacket, RCODE_SERV_FAIL);
			goto exit;
		}
		serverPacket = dns_read_packet(serverSock);
		if (!serverPacket) {
			dns_response_error(clientSock, dns, clientPacket, RCODE_SERV_FAIL);
			goto exit;
		}
		dns_parse_response(dns, serverPacket,1);
		dns_write_packet(clientSock, serverPacket);
	}

exit:
	if (clientPacket) {
		dns_free_packet(clientPacket);
	}
	if (serverPacket) {
		dns_free_packet(serverPacket);
	}
	if (serverSock > 0) {
		close(serverSock);
	}
	close(clientSock);
	free(param);
	return NULL;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("usage: dns_svr [dns server address] [dns server port]\n");
		exit(EXIT_FAILURE);
    }
	struct sigaction sig;
	sigemptyset(&sig.sa_mask);
	sig.sa_flags = 0;
	sig.sa_handler = sigpipe_handler;
	sigaction(SIGPIPE, &sig, NULL);
    
	DNS_T* dns = dns_init(argv[1], argv[2]);
	if (!dns) {
		exit(EXIT_FAILURE);
	}

	int listenfd = open_listen();
	if (listenfd < 0) {
		exit(EXIT_FAILURE);
	}

	//connect
	while (1) {
		int sock = accept_socket(listenfd);
		if (sock < 0) continue;

		pthread_t ntid;
		THREAD_PARAM *param = (THREAD_PARAM*)malloc(sizeof(THREAD_PARAM));
		param->dns = dns;
		param->sock = sock;
		int err = pthread_create(&ntid, NULL, handle_thread, param);
		if (err != 0) {
			free(param);
			close(sock);
		}
	}
	close(listenfd);

    return 0;
}
