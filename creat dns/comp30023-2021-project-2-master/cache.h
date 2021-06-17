
#ifndef CACHE_H
#define CACHE_H
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/types.h>

#define MAX_CACHE_SIZE 5

typedef struct dns_packet {
	char* buf;
	ssize_t bufSize;
	int* ttlOffset;
	int ttlOffsetNum;
}DNS_PACKET;

//Cache uses a linked list to store data
typedef struct cache_node CACHE_NODE;
struct cache_node {
	char* url;
	time_t beginTime;
	time_t expireTime;
	DNS_PACKET* packet;
	CACHE_NODE* prev;
	CACHE_NODE* next;
};

typedef struct cache {
	pthread_mutex_t lock;
	CACHE_NODE* head;
	CACHE_NODE* tail;
	int size;
} CACHE;

//Initialize the cache
CACHE*	cache_init();

//return the cache object of url
//or NULL if no cache
DNS_PACKET*	cache_get(CACHE* cache, const char *url, int logfd);

//add a url data to cache
void	cache_add(CACHE* cache, const char* url, DNS_PACKET *packet,time_t expireTime, int logfd);


#endif /* CACHE_H */
