#include "cache.h"
#include "dns.h"

//Initialize the cache
CACHE* cache_init()
{
	CACHE* cache = (CACHE*)malloc(sizeof(CACHE));

	pthread_mutex_init(&cache->lock, NULL);
	cache->head = NULL;
	cache->tail = NULL;
	cache->size = 0;
	
	return cache;
}

//remove a cache node from the linked list
void	cache_remove_node(CACHE* cache, CACHE_NODE* node)
{
	CACHE_NODE *prev = node->prev;
	CACHE_NODE* next = node->next;
	if (prev) {
		prev->next = next;
	}
	if (next) {
		next->prev = prev;
	}
	node->prev = NULL;
	node->next = NULL;

	if (node == cache->head) {
		cache->head = next;
	}
	if (node == cache->tail) {
		cache->tail = prev;
	}
}

//add a cache node to the head of the linked list
void	cache_add_node(CACHE* cache, CACHE_NODE* node)
{
	CACHE_NODE* head = cache->head;
	CACHE_NODE* tail = cache->tail;


	if (head) {
		head->prev = node;
	}
	node->next = head;
	node->prev = NULL;
	cache->head = node;

	if (!tail) {
		cache->tail = node;
	}
}

//get the cache of the url
DNS_PACKET* cache_get(CACHE* cache, const char* url,int logfd)
{
	DNS_PACKET* packet = NULL;
	time_t expireTime = 0;
	time_t beginTime = 0;
	time_t t;
	time(&t);
	pthread_mutex_lock(&cache->lock);
	CACHE_NODE* node = cache->head;
	while (node) {
		if (strcasecmp(url, node->url) == 0) {
			//hit,and move the node to head
			expireTime = node->expireTime;
			if (t < expireTime) {
				beginTime = node->beginTime;
				packet = dns_copy_packet(node->packet);
				cache_remove_node(cache, node);
				cache_add_node(cache, node);
			}
			break;
		}
		node = node->next;
	}
	pthread_mutex_unlock(&cache->lock);
	if (expireTime != 0 && t < expireTime ) {
		char expireTimestamp[MAX_TIMESTAMP_SIZE];
		dns_log_format_time(expireTime, expireTimestamp, MAX_TIMESTAMP_SIZE);
		dns_write_log(logfd, "%s expires at %s\n", url, expireTimestamp);
	}

	if (packet) {
		int num = packet->ttlOffsetNum;
		int i;
		u_int32_t *ttl;
		int ttlValue;
		int elapsedTime = t - beginTime;
		for (i = 0; i < num; i++) {
			ttl = (u_int32_t*)(packet->buf + packet->ttlOffset[i]);
			ttlValue = ntohl(*ttl);
			ttlValue -= elapsedTime;
			if (ttlValue < 0) {
				ttlValue = 0;
			}
			*ttl = htonl(ttlValue);
		}
	}

	return packet;
}


//add a url data to cache
void cache_add(CACHE* cache, const char* url, DNS_PACKET* packet, time_t expireTime, int logfd)
{
	time_t t;
	time(&t);

	CACHE_NODE* node;
	CACHE_NODE* replacedNode = NULL;

	pthread_mutex_lock(&cache->lock);
	node = cache->head;
	while (node) {
		if (strcasecmp(url, node->url) == 0) {
			replacedNode = node;
			break;
		}
		node = node->next;
	}
	if(!replacedNode && cache->size >= MAX_CACHE_SIZE) {
		node = cache->tail;
		while (node) {
			if(t >= node->expireTime) {
				replacedNode = node;
				break;
			}
			node = node->prev;
		}
		if (!replacedNode) {
			replacedNode = cache->tail;
		}
	}
	if (replacedNode) {
		cache_remove_node(cache, replacedNode);
		cache->size--;
	}
	node = (CACHE_NODE*)malloc(sizeof(CACHE_NODE));
	int urlLen = strlen(url);
	node->url = (char*)malloc(urlLen + 1);
	memcpy(node->url, url, urlLen);
	node->url[urlLen] = 0;
	node->packet = packet;
	node->beginTime = t;
	node->expireTime = expireTime;
	cache_add_node(cache, node);
	cache->size ++;
	pthread_mutex_unlock(&cache->lock);
	if (replacedNode) {
		dns_write_log(logfd, "replacing %s by %s\n", replacedNode->url,url);
		dns_free_packet(replacedNode->packet);
		free(replacedNode->url);
		free(replacedNode);
	}
}
