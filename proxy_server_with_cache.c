#include "proxy_parse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/wait.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>


#define MAX_CLIENTS 10
typedef struct cache_element cache_element;

struct cache_element{
    char* data;
    int len;
    char* url;
    time_t lru_time;
    cache_element* next;
};

// Functions to add, remove and find elements in linked list of cache elements
cache_element* find_cache_element(char* url);
int add_cache_element(char* data, int len, char* url);
void remove_cache_element();

int port_number = 8080;
int proxy_socket_id;
pthread_t tid[MAX_CLIENTS];
sem_t semaphore;
pthread_mutex_t lock;





