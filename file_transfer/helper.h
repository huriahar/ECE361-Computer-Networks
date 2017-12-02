#ifndef _HELPER_H_
#define _HELPER_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define MAXBUFLEN 100
#define FILENAMESIZE 100
#define MAXPKTDATASIZE 1000
#define MAXPACKETLEN 1200
#define ACKLEN 5
#define TIMER_DURATION 100000

#define max(a,b) \
    ({__typeof__ (a) _a = (a); \
        __typeof__ (b) _b = (b); \
        _a > _b ? _a : _b; })

#define min(a,b) \
    ({__typeof__ (a) _a = (a); \
        __typeof__ (b) _b = (b); \
        _a < _b ? _a : _b; })

typedef struct packet {
    unsigned int total_frag;
    unsigned int frag_no;
    unsigned int size;
    char *filename;
    char filedata[MAXPKTDATASIZE];
} packet;

void *get_in_addr(struct sockaddr *sa);

unsigned long get_file_size (const char *file);
void print_packet(const packet *pkt);
char *create_packet_string(const packet *pkt, unsigned int *pkt_len);

#endif // _HELPER_H_
