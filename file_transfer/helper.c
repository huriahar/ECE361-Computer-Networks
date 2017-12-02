#include "helper.h"

// get sockaddr, IPv4 or IPv6
void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    else {
        return &(((struct sockaddr_in6*)sa)->sin6_addr);
    }
}

unsigned long get_file_size(const char *file) {
    struct stat st;
    if (stat(file, &st) == 0)
        return (unsigned long)st.st_size;

    fprintf(stderr, "file_size: cannot determine size of %s: %s\n", file, strerror(errno));
    return 0;
}

void print_packet (const packet *pkt) {
    printf("total_frag: %d\nfrag_no: %d\nsize: %d\nfilename: %s\n", pkt->total_frag, 
        pkt->frag_no, pkt->size, pkt->filename);
}

char *create_packet_string(const packet *pkt, unsigned int *pkt_len) {
    unsigned int size_usi = sizeof(unsigned int);
    unsigned int size_fn = strlen(pkt->filename);
    // Space for 3 unisgned int + filename +file data + 4 ':'
    unsigned int size = 3*size_usi + size_fn + pkt->size + 4;
    (*pkt_len) = size;

    char *pkt_string = malloc(size);
    memset(pkt_string, 0, size);

    unsigned int offset = 0;

    // Set total_frag
    memcpy(pkt_string, (char *)&(pkt->total_frag), size_usi);
    offset += size_usi;
    pkt_string[offset++] = ':';

    // Set frag_no
    memcpy(pkt_string + offset, (char *)&(pkt->frag_no), size_usi);
    offset += size_usi;
    pkt_string[offset++] = ':';

    // Set size
    memcpy(pkt_string + offset, (char *)&(pkt->size), size_usi);
    offset += size_usi;
    pkt_string[offset++] = ':';

    // Set filename
    memcpy(pkt_string + offset, pkt->filename, size_fn);
    offset += size_fn;
    pkt_string[offset++] = ':';

    // Set filedata
    memcpy(pkt_string + offset, pkt->filedata, pkt->size);

    return pkt_string;
}