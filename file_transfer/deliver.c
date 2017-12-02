/*
 * deliver.c -- Execution: deliver <server address> <server port number>
 * 1) Ask user to input message as: ftp <file name>
 * 2) If file exists, send message "ftp" to server, else exit
 * 3) Receive message from server: if message is "yes", print out 
 *    "A file transfer can start", else exit
 * 4) Break the file into multiple packets of 1000 bytes each
 * 5) Send a packet as total_frag:frag_no:size:filename:filedata
 * 6) Start a timer, if before the end of the timer, an ACK is received,
 *    everything is good. If the timer runs out, retransmit the packet
 */

#include "helper.h"

int main (int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "usage: deliver <server address> <server port number>\n");
        exit(1); 
    }

    int sockfd;
    struct addrinfo hints, *res = NULL, *p = NULL;
    int status;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

     if ((status = getaddrinfo(argv[1], argv[2], &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return 1;
    }

    // Loop through all the results and make a socket
    for (p = res; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("deliver: socket");
            continue;
        }
        break;
    }

    if (p == NULL) {
        fprintf(stderr, "deliver: failed to create socket\n");
        return 1;
    }

    char cmd[10], file_name[FILENAMESIZE];
    bool file_exists = false;
    int numbytes_sent = 0;
    
    printf("Enter file name as: ftp <file_name>\n");
    scanf("%s %s", cmd, file_name);
    
    if (strcmp(cmd, "ftp") == 0) {
        if (access(file_name, F_OK) != -1) {
            file_exists = true;  
        }
        else {
            fprintf(stderr, "File not found\n");
            return 1;
        }
    }
    else {
        fprintf(stderr, "Entered the wrong command. Enter file name as: ftp <file_name>\n");
        return 2;
    }

    clock_t cpu_start = clock();

    if (file_exists) {
        // Send message "ftp" to server
        if ((numbytes_sent = sendto(sockfd, cmd, strlen(cmd), 0,
            p->ai_addr, p->ai_addrlen)) == -1) {
            perror("deliver: sendto");
            return 1;
        }
    }

    freeaddrinfo(res);
    printf("deliver: waiting to receive from...\n");

    struct sockaddr_storage their_addr;
    int their_addr_len = sizeof(their_addr), numbytes_rcvd = 0;
    char buf[MAXBUFLEN], s[INET6_ADDRSTRLEN];

    if ((numbytes_rcvd = recvfrom(sockfd, buf, MAXBUFLEN-1, 0,
        (struct sockaddr *)&their_addr, &their_addr_len)) == -1) {
        perror("deliver: recvfrom");
        return 1;
    }
    
    clock_t cpu_end = clock();
    
    printf("deliver: got packet from %s\n", inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr), s, sizeof(s)));
    printf("deliver: packet is %d bytes long\n", numbytes_rcvd);
    buf[numbytes_rcvd] = '\0';
    printf("deliver: packet containes \"%s\"\n", buf);

    if (strcmp(buf, "yes") == 0) {
        printf("A file transfer can start.\n");
    }
    else {
        return 1;
    }

    float diff = ((float)(cpu_end - cpu_start) / 1000000.0F)*1000;
    printf("Time Diff: %f\n", diff);

    unsigned long size = get_file_size(file_name);
    printf("File size %d\n", size);

    unsigned long num_packets = size/(unsigned long)MAXPKTDATASIZE + 1;
    printf("Num packets: %d\n", num_packets);

    FILE *fh;
    fh = fopen(file_name, "rb");        // Open the file in binary mode

    struct packet pkt;
    pkt.total_frag = num_packets;
    pkt.filename = file_name;

    char *pkt_string, ack[ACKLEN]; 
    unsigned int pkt_i, pkt_size, offset = 0, pkt_len = 0;

    // Set timer for recv socket
    struct timeval tv = {0,TIMER_DURATION};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
    bool success = false;

    for (pkt_i = 0; pkt_i < num_packets; ++pkt_i) {
        pkt.frag_no = pkt_i+1;
        pkt_size = min(MAXPKTDATASIZE, size);
        size -= pkt_size;
        pkt.size = pkt_size;
        offset += pkt_size;
        fread(pkt.filedata, pkt_size, 1, fh);
        fseek(fh, offset, SEEK_SET);
        print_packet(&pkt);
        pkt_string = create_packet_string(&pkt, &pkt_len);
        success = false;

        while (!success) {
            // Send packet string to server
            printf("Transmitting packet\n");
            /*
             * If you remove the commented if statement, it simulates a lost last packet
             * i.e. the last packet of the file is not sent to the server, simulating a
             * packet is lost. So, the  deliver doesn't receive an ACK packet, timer runs out
             * and it keeps trying to retransmit the packet (which again doesn't get sent) :(
             */
            //if (pkt_i != (num_packets - 1)) {
                if ((numbytes_sent = sendto(sockfd, pkt_string, pkt_len, 0,
                    (struct sockaddr *)&their_addr, their_addr_len)) == -1) {
                    perror("deliver: sendto");
                    return 1;
                }
            //}

            while (1) {
                if ((numbytes_rcvd = recvfrom(sockfd, ack, ACKLEN - 1, 0,
                    (struct sockaddr *)&their_addr, &their_addr_len)) < 0) {
                    // Timer ran out and did not receive ACK
                    success = false;
                    printf("Timer ran out!\n");
                    break;
                }
                else {
                    success = true;
                }

                if (success) {
                    printf("deliver: got packet from %s\n", inet_ntop(their_addr.ss_family,
                        get_in_addr((struct sockaddr *)&their_addr), s, sizeof(s)));
                    printf("deliver: packet is %d bytes long\n", numbytes_rcvd);
                    ack[numbytes_rcvd] = '\0';
                    printf("deliver: packet contains \"%s\"\n", ack);

                    if (strcmp(ack, "ACK") == 0) {
                        break;
                    }
                }
            }
        }

        free(pkt_string);
    }

    close(sockfd);
    return 0;
}   
