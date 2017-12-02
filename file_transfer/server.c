/*
 * server.c -- Execution: server <UDP listen port>
 * 1) Open a UDP socket and listen at the specified port number
 * 2) Receive a message from the client:
 * If message is "ftp", reply "yes" else "no"
 * 3) Start receiving packets from deliver. If it is the first packet received,
 *    open a new file and start writing out the received data to it
 * 4) Send an ACK packet to deliver for each packet received
 */

 #include "helper.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: server <UDP listen port>\n");
        return 1;
    }
    
    struct addrinfo hints, *res = NULL, *p = NULL;
    int status;
    int sockfd;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;    // set to AF_INET to force IPv4. Currently, don't care IPv4 or IPv6
    hints.ai_socktype = SOCK_DGRAM; // UDP sockets
    hints.ai_flags = AI_PASSIVE;    // fill in my IP for me

    if ((status = getaddrinfo(NULL, argv[1], &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return 2;
    }

    // res now points to a linked list of 1 or more struct addrinfos
    
    // Loop through all the results and bind to the first socket we can
    for (p = res; p != NULL; p = p->ai_next) {
        // make a socket
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        // bind it to the port we passed in to getaddrinfo()
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "server: failed to bind socket\n");
        return 2;
    }

    freeaddrinfo(res);        // free the linked list

    // Keep listening on that port
    while (1) {
        printf("server: waiting to recvfrom...\n");

        struct sockaddr_storage their_addr;
        socklen_t their_addr_len;
        int numbytes_rcvd, numbytes_sent;
        char buf[MAXBUFLEN];
        char s[INET6_ADDRSTRLEN];

        their_addr_len = sizeof(their_addr);
        if ((numbytes_rcvd = recvfrom(sockfd, buf, MAXBUFLEN-1, 0,
            (struct sockaddr *)&their_addr, &their_addr_len)) == -1) {
            perror("server: recvfrom");
            exit(1);
        }

        printf("server: got packet from %s\n", 
            inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof(s)));
        printf("listener: packet is %d bytes long\n", numbytes_rcvd);
        buf[numbytes_rcvd] = '\0';
        printf("server: packet contains \"%s\"\n", buf);

        // If message is "ftp" reply a "yes" to the client, else "no"
        char yes_msg[4] = "yes", no_msg[3] = "no";
        char msg[4];
        if (strcmp(buf, "ftp") == 0) {
            strcpy(msg, yes_msg);
        }
        else {
            strcpy(msg, no_msg);
        }
        msg[strlen(msg) + 1] = '\0';

        // Send "yes" or "no" message
        if ((numbytes_sent = sendto(sockfd, msg, strlen(msg), 0,
            (struct sockaddr *)&their_addr, their_addr_len)) == -1) {
            perror("server: sendto");
            exit(1);
        }

        // Start receiving actual packets
        char packet[MAXPACKETLEN];
        unsigned int num_packets = 1, size_usi = sizeof(unsigned int),
         total_frag = 0, frag_no = 0, size = 0, offset = 0, i = 0, file_offset = 0;
        char ch, filename[FILENAMESIZE], *filedata, ack[5] = "ACK";
        ack[3] = '\0';
        FILE *fh;

        printf("Start receiving packets now\n");

        // Receive all packets and open up file handle if first packet
        while (num_packets > 0) {
            if ((numbytes_rcvd = recvfrom(sockfd, packet, MAXPACKETLEN, 0,
            (struct sockaddr *)&their_addr, &their_addr_len)) == -1) {
                perror("server: recvfrom");
                exit(1);
            }

            // Start parsing the packet
            memcpy(&total_frag, packet, size_usi);
            offset += size_usi;
            memcpy(&ch, packet+offset, 1);
            offset++;
            printf("total_frag: %d %c\n", total_frag, ch);

            memcpy(&frag_no, packet+offset, size_usi);
            offset += size_usi;
            memcpy(&ch, packet+offset, 1);
            offset++;
            printf("frag_no: %d %c\n", frag_no, ch);

            memcpy(&size, packet+offset, size_usi);
            offset += size_usi;
            memcpy(&ch, packet+offset, 1);
            offset++;
            printf("size: %d %c\n", size, ch);

            // Time to read file name now
            while (packet[offset] != ':') {
                filename[i++] = packet[offset++];
            }
            offset++;

            filename[i] = '\0';
            printf("filename: %s\n", filename);

            filedata = malloc(size);
            memcpy(filedata, packet+offset, size);           

            if (frag_no == 1) {
                num_packets = total_frag;
                fh = fopen(filename, "w");
            }

            // Check to see if you received a duplicate packet or not
            if (num_packets + frag_no > total_frag) {
                fwrite(filedata, 1, size, fh);
                file_offset += size;
                fseek(fh, file_offset, SEEK_SET);
                num_packets--;
                printf("Num packets left %d\n", num_packets);
            }
            else {
                // Got a repeat packet, so drop it
                printf("Got a repeat packet.. dropping it\n");
            }

            /*
             * If you remove the if statement, it simulates a lost last ACK packet i.e.
             * the ACK packet for the last packet received for the file never reaches the deliver
             * On the deliver side, timer runs out and it retransmits the packet again and again
             * On the server side, it receives a duplicate packet and does not process it.
             * The server just sends an ACK again (which again doesn't get sent :( )
             */
            //if (num_packets != 1) {
                // Send acknowledgement of the received packet - send ACK
                if ((numbytes_sent = sendto(sockfd, ack, strlen(ack), 0,
                    (struct sockaddr *)&their_addr, their_addr_len)) == -1) {
                    perror("server: sendto");
                    exit(1);
                }
            //}

            offset = 0;
            i = 0;
            memset(filename, 0, sizeof(filename));
        }
        fclose(fh);
    }
    close(sockfd);

    return 0;
}