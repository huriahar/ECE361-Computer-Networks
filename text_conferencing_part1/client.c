/*
 * client.c -- Execution: client
 */

#include "helper.h"

const char *USER_NOT_LOGGED_IN = "User is not logged in. Login first";
const char *USER_NOT_IN_SESSION = "User is not joined in a session. Join a session first";
const char *USER_ALREADY_LOGGED_IN = "A user is already logged in. Logout first.";
const char *RECEIVED_NON_QU_ACK = "Received a non QU_ACK packet. Expecting response to list";

pthread_t recv_thread, client_thread;
pthread_mutex_t logon, join;

bool successfully_logged_in = false;
bool successfully_joined_session = false;

void *receive_message(void *d) {
    int sockfd = *((int *)d), numbytes = 0;
    char buf[MAXPACKETLEN];
    message *msg_rcvd = NULL;

    while (1) {
        bzero(buf, MAXPACKETLEN);
        if ((numbytes = recv(sockfd, buf, sizeof(buf), 0)) == -1) {
            perror("client: recv MESSAGE thread");
            close(sockfd);
            exit(1);
        }

        msg_rcvd = process_packet_string(buf, numbytes);
        if (msg_rcvd->type == NS_ACK) {
            pthread_mutex_lock(&join);
            successfully_joined_session = true;
            pthread_mutex_unlock(&join);
            printf("User %s successfully created and joined session %s\n\n", msg_rcvd->source, msg_rcvd->data);
        }
        else if (msg_rcvd->type == NS_NAK) {
            printf("User %s did not successfully create session. Error: %s\n\n", msg_rcvd->source, msg_rcvd->data);
        }
        else if (msg_rcvd->type == JN_ACK) {
            printf("User %s successfully joined session %s\n\n", msg_rcvd->source, msg_rcvd->data);
            pthread_mutex_lock(&join);
            successfully_joined_session = true;
            pthread_mutex_unlock(&join);
        }
        else if (msg_rcvd->type == JN_NAK) {
            printf("User %s did not successfully join session. Error: %s\n\n", msg_rcvd->source, msg_rcvd->data);
        }
        else if (msg_rcvd->type == QU_ACK) {
            printf("Printing users: sessions...\n");
            printf("%s\n", msg_rcvd->data);
        }
        else if (msg_rcvd->type == MESSAGE) {
            // Display the message
            printf("%s\n", msg_rcvd->data);
        }
    }

    free(msg_rcvd);
}

void *client_commands() {
    char instruction[INSN_SIZE], delim[3] = " \n", instruction_orig[INSN_SIZE];
    char *command, *user_name, *pass, *server_ip, *server_port, *session_id;

    int sockfd, numbytes;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET_ADDRSTRLEN];
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    message *msg_sent = NULL, *msg_rcvd = NULL;
    int data_len = 0;
    char *data;
    char *pkt_string;
    unsigned int pkt_len = 0;
    char buf[MAXPACKETLEN];
    char source[MAX_SOURCE_LEN];

    do {
        fgets(instruction, INSN_SIZE, stdin);
        strcpy(instruction_orig, instruction);
        // strtok will modify original string by replacing spaces with '\0'. So keep a copy of string if
        // instruction is a message being sent to the session
        command = strtok(instruction, delim);

        if (strcmp(command, "/login") == 0) {
            // Check if user is already logged in.. Do not allow multiple users to login from same execution
            if (successfully_logged_in) {
                printf("%s\n\n", USER_ALREADY_LOGGED_IN);
            }
            else {
                user_name = strtok(NULL, delim);
                pass = strtok(NULL, delim);
                server_ip = strtok(NULL, delim);
                server_port = strtok(NULL, delim);

                if ((rv = getaddrinfo(server_ip, server_port, &hints, &servinfo)) != 0) {
                    fprintf(stderr, "client: getaddrinfo: %s\n", gai_strerror(rv));
                    return (void *)1;
                }

                // Loop through all the results and conect to the first one we can
                for (p = servinfo; p != NULL; p = p->ai_next) {
                    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
                        perror("client: socket");
                        continue;
                    }
                    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
                        close(sockfd);
                        perror("client: connect");
                        continue;
                    }
                    break;
                }

                if (p == NULL) {
                    fprintf(stderr, "client: failed to connect\n");
                    return (void *)2;
                }

                inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
                    s, sizeof(s));
                printf("client: connecting to %s\n", s);
                freeaddrinfo(servinfo);

                // Control packet - login
                data_len = strlen(user_name) + strlen(pass) + 2;
                data = malloc(sizeof(char) * (data_len));
                strcpy(data,"");
                strcat(data, user_name);
                strcat(data, ",");
                strcat(data, pass);

                msg_sent = create_packet(LOGIN, data_len, user_name, data);

                pkt_string = create_packet_string(msg_sent, &pkt_len);

                if (send(sockfd, pkt_string, pkt_len, 0) == -1) {
                    perror("client: send login");
                }

                // Now wait to get an ACK - either password is correct or not
                if ((numbytes = recv(sockfd, buf, sizeof(buf), 0)) == -1) {
                    perror("client: recv LO_ACK/LO_NAK");
                    exit(1);
                }

                msg_rcvd = process_packet_string(buf, numbytes);

                if (msg_rcvd->type == LO_ACK) {
                    printf("User %s successfully logged in\n\n", user_name);
                    strcpy(source, user_name);
                    pthread_mutex_lock(&logon);
                    successfully_logged_in = true;
                    pthread_mutex_unlock(&logon);
                    pthread_create(&recv_thread, NULL, receive_message, (void*)&sockfd);
                }
                else if (msg_rcvd->type == LO_NAK) {
                    printf("User not successfully logged in. Error: %s\n\n", msg_rcvd->data);
                }

                free(data);
                free(pkt_string);
                free(msg_sent);
                free(msg_rcvd);
            }
        }
        else if (strcmp(command, "/logout") == 0) {
            if (!successfully_logged_in) {
                printf("%s\n\n", USER_NOT_LOGGED_IN);
            }
            else {
                msg_sent = create_packet(EXIT, 1, source, "");
                pkt_string = create_packet_string(msg_sent, &pkt_len);

                if (send(sockfd, pkt_string, pkt_len, 0) == -1) {
                    perror("client: send logout");
                }

                pthread_mutex_lock(&logon);
                successfully_logged_in = false;
                pthread_mutex_unlock(&logon);
                pthread_mutex_lock(&join);
                successfully_joined_session = false;
                pthread_mutex_unlock(&join);
                printf("User %s is successfully logged out\n\n", msg_sent->source);

                close(sockfd);
                pthread_cancel(recv_thread);

                free(msg_sent);
                free(pkt_string);
            }
        }
        else if (strcmp(command, "/joinsession") == 0) {
            session_id = strtok(NULL, delim);
            if (!successfully_logged_in) {
                printf("%s\n\n", USER_NOT_LOGGED_IN);
            }
            else {
                session_id[strlen(session_id)] = '\0';
                msg_sent = create_packet(JOIN, strlen(session_id)+1, source, session_id);

                pkt_string = create_packet_string(msg_sent, &pkt_len);

                if (send(sockfd, pkt_string, pkt_len, 0) == -1) {
                    perror("client: send joinsession");
                }

                free(pkt_string);
                free(msg_sent);
            }
        }
        else if (strcmp(command, "/leavesession") == 0) {
            if (!successfully_logged_in) {
                printf("%s\n\n", USER_NOT_LOGGED_IN);
            }
            else if (!successfully_joined_session) {
                printf("%s\n\n", USER_NOT_IN_SESSION);
            }
            else {
                msg_sent = create_packet(LEAVE_SESS, 1, source, "");
                pkt_string = create_packet_string(msg_sent, &pkt_len);

                if (send(sockfd, pkt_string, pkt_len, 0) == -1) {
                    perror("client: send leavesession");
                }
                pthread_mutex_lock(&join);
                successfully_joined_session = false;
                pthread_mutex_unlock(&join);
                printf("User %s has successfully left session\n\n", msg_sent->source);

                free(msg_sent);
                free(pkt_string);
            }
        }
        else if (strcmp(command, "/createsession") == 0) {
            session_id = strtok(NULL, delim);
            if (!successfully_logged_in) {
                printf("%s\n\n", USER_NOT_LOGGED_IN);
            }
            else {
                session_id[strlen(session_id)] = '\0';
                msg_sent = create_packet(NEW_SESS, strlen(session_id)+1, source, session_id);

                pkt_string = create_packet_string(msg_sent, &pkt_len);

                if (send(sockfd, pkt_string, pkt_len, 0) == -1) {
                    perror("client: send createsession");
                }

                free(msg_sent);
                free(pkt_string);
            }
        }
        else if (strcmp(command, "/list") == 0) {
            if (!successfully_logged_in) {
                printf("%s\n\n", USER_NOT_LOGGED_IN);
            }
            else {
                msg_sent = create_packet(QUERY, 1, source, "");
                pkt_string = create_packet_string(msg_sent, &pkt_len);

                if (send(sockfd, pkt_string, pkt_len, 0) == -1) {
                    perror("client: send list");
                }

                free(msg_sent);
                free(pkt_string);
            }
        }
        else if (strcmp(command, "/quit") == 0) {
            msg_sent = create_packet(EXIT, 1, source, "");
            pkt_string = create_packet_string(msg_sent, &pkt_len);

            if (send(sockfd, pkt_string, pkt_len, 0) == -1) {
                perror("client: send quit");
            }

            close(sockfd);
            pthread_cancel(recv_thread);

            free(msg_sent);
            free(pkt_string);

            break;
        }
        else {
            if (!successfully_logged_in) {
                printf("%s\n\n", USER_NOT_LOGGED_IN);
            }
            else if (!successfully_joined_session) {
                printf("%s\n\n", USER_NOT_IN_SESSION);
            }
            else {
                // Send instruction to server
                if (instruction_orig) {
                    msg_sent = create_packet(MESSAGE, strlen(instruction_orig)+1, source, instruction_orig);
                    pkt_string = create_packet_string(msg_sent, &pkt_len);

                    if (send(sockfd, pkt_string, pkt_len, 0) == -1) {
                        perror("client: send message");
                    }
                    printf("\n");
                }

                free(msg_sent);
                free(pkt_string);
            }
        }

        strcpy(instruction, "");
        strcpy(instruction_orig, "");
    } while (1);
}

int main (int argc, char *argv[]) {
    if (argc != 1) {
        fprintf(stderr, "Usage: client\n");
        return 1;
    }

    // Create a thread which will handle User input/Output at the terminal
    pthread_create(&client_thread, NULL, client_commands, NULL);
    pthread_exit(NULL);

    return 0;
}