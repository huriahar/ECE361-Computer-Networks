/*
 * server.c -- Execution: server <TCP Port number to listen to>
 * Contains the client database and fulfills requests for various clients connected to the server
 * Packet types and functions:
 * LOGIN - Login with the server. Data as <client_id,password> If successful login, send LO_ACK packet
 *         back. Else send LO_NAK with reason for failure
 * EXIT - Exit from the server
 * JOIN - Join an existing session. Session id in data of packet. If successful, send JN_ACK else JN_NAK
 *         with reason for failure
 * LEAVE_SESS - Leave a conference session specified by the session_id field
 * NEW_SESS - Create a new conference session. If successful, send NS_ACK with session_id in data. Else NS_NAK
 * QUERY - Send a list of connected users and the sessions that they are in the reply packet QU_ACK
 * MESSAGE - Receive message packet and forward the message from client to all the messages in the session
 *           specified by session_id field
 */

#include "helper.h"

// Error Message Strings
const char *INVALID_USERNAME = "Invalid Username";
const char *INVALID_PASSWORD = "Invalid Password";
const char *USER_ALREADY_LOGGED_IN = "User is already logged in";
const char *USER_IN_MAX_SESSIONS = "User is already in the maximum possible number of sessions. Leave one of the previous sessions first";
const char *SESSION_DOES_NOT_EXIST = "Session does not exist. Create the session first";
const char *SESSION_ALREADY_EXISTS = "Session already exists";
const char *USER_NOT_IN_SESSION = "User is not joined in a session. Join a session first";
const char *USER_NOT_IN_SPECIFIED_SESSION = "User is not joined in the specified session. Join the session first";
const char *USER_ALREADY_IN_SESSION = "User is already in the specified session";

users_db *users;                // User database with all the usernames and passwords
session *sessions;              // Session database with all the active sessions and a list of users in each session

// Create the hash table and populate it with user names and passwords
void set_up_users_db() {
    users = ht_create(10);
    ht_set(users, "alice", "ALICE");
    ht_set(users, "bob", "BOB");
    ht_set(users, "cathy", "CATHY");
    ht_set(users, "jack", "JACK");
    ht_set(users, "joe", "JOE");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: server <TCP listen port>\n");
        return 1;
    }

    struct addrinfo hints, *res = NULL, *p = NULL;
    int status, yes = 1;
    int listener_fd, new_fd;            // listen on listener_fd, new connection on new_fd


    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;          // set to AF_INET to force IPv4
    hints.ai_socktype = SOCK_STREAM;    // TCP sockets
    hints.ai_flags = AI_PASSIVE;        // Fill in my IP for me

    if ((status = getaddrinfo(NULL, argv[1], &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return 2;
    }

    // res now points to a linked list of 1 or more struct addrinfos
    // Loop through all of the results and bind to the first one we can

    for (p = res; p != NULL; p = p->ai_next) {
        if ((listener_fd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("server: setsockopt");
            exit(1);
        }

        if (bind(listener_fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(listener_fd);
            perror("server: bind");
            continue;
        }
        break;
    }

    if (p == NULL) {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    freeaddrinfo(res);                  // All done with this structure

    // Initialize the user & sessions database
    set_up_users_db();
    sessions = NULL;

    printf("server: waiting for connections...\n");

    // Set of socket descriptors
    fd_set master;                      // master file descriptor list
    fd_set readfds;                     // temp file descriptor list for select()
    // Clear the master and temp set
    FD_ZERO(&master);
    FD_ZERO(&readfds);

    socklen_t sin_size;
    struct sockaddr_storage their_addr; // Connector's address information
    char remoteIP[INET_ADDRSTRLEN];     // Connector's IP in IPv4

    int numbytes = 0, i = 0, j = 0, socket = 0;
    char buf[MAXPACKETLEN];             // Char array which receives the packet from client

    message *msg_rcvd, *msg_sent;
    char *pkt_string, *data;
    unsigned int pkt_len;

    int max_fd;
    unsigned short recv_port;
    bool valid = false;

    char *session_id, *source;

    user_t *user = NULL;
    session *sess = NULL;
    client *cur_client = NULL;

    if (listen(listener_fd, QUEUE_SIZE) == -1) {
        perror("server: listen");
        exit(1);
    }
    
    // Add the listener to the master set
    FD_SET(listener_fd, &master);
    max_fd = listener_fd;

    // Main accept() loop
    while (1) {
        readfds = master;   // Copy it
        if (select(max_fd + 1, &readfds, NULL, NULL, NULL) == -1) {
            perror("server: select\n");
            exit(1);
        }

        // Run through the existing connections looking for data to read
        for (i = 0; i <= max_fd; ++i) {
            if (FD_ISSET(i, &readfds)) {            // We got one!
                if (i == listener_fd) {
                    // Handle new connections
                    sin_size = sizeof(their_addr);
                    new_fd = accept(listener_fd, (struct sockaddr *)&their_addr, &sin_size);
                    if (new_fd == -1) {
                        perror("server: accept\n");
                    }
                    else {
                        FD_SET(new_fd, &master);    // Add to master set
                        if (new_fd > max_fd) {      // Keep track of the max
                            max_fd = new_fd;
                        }

                        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr),
                                remoteIP, sizeof(remoteIP));
                        recv_port = get_in_port((struct sockaddr *)&their_addr);

                        // Inform user of IP, socket number and port number
                        printf("New connection from %s on socket %d on port %d\n", remoteIP, new_fd, recv_port);
                    }
                }
                else {
                    // Handle data from client
                    if ((numbytes = recv(i, buf, sizeof(buf), 0)) <= 0) {
                        // Got error or connection closed by client
                        if (numbytes == 0) {
                            // Connection closed
                            printf("server: socket %d hung up\n", i);
                        }
                        else {
                            perror("server: recv\n");
                        }
                        close(i);
                        FD_CLR(i, &master);                 // Remove from master set
                    }
                    else {
                        // We got some data from the client -- process it
                        // Create a message struct out of buf str
                        msg_rcvd = process_packet_string(buf, numbytes);
                        source = msg_rcvd->source;

                        if (msg_rcvd->type == LOGIN) {
                            // Check if Username and Password are valid
                            char *user_name, *password;
                            char delim[3] = ",\n";
                            user_name = strtok(msg_rcvd->data, delim);
                            password = strtok(NULL, delim);
                            valid = false;

                            // Check if client exists in database
                            user = ht_get_user(users, user_name);
                            if (user) {
                                if (user->logged_in) {
                                    msg_sent = create_packet(LO_NAK, strlen(USER_ALREADY_LOGGED_IN)+1, user_name, "", USER_ALREADY_LOGGED_IN);
                                    printf("User %s not successfully logged in. Error: %s\n\n", user_name, USER_ALREADY_LOGGED_IN);
                                }
                                else {
                                    // Now check if passwords match
                                    if (strcmp(user->password, password) == 0) {
                                        msg_sent = create_packet(LO_ACK, 1, user_name, "", "");
                                        valid = true;
                                    }
                                    else {
                                        msg_sent = create_packet(LO_NAK, strlen(INVALID_PASSWORD)+1, user_name, "", INVALID_PASSWORD);
                                        printf("User %s not successfully logged in. Error: %s\n\n", user_name, INVALID_PASSWORD);
                                    }
                                }
                            }
                            else {
                                msg_sent = create_packet(LO_NAK, strlen(INVALID_USERNAME)+1, user_name, "", INVALID_USERNAME);
                                printf("User %s not successfully logged in. Error: %s\n\n", user_name, INVALID_USERNAME);
                            }

                            pkt_string = create_packet_string(msg_sent, &pkt_len);
                            if (send(i, pkt_string, pkt_len, 0) == -1) {
                                perror("server: send LO_ACK/LO_NAK\n");
                            }

                            // User successfully logged in - Add user to the list of active users
                            if (valid) {
                                set_logged_in(user, remoteIP, new_fd);
                                printf("User %s successfully logged in\n\n", user_name);
                                valid = false;
                            }
                            else {
                                close(i);
                                FD_CLR(i, &master);         // Remove from master set
                            }

                            free(pkt_string);
                            free(msg_sent);
                        }
                        else if (msg_rcvd->type == EXIT) {
                            // Set client as logged out & Remove client from all active sessions
                            // Check if client exists in database
                            user = ht_get_user(users, source);
                            if (user) {
                                if (user->logged_in) {
                                    remove_logged_in(user);
                                    char *session, *session_copy;
                                    while (user->num_sessions > 0) {
                                        // Remove user from all sessions that it is a part of
                                        session_id = get_connected_session(user);
                                        session_copy = (char *)malloc((strlen(session_id)+1)*sizeof(char));
                                        strcpy(session_copy, session_id);
                                        sess = find_session(sessions, session_id);
                                        assert(sess);
                                        remove_client_from_session(sess, source);
                                        remove_connected(user, session_copy);
                                        delete_session_if_last(&sessions, session_copy);
                                        free(session_copy);
                                    }
                                    printf("User %s successfully logged out\n\n", msg_rcvd->source);

                                    close(user->socket);
                                    FD_CLR(user->socket, &master);
                                }
                            }
                        }
                        else if (msg_rcvd->type == JOIN) {
                            user = ht_get_user(users, source);
                            session_id = msg_rcvd->data;
                            if (user) {
                                if (user->num_sessions == MAX_SESSIONS) {
                                    // User is already in another session..
                                    msg_sent = create_packet(JN_NAK, strlen(USER_IN_MAX_SESSIONS)+1, source, "", USER_IN_MAX_SESSIONS);
                                    printf("User %s did not successfully join session %s. Error: %s\n\n", source, session_id, USER_IN_MAX_SESSIONS);
                                }
                                else {
                                    // Check if session exists
                                    sess = find_session(sessions, session_id);
                                    if (sess == NULL) {
                                        // Session does not exist
                                        msg_sent = create_packet(JN_NAK, strlen(SESSION_DOES_NOT_EXIST)+1, source, "", SESSION_DOES_NOT_EXIST);
                                        printf("User %s did not successfully join session %s. Error: %s\n\n", source, session_id, SESSION_DOES_NOT_EXIST);
                                    }
                                    else {
                                        if (is_user_in_session(sess, source)) {
                                            msg_sent = create_packet(JN_NAK, strlen(USER_ALREADY_IN_SESSION)+1, source, "", USER_ALREADY_IN_SESSION);
                                            printf("User %s did not successfully join session %s. Error: %s\n\n", source, session_id, USER_ALREADY_IN_SESSION);       
                                        }
                                        else {
                                            valid = true;
                                            msg_sent = create_packet(JN_ACK, strlen(session_id)+1, source, session_id, session_id);
                                            printf("User %s successfully joined session %s\n\n", source, session_id);
                                        }
                                    }
                                }

                                if (valid) {
                                    add_client_to_session(sess, source);
                                    set_user_session(user, session_id);
                                    valid = false;
                                }

                                // Send the packet
                                pkt_string = create_packet_string(msg_sent, &pkt_len);
                                if (send(i, pkt_string, pkt_len, 0) == -1) {
                                    perror("server: send JN_ACK/JN_NAK\n");
                                }

                                free(pkt_string);
                                free(msg_sent);
                            }
                            else {
                                printf("JOIN: Should not get here! User does not exist in db. This should have been handled in login\n\n");
                            }
                        }
                        else if (msg_rcvd->type == NEW_SESS) {
                            user = ht_get_user(users, source);
                            session_id = msg_rcvd->data;

                            if (user) {
                                // Check if session already exists before
                                if (find_session(sessions, session_id) != NULL) {
                                    // Session already exists before
                                    msg_sent = create_packet(NS_NAK, strlen(SESSION_ALREADY_EXISTS)+1, source, "", SESSION_ALREADY_EXISTS);
                                    printf("User %s did not successfully create a session %s. Error: %s\n\n", source, session_id, SESSION_ALREADY_EXISTS);
                                }
                                else if (user->num_sessions == MAX_SESSIONS) {
                                    msg_sent = create_packet(NS_NAK, strlen(USER_IN_MAX_SESSIONS)+1, source, "", USER_IN_MAX_SESSIONS);
                                    printf("User %s did not successfully create session %s. Error: %s\n\n", source, session_id, USER_IN_MAX_SESSIONS);
                                }
                                else {
                                    sess = add_session(&sessions, session_id);
                                    assert(sess);

                                    add_client_to_session(sess, source);
                                    set_user_session(user, session_id);

                                    // Send NS_ACK to client
                                    msg_sent = create_packet(NS_ACK, strlen(session_id)+1, source, session_id, session_id);
                                    printf("User %s successfully created and joined session %s\n\n", source, session_id);
                                }

                                pkt_string = create_packet_string(msg_sent, &pkt_len);
                                if (send(i, pkt_string, pkt_len, 0) == -1) {
                                    perror("server: send NS_ACK\n");
                                }
                                free(pkt_string);
                                free(msg_sent);

                            }
                            else {
                                printf("NEW_SESS: Should not get here! User does not exist in db. This should have been handled in login\n\n");
                            }
                        }
                        else if (msg_rcvd->type == LEAVE_SESS) {
                            user = ht_get_user(users, source);
                            session_id = msg_rcvd->data;
                            if (user) {
                                if (!user->num_sessions) {
                                    printf("User %s did not successfully leave session %s. Error: %s\n\n", source, session_id, USER_NOT_IN_SESSION);
                                }
                                else {
                                    sess = find_session(sessions, session_id);
                                    if (sess == NULL) {
                                        printf("User %s did not successfully leave session %s. Error: %s\n\n", source, session_id, SESSION_DOES_NOT_EXIST);
                                    }
                                    else if (!is_user_in_session(sess, msg_rcvd->source)) {
                                        printf("User %s did not successfully leave session %s. Error: %s\n\n", source, session_id, USER_NOT_IN_SPECIFIED_SESSION);
                                    }
                                    else {
                                        // Remove user from session
                                        printf("User %s successfully left session %s\n\n", msg_rcvd->source, msg_rcvd->session_id);
                                        remove_client_from_session(sess, source);
                                        remove_connected(user, session_id);
                                        delete_session_if_last(&sessions, session_id);
                                    }
                                }
                            }
                            else {
                                printf("LEAVE_SESS: Should not get here! User does not exist in db. This should have been handled in login\n\n");
                            }
                        }
                        else if (msg_rcvd->type == QUERY) {
                            data = get_users_and_sessions(users);
                            msg_sent = create_packet(QU_ACK, strlen(data)+1, source, "", data);

                            printf("Sending data about clients and sessions\n\n");

                            pkt_string = create_packet_string(msg_sent, &pkt_len);
                            if (send(i, pkt_string, pkt_len, 0) == -1) {
                                perror("server: send NS_ACK\n");
                            }

                            free(pkt_string);
                            free(msg_sent);
                            free(data);
                        }
                        else if (msg_rcvd->type == MESSAGE) {
                            user = ht_get_user(users, source);
                            if (user) {
                                sess = find_session(sessions, msg_rcvd->session_id);
                                if (sess == NULL) {
                                    printf("User %s did not successfully send message to session %s. Error: %s\n\n", source, msg_rcvd->session_id, SESSION_DOES_NOT_EXIST);
                                }
                                else if (!is_user_in_session(sess, msg_rcvd->source)) {
                                    printf("User %s did not successfully send message to session %s. Error: %s\n\n", source, msg_rcvd->session_id, USER_NOT_IN_SPECIFIED_SESSION);
                                }
                                else {
                                    // Add the session_id and client_id of the sender before the data is sent out to other receivers
                                    char data[MAXPACKETLEN];
                                    strcpy(data, "");
                                    strcpy(data, msg_rcvd->session_id);
                                    strcat(data, ": ");
                                    strcat(data, msg_rcvd->source);
                                    strcat(data, ": ");
                                    strcat(data, msg_rcvd->data);
                                    strcpy(msg_rcvd->data, "");
                                    strcpy(msg_rcvd->data, data);
                                    msg_rcvd->size = strlen(msg_rcvd->data) + 1;

                                    pkt_string = create_packet_string(msg_rcvd, &pkt_len);

                                    cur_client = sess->clients;
                                    // Should have at least one client in the session to have gotten the MESSAGE packet
                                    assert(cur_client);
                                    while(cur_client != NULL) {
                                        socket = get_socket(users, cur_client->username);
                                        if (FD_ISSET(socket, &master)) {
                                            // Except the listener and sender itself
                                            if (socket != listener_fd && (strcmp(cur_client->username, source) != 0)) {
                                                if (send(socket, pkt_string, pkt_len, 0) == -1) {
                                                    perror("server: send MESSAGE\n");
                                                }
                                            }
                                        }
                                        cur_client = cur_client->next;
                                    }
                                }
                            }
                            else {
                                printf("LEAVE_SESS: Should not get here! User does not exist in db. This should have been handled in login\n\n");
                            }
                        }
                    }
                }
            }  
        }
    }
    
    return 0;

}
