#include "helper.h"

//////////////////////////////////
// CONNECTION FUNCTIONS //////////
//////////////////////////////////

void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

unsigned short get_in_port(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return ntohs(((struct sockaddr_in *)sa)->sin_port);
    }
    return ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
}

//////////////////////////////////
// DEBUG FUNCTIONS ///////////////
//////////////////////////////////

void print_packet(const message *msg) {
    printf("Printing packet\n");
    printf("Type: %s\n", stringFromPktType(msg->type));
    printf("Size: %d\n", msg->size);
    printf("Source: %s\n", msg->source);
    printf("Session_id: %s\n", msg->session_id);
    printf("Data: %s\n", msg->data);
}


void ht_print (users_db *users) {
    printf("Printing User Database\n");
    printf("Size %d\n", users->size);
    int i = 0;
    for (; i < users->size; ++i) {
        printf("i: %d\n", i);
        if (users->table[i] != NULL) {
            user_t *cur = users->table[i];
            while (cur != NULL) {
                printf("Username %s Password %s\n", cur->username, cur->password);
                printf("User is logged in %d User is connected to a session %d\n", cur->logged_in, cur->num_sessions);
                if (cur->logged_in) {
                    printf("IP address: %s Socket number %d\n", cur->ip_addr, cur->socket);
                }
                if (cur->num_sessions > 0) {
                    int i;
                    for (i = 0; i < MAX_SESSIONS; ++i) {
                        if (strcmp(cur->session_id[i], "") != 0) {
                            printf("Session ID: %s\n", cur->session_id[i]);
                        }
                    }
                }
                cur = cur->next;
            }
        }
    }
}

void print_sessions(session *sessions) {
    if (sessions) {
        session *cur = sessions;
        client *cur_client = NULL;
        printf("Printing sessions\n");
        while(cur != NULL) {
            printf("Session_id: %s\n", cur->session_id);
            printf("Num clients: %d\n", cur->num_clients);
            cur_client = cur->clients;
            if (cur->num_clients > 0 && cur_client != NULL)
                printf("Printing clients...\n");
            while (cur_client != NULL) {
                printf("Username: %s\n", cur_client->username);
                cur_client = cur_client->next;
            }
            cur = cur->next;
        }
        printf("\n");
    }
}

//////////////////////////////////
// USER DATABASE FUNCTIONS ///////
//////////////////////////////////

users_db *ht_create (int size) {
    users_db *users = NULL;
    int i;
    if (size < 1) return NULL;
    // Allocate the table
    if ((users = malloc(sizeof(users_db))) == NULL) {
        return NULL;
    }

    // Allocate pointers to the head nodes
    if ((users->table = malloc(sizeof(user_t *)*size)) == NULL) {
        return NULL;
    }
    for (i = 0; i < size; ++i) {
        users->table[i] = NULL;
    }
    users->size = size;
    return users;
}

int ht_hash (users_db *users, char *key) {
    assert(users);
    assert(key);
    unsigned long int hash = 0;
    int i = 0;
    while (hash < ULONG_MAX && i < strlen(key)) {
        hash += key[i];
        hash = hash << 8;
        i++;
    }
    return (hash % users->size);
}

user_t *ht_newpair (char *key, char *value) {
    user_t *newpair;
    if ((newpair = malloc(sizeof(user_t))) == NULL) {
        return NULL;
    }
    assert(key);
    assert(value);

    if ((newpair->username = strdup(key)) == NULL) {
        return NULL;
    }
    if ((newpair->password = strdup(value)) == NULL) {
        return NULL;
    }
    newpair->logged_in = false;
    newpair->num_sessions = 0;
    int i;
    for (i = 0; i < MAX_SESSIONS; ++i) {
        strcpy(newpair->session_id[i], "");
    }
    strcpy(newpair->ip_addr, "");
    newpair->socket = 0;
    newpair->next = NULL;
    return newpair;
}

void ht_set(users_db *users, char *key, char *value) {
    int hash = 0;
    user_t *newpair = NULL, *cur = NULL, *prev = NULL;
    assert(users);
    assert(key);
    assert(value);
    hash = ht_hash(users, key);
    cur = users->table[hash];

    while (cur != NULL && cur->username != NULL && strcmp(key, cur->username) > 0) {
        prev = cur;
        cur = cur->next;
    }

    // If a pair already exists, replace the string
    if (cur != NULL && cur->username != NULL && strcmp(key, cur->username) == 0) {
        free(cur->password);
        cur->password = strdup(value);
    }
    else {
        newpair = ht_newpair(key, value);
        // At the start of the linked list at this hash
        if (cur == users->table[hash]) {
            newpair->next = cur;
            users->table[hash] = newpair;
        }
        // At the end of the linked list
        else if (cur == NULL) {
            prev->next = newpair;
        }
        // In the middle
        else {
            newpair->next = cur;
            prev->next = newpair;
        }
    }
}

bool ht_key_exists(users_db *users, char *key) {
    assert(users);
    assert(key);

    int hash = ht_hash(users, key);
    user_t *cur = users->table[hash];
    while (cur != NULL) {
        if (cur->username != NULL && (strcmp(key, cur->username) == 0)) {
            return true;
        }
        cur = cur->next;
    }
    return false;
}

user_t *ht_get_user (users_db *users, char *key) {
    assert(users);
    assert(key);

    user_t *user = NULL;

    int hash = ht_hash(users, key);
    user_t *cur = users->table[hash];
    while (cur != NULL) {
        if (cur->username != NULL && (strcmp(key, cur->username) == 0)) {
            user = cur;
            break;
        }
        cur = cur->next;
    }
    return user;
}

void set_logged_in (user_t *user, char *ip_addr, int socket) {
    assert(user);
    assert(ip_addr);
    assert(socket >= 0);

    user->logged_in = true;
    strcpy(user->ip_addr, ip_addr);
    user->socket = socket;
}

void remove_logged_in (user_t *user) {
    assert(user);

    user->logged_in = false;
    strcpy(user->ip_addr, "");
    user->socket = 0;
}

int get_socket(users_db *users, char *client_id) {
    user_t *user = NULL;
    user = ht_get_user(users, client_id);
    assert(user);

    return user->socket;
}

//////////////////////////////////
// MESSAGE PACKET FUNCTIONS //////
//////////////////////////////////

char *create_packet_string(const message *pkt, unsigned int *pkt_len) {
    unsigned int size_usi = sizeof(unsigned int);
    unsigned int size_source = strlen(pkt->source) + 1;
    unsigned int size_session_id = strlen(pkt->session_id) + 1;
    // Space for 2 unsigned int + source + session_id + data + 4 ':'
    unsigned int size = 2*size_usi + size_source + size_session_id + pkt->size + 4;
    (*pkt_len) = size;

    char *pkt_string = malloc(size);
    memset(pkt_string, 0, size);

    unsigned int offset = 0;

    // Set type
    memcpy(pkt_string, (char *)&(pkt->type), size_usi);
    offset += size_usi;
    pkt_string[offset++] = ':';

    // Set size
    memcpy(pkt_string + offset, (char *)&(pkt->size), size_usi);
    offset += size_usi;
    pkt_string[offset++] = ':';

    // Set source
    memcpy(pkt_string + offset, (char *)&(pkt->source), size_source);
    offset += size_source;
    pkt_string[offset++] = ':';

    memcpy(pkt_string + offset, (char *)&(pkt->session_id), size_session_id);
    offset += size_session_id;
    pkt_string[offset++] = ':';

    // Set data
    memcpy(pkt_string + offset, pkt->data, pkt->size);

    return pkt_string;
}

message *process_packet_string(char *packet, int numbytes) {

    message *msg = malloc(sizeof(message));
    strcpy(msg->source, "");
    strcpy(msg->data, "");
    strcpy(msg->session_id, "");
    unsigned int size_usi = sizeof(unsigned int), offset = 0, i = 0;

    // Start parsing the packet
    memcpy(&(msg->type), packet, size_usi);
    offset += size_usi;
    offset++;

    memcpy(&(msg->size), packet+offset, size_usi);
    offset += size_usi;
    offset++;

    // Time to read source now
    while(packet[offset] != ':') {
        msg->source[i++] = packet[offset++];
    }
    offset++;

    i = 0;
    while(packet[offset] != ':') {
        msg->session_id[i++] = packet[offset++];
    }
    offset++;

    memcpy(&(msg->data), packet+offset, msg->size);

    return msg;
}

message *create_packet(const pkt_type type, const int len, const char *source, const char *session_id, const char *data) {
    message *msg = malloc(sizeof(message));
    strcpy(msg->source, "");
    strcpy(msg->data, "");
    strcpy(msg->session_id, "");
    msg->type = type;
    msg->size = len;
    strcpy(msg->source, source);
    strcpy(msg->session_id, session_id);
    strcpy(msg->data, data);
    return msg;
}

//////////////////////////////////
// SESSIONS FUNCTIONS ////////////
//////////////////////////////////

session *add_session(session **sessions, char *session_id) {
    assert(session_id);
    session *cur= NULL;

    if ((*sessions) == NULL) {
        // First session
        *sessions = malloc(sizeof(session));
        cur = *sessions;
    }
    else {
        // Find the last session
        cur = *sessions;
        while (cur->next != NULL) {
            cur = cur->next;
        }
        // Cur now points to the last session in the sessions list
        cur->next = malloc(sizeof(session));
        cur = cur->next;
    }
    assert(cur);

    strcpy(cur->session_id, session_id);
    cur->num_clients = 0;
    cur->clients = NULL;
    cur->next = NULL;
    return cur;
}

session *find_session(session *sessions, char *session_id) {
    assert(session_id);

    if (sessions == NULL) return NULL;

    session *cur = sessions;
    while (cur != NULL) {
        if (strcmp(cur->session_id, session_id) == 0) {
            return cur;
        }
        cur = cur->next;
    }
    return NULL;
}

void add_client_to_session(session *sess, char *client_id) {
    assert(sess);
    assert(client_id);

    client *cur = sess->clients;
    if (cur == NULL) {
        // First client in the session
        sess->clients = create_client(client_id);
    }
    else {
        while (cur->next != NULL) {
            // Get the last client in session
            cur = cur->next;
        }
        cur->next = create_client(client_id);
    }
    sess->num_clients++;
}

client *create_client(char *client_id) {
    assert(client_id);

    client *clnt = malloc(sizeof(client));
    strcpy(clnt->username, client_id);
    clnt->next = NULL;

    return clnt;
}

void set_user_session(user_t *user, char *session_id) {
    assert(user);
    assert(session_id);
    assert(user->num_sessions < MAX_SESSIONS);

    user->num_sessions++;
    int i;
    // Find an empty spot in the available sessions that the user can have
    for (i = 0; i < MAX_SESSIONS; ++i) {
        if (strcmp(user->session_id[i], "") == 0) {
            strcpy(user->session_id[i], session_id);
            break;
        }
    }
}

void remove_client_from_session(session *sess, char *client_id) {
    assert(sess);
    assert(client_id);

    client *head = sess->clients, *cur = NULL, *prev = head;

    // Iterate over session and remove client with username as client_id
    if (strcmp(head->username, client_id) == 0) {
        // Removing the head
        cur = head->next;
        free(head);
        sess->clients = cur;
    }
    else {
        while(prev->next != NULL && (strcmp(prev->next->username, client_id) != 0)) {
            prev = prev->next;
        }

        if (prev->next == NULL) {
            printf("Did not find client_id %s in session %s!!!\n", client_id, sess->session_id);
        }

        cur = prev->next;
        prev->next = prev->next->next;
        free(cur);
    }
    sess->num_clients--;
}

void remove_connected (user_t *user, char *session_id) {
    assert(user);

    user->num_sessions--;
    int i = 0;
    // Find the session and reset it
    for (; i < MAX_SESSIONS; ++i) {
        if (strcmp(user->session_id[i], session_id) == 0) {
            strcpy(user->session_id[i], "");
            break;
        }
    }
}

char *get_connected_session(user_t *user) {
    assert(user->num_sessions > 0);
    int i;
    for (i = 0; i < MAX_SESSIONS; ++i) {
        if (strcmp(user->session_id[i], "") != 0) {
            return user->session_id[i];
        }
    }
    // Will never get here
    return "";
}

bool is_user_in_session(const session *session, const char *user) {
    assert(session);
    assert(user);

    client *cur = session->clients;
    while (cur != NULL) {
        if (strcmp(cur->username, user) == 0) {
            // Found it
            return true;
        }
        cur = cur->next;
    }
    return false;
}

void delete_session_if_last(session **sessions, char *session_id) {
    assert(*sessions);
    assert(session_id);

    session *head = *sessions, *cur = NULL, *prev = head;

    // Iterate over sessions and find the matching session. If found save prev session
    if ((strcmp(head->session_id, session_id) == 0)) {
        if (head->num_clients == 0) {
            cur = head->next;
            free(head);
            (*sessions) = cur;
        }
    }
    else {      // Removing a session in the middle
        while ((prev->next != NULL) && (strcmp(prev->next->session_id, session_id) != 0)) {
            prev = prev->next;
        }
        if (prev->next == NULL) {
            printf("Did not find session_id %s in sessions!!\n", session_id);
        }

        cur = prev->next;
        if (cur->num_clients == 0) {
            prev->next = prev->next->next;
            free(cur);
        }
    }
}

bool session_exists(const char *session) {
    assert(session);
    char colon[2] = ":";
    return (strchr(session, *colon) != NULL);
}

char *get_users_and_sessions(users_db *users) {
    // data will look like: <USER1>: <SESSION1> <SESSION2> ...\n<USER2>: <SESSION1> ...\n...
    int i = 0;
    char *data = malloc(sizeof(char)*MAX_DATA_LEN);
    user_t *user = NULL;
    strcpy(data, "");
    printf("%s\n", data);
    for (; i < users->size; ++i) {
        user = users->table[i];
        if(user != NULL) {
            while (user != NULL) {
                if (user->logged_in) {
                    strcat(data, user->username);
                    if (user->num_sessions > 0) {
                        strcat(data, ": ");
                        int i = 0;
                        for (i = 0; i < MAX_SESSIONS; ++i) {
                            if (strcmp(user->session_id[i], "") != 0) {
                                strcat(data, user->session_id[i]);
                                strcat(data, " ");        
                            }
                        }
                    }
                    strcat(data, "\n");
                }
                user = user->next;
            }
        }
    }
    return data;
}