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
#include <limits.h>
#include <assert.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <signal.h>

#define QUEUE_SIZE 10
#define INSN_SIZE 100
#define MAX_SOURCE_LEN 30
#define MAX_DATA_LEN 1000
#define MAXPACKETLEN 1100
#define MAX_SESSION_LEN 100

// Error Messages
extern const char *INVALID_USERNAME;
extern const char *INVALID_PASSWORD;
extern const char *USER_ALREADY_LOGGED_IN;
extern const char *USER_NOT_LOGGED_IN;
extern const char *USER_NOT_IN_SESSION;
extern const char *USER_ALREADY_IN_SESSION;
extern const char *SESSION_DOES_NOT_EXIST;
extern const char *SESSION_ALREADY_EXISTS;
extern const char *RECEIVED_NON_QU_ACK;


enum packet_type {LOGIN, LO_ACK, LO_NAK, EXIT, JOIN, JN_ACK, 
    JN_NAK, LEAVE_SESS, NEW_SESS, NS_ACK, NS_NAK, MESSAGE, QUERY, QU_ACK};
typedef enum packet_type pkt_type;

static inline const char *stringFromPktType (pkt_type pt) {
    static const char *strings [] = {"LOGIN", "LO_ACK", "LO_NAK", "EXIT", "JOIN",
        "JN_ACK", "JN_NAK", "LEAVE_SESS", "NEW_SESS", "NS_ACK", "NS_NAK", "MESSAGE", "QUERY", "QU_ACK"};
    return strings[pt];
}

// Hash Table Implementation for storing username & password
struct user_t {
    char *username;     // Client ID
    char *password;
    bool logged_in;     // Client is logged onto the server
    bool connected;     // Connected to a session
    char session_id[MAX_SESSION_LEN];
    char ip_addr[INET_ADDRSTRLEN];
    int socket;
    struct user_t *next;
};
typedef struct user_t user_t;

struct users_db {
    int size;
    user_t **table;
};
typedef struct users_db users_db;

struct lab3message {
    unsigned int type;
    unsigned int size;
    unsigned char source[MAX_SOURCE_LEN];
    unsigned char data[MAXPACKETLEN];
};
typedef struct lab3message message;

struct session {
    char session_id[MAX_SESSION_LEN];
    int num_clients;
    struct client *clients;
    struct session *next;
};
typedef struct session session;

struct client {
    char username[MAX_SOURCE_LEN];
    struct client *next;
};
typedef struct client client;

// get sockaddr IPv4 or IPv6
void *get_in_addr(struct sockaddr *sa);

unsigned short get_in_port(struct sockaddr *sa);

void print_packet(const message *msg);

// Create a new hashtable
users_db *ht_create (int size);

// Hash a string
int ht_hash (users_db *users, char *key);
// Create a key-value pair
user_t *ht_newpair (char *key, char *value);

// Insert a key-value pair in hashtable
void set_logged_in (user_t *user, char *ip_addr, int socket);

void remove_logged_in (user_t *user);

// Retrieve a username-password pair from the hashtable
bool ht_get_user (users_db *users, char *key, user_t **user);

bool ht_key_exists(users_db *users, char *key);

void ht_set(users_db *users, char *key, char *value);

// Print hash table
void ht_print(users_db *users);

char *create_packet_string(const message *pkt, unsigned int *pkt_len);

message *process_packet_string(char *packet, int numbytes);

message *create_packet(const pkt_type type, const int len, const char *source, const char *data);

session* add_session(session **sessions, char *session_id);

void print_sessions(session *sessions);

session *find_session(session *sessions, char *session_id);

void add_client_to_session(session *sess, char *client_id);

client *create_client(char *client_id);

void set_user_session(user_t *user, char *session_id);

void remove_client_from_session(session *sess, char *client_id);

void remove_connected (user_t *user);

char *get_users_and_sessions(users_db *users);

int get_socket(users_db *users, char *client_id);

void delete_session_if_last(session **sessions, char *session_id);

#endif // _HELPER_H_