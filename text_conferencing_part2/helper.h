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
#define MAX_SESSIONS 10

// Error Messages
extern const char *INVALID_USERNAME;
extern const char *INVALID_PASSWORD;
extern const char *USER_ALREADY_LOGGED_IN;
extern const char *USER_NOT_LOGGED_IN;
extern const char *USER_NOT_IN_SESSION;
extern const char *USER_IN_MAX_SESSIONS;
extern const char *SESSION_DOES_NOT_EXIST;
extern const char *SESSION_ALREADY_EXISTS;
extern const char *SPECIFY_SESSION_FOR_MESSAGE;
extern const char *USER_NOT_IN_SPECIFIED_SESSION;
extern const char *USER_ALREADY_IN_SESSION;


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
    char *username;                                     // Client ID
    char *password;                                     // Password
    bool logged_in;                                     // Stores whether client is logged onto the server
    unsigned short num_sessions;                        // Number of sessions that the client is joined in
    char session_id[MAX_SESSIONS][MAX_SESSION_LEN];     // The session ids that the user is joined in
    char ip_addr[INET_ADDRSTRLEN];                      // IP address of client
    int socket;                                         // Socket used by the client
    struct user_t *next;
};
typedef struct user_t user_t;

// Hash Table which stores all the client's information
struct users_db {
    int size;
    user_t **table;
};
typedef struct users_db users_db;

// Message struct
struct lab3message {
    unsigned int type;                                  // Type of message
    unsigned int size;                                  // Size of data -> strlen(data) + 1 (for '\0')
    unsigned char source[MAX_SOURCE_LEN];               // Client id associated with the message
    unsigned char session_id[MAX_SESSION_LEN];          // Session ID associated with the message
    unsigned char data[MAXPACKETLEN];                   // Actual data
};
typedef struct lab3message message;

// Sessions database
struct session {
    char session_id[MAX_SESSION_LEN];                   // Unique ID for the session
    int num_clients;                                    // Number of clients logged into the current session
    struct client *clients;                             // A list of clients connected to the session
    struct session *next;
};
typedef struct session session;

// Client IDs
struct client {
    char username[MAX_SOURCE_LEN];                      // Client IDs of the client in the session
    struct client *next;
};
typedef struct client client;

//////////////////////////////////
// CONNECTION FUNCTIONS //////////
//////////////////////////////////

// get sockaddr IPv4 or IPv6
void *get_in_addr(struct sockaddr *sa);

unsigned short get_in_port(struct sockaddr *sa);

//////////////////////////////////
// DEBUG FUNCTIONS ///////////////
//////////////////////////////////

// Print the message packet
void print_packet(const message *msg);

// Print the user database
void ht_print(users_db *users);

// Print the sessions database
void print_sessions(session *sessions);

//////////////////////////////////
// USER DATABASE FUNCTIONS ///////
//////////////////////////////////

// Create a new user database
users_db *ht_create (int size);

// Hash a string and get the index
int ht_hash (users_db *users, char *key);

// Create a key-value pair with the username and password and initialize the user_t struct
user_t *ht_newpair (char *key, char *value);

// Insert a key-value pair of username & password in hashtable
void ht_set(users_db *users, char *key, char *value);

// Check if the given username exists in the database
bool ht_key_exists(users_db *users, char *key);

// Retrieve a user struct from the database with the username key. 
user_t *ht_get_user (users_db *users, char *key);

// If a user is correctly logged in, set its IP address and socket
void set_logged_in (user_t *user, char *ip_addr, int socket);

// Once a user logs out, reset IP address, socket and logged_in field
void remove_logged_in (user_t *user);

// Get the socket number of the given client_id
int get_socket(users_db *users, char *client_id);

//////////////////////////////////
// MESSAGE PACKET FUNCTIONS //////
//////////////////////////////////

// Compress the given packet into a single string and separate each of the fields with ':'.
// Return the compressed string and it's length in pkt_len
char *create_packet_string(const message *pkt, unsigned int *pkt_len);

// Given a packet string, extract the fields and return a message packet
message *process_packet_string(char *packet, int numbytes);

// Create a message packet with the supplied fields
message *create_packet(const pkt_type type, const int len, const char *source, const char *session_id, const char *data);

//////////////////////////////////
// SESSIONS FUNCTIONS ////////////
//////////////////////////////////

// Add a new session with given session_id to the sessions database
session* add_session(session **sessions, char *session_id);

// Find a session with the given session id. If not found, return NULL
session *find_session(session *sessions, char *session_id);

// Add a new client with name as client_id into the given session
void add_client_to_session(session *sess, char *client_id);

// return a client struct initialized with the given client_id
client *create_client(char *client_id);

// Given a user_t strut, update its session info
void set_user_session(user_t *user, char *session_id);

// Remove a client with the given client_id from the given session
void remove_client_from_session(session *sess, char *client_id);

// Reset the session info for the give session_id for the given user
void remove_connected (user_t *user, char *session_id);

// Get a session that the user is part of 
char *get_connected_session(user_t *user);

// Check if the given user is part of that session
bool is_user_in_session(const session *session, const char *user);

// If there are no more users in the given session_id, delete the session from the sessions database
void delete_session_if_last(session **sessions, char *session_id);

// Used when the client wants to send a message. Checks if a colon is present in the entered string
// If so, ASSUME that the client entered the correct syntax to send a message to the server
// Does not check for the space after colon
// Correct syntax: <session_id>: <Message>
bool session_exists(const char *session);

// Return a string of all users and their sessions connected to the server.
// Used to respond to QUERY type packet
char *get_users_and_sessions(users_db *users);

#endif // _HELPER_H_