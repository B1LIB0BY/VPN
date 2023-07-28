#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <errno.h>
#include <crypt.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>


#define DEVICE "tun0"
#define MTU 1500
#define SERVER_PORT 7777
#define MAX_CLIENTS 10


struct iplookup {
    char* ip;
    bool available;
    SSL* ssl;
    pid_t pid;
    struct iplookup* next;
};

SSL_CTX* create_ssl_context()
{
    SSL_CTX* ctx;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "./cert_server/servercrt.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/serverkey.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set up the trusted CA certificate locations, if needed
    if (!SSL_CTX_load_verify_locations(ctx, NULL, "./cert_server/cacert.pem")) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    return ctx;
}

void cleanup_ssl_context(SSL_CTX* ctx)
{
    SSL_CTX_free(ctx);
    EVP_cleanup();
}

int tun_alloc(char* dev)
{
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        printf("The file /dev/net/tun cannot be opened!");
        return EXIT_FAILURE;
    }
    memset(&ifr, 0, sizeof(ifr));
    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */
    ifr.ifr_flags = IFF_TUN;
    if (*dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) < 0) {
        printf("Need Permissions");
        close(fd);
        return err;
    }
    strcpy(dev, ifr.ifr_name);
    printf("[->] Virtual network device '%s' created.\n", ifr.ifr_name);
    return fd;
}

static void run(char* cmd)
{
    printf("[+] Execute `%s`\n", cmd);
    if (system(cmd)) {
        printf("[-] ");
        perror(cmd);
        exit(1);
    }
    return;
}

void routing_table()
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ifconfig tun0 10.8.0.1/16 mtu %d up", MTU);
    run(cmd);

    run("sysctl -w net.ipv4.ip_forward=1");

    run("iptables -t nat -A POSTROUTING -s 10.8.0.0/16 ! -d 10.8.0.0/16  -j MASQUERADE");
    run("iptables -A FORWARD -s 10.8.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT");
    run("iptables -A FORWARD -d 10.8.0.0/16 -j ACCEPT");

    return;
}

void delete_routing_table()
{
    run("iptables -t nat -D POSTROUTING -s 10.8.0.0/16 ! -d 10.8.0.0/16 -j MASQUERADE");
    run("iptables -D FORWARD -s 10.8.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT");
    run("iptables -D FORWARD -d 10.8.0.0/16 -j ACCEPT");
    printf("[->] Routing table configurations deleted successfully.\n");

    return;
}

void add_client(struct iplookup** head, int size, bool available, SSL* ssl, pid_t pid, int client_socket)
{
    struct iplookup* new_client = (struct iplookup*)malloc(sizeof(struct iplookup));
    int count = 1;
    int temp = size;
    while (temp != 0) {
        temp /= 10;
        count++;
    }

    char* unique_number = (char*)malloc(count + 1);
    sprintf(unique_number, "%d", size);
    char new_ip[14];
    strcpy(new_ip, "10.8.0.");
    strcat(new_ip, unique_number);
    printf("[->] New IP: %s\n", new_ip);

    new_client->ip = (char*)malloc(strlen(new_ip) + 1);  // +1 for null terminator
    strcpy(new_client->ip, new_ip);

    new_client->available = available;
    new_client->ssl = ssl;
    new_client->pid = pid;
    new_client->next = NULL;

    if (*head == NULL) {
        *head = new_client;
    }
    else {
        struct iplookup* current = *head;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = new_client;
    }

    const char* message = new_client->ip;
    ssize_t bytes_sent = SSL_write(ssl, message, strlen(message));
    if (bytes_sent == -1) {
        perror("write");
    }
    else {
        printf("[+] Message sent to the client\n");
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);
}

void remove_client(struct iplookup** head, char* ip)
{
    struct iplookup* current = *head;
    struct iplookup* previous = NULL;

    while (current != NULL) {
        if (strcmp(current->ip, ip) == 0) {
            if (previous == NULL) {
                *head = current->next;
            }
            else {
                previous->next = current->next;
            }
            free(current);
            return;
        }

        previous = current;
        current = current->next;
    }
}

void print_clients(struct iplookup* head)
{
    struct iplookup* current = head;
    printf("\n--------------------------");
    printf("\n\nClients:\n\n");
    while (current != NULL) {
        printf("IP: %s\n", current->ip);
        printf("Available: %s\n", current->available ? "true" : "false");
        printf("SSL: %p\n", (void*)current->ssl);
        printf("PID: %d\n\n", current->pid);

        current = current->next;
    }
    printf("--------------------------\n\n");
}

void cleanup(struct iplookup** head)
{
    struct iplookup* current = *head;
    struct iplookup* temp;
    while (current != NULL) {
        temp = current;
        current = current->next;
        free(temp->ip);
        free(temp);
    }
    *head = NULL;
}

void configure_server(int server_socket)
{
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(SERVER_PORT);

    if (bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)) == -1) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, MAX_CLIENTS) == -1) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("[+] Server listening on port %d\n", SERVER_PORT);
}

int main()
{
    char dev[] = DEVICE;
    tun_alloc(dev);
    routing_table();

    SSL_METHOD* meth;
    SSL_CTX* ctx;
    SSL* ssl;
    int err;

    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    // SSL context initialization.
    meth = (SSL_METHOD*)TLSv1_2_method();

    ctx = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    //Set up the server certificate and private key
    SSL_CTX_use_certificate_file(ctx, "./cert_server/servercrt.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/serverkey.pem", SSL_FILETYPE_PEM);
    // Create a new SSL structure for a connection
    ssl = SSL_new(ctx);

    // TCP server.
    int server_socket, client_socket;
    struct sockaddr_in client_address;
    socklen_t client_address_length;
    

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    int clients = 0;
    struct iplookup* head = NULL; // Head of the linked list
    // Configure the server
    configure_server(server_socket);

    while (1) {
        // Accept a client connection
        client_address_length = sizeof(client_address);
        client_socket = accept(server_socket, (struct sockaddr*)&client_address, &client_address_length);
        if (client_socket == -1) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Attach the SSL session to the socket descriptor
        SSL_set_fd(ssl, client_socket);

        // Perform SSL handshake
        err = SSL_accept(ssl);
        if (err <= 0) {
            ERR_print_errors_fp(stderr);
            close(client_socket);
            continue;
        }

        // Verify client certificate (optional)

        // Create a new process for the client
        pid_t pid = fork();
        if (pid == -1) {
            perror("fork");
            exit(EXIT_FAILURE);
        }
        else if (pid == 0) {
            // This is the child process
            printf("[+] New client connected\n");

            // Close the listening socket
            close(server_socket);

            // Add the client to the linked list
            add_client(&head, clients + 1, true, ssl, pid, client_socket);
            clients++;

            // Print the list of clients
            print_clients(head);

            // Child process loop
            while (1) {
                // Receive data from the client
                char buffer[1024];
                ssize_t bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                if (bytes_received == -1) {
                    perror("read");
                    // Handle error if needed
                }
                else if (bytes_received == 0) {
                    // Connection closed by the client
                    printf("[-] Client disconnected\n");

                    // Remove the client from the linked list
                    remove_client(&head, ssl);

                    // Print the list of clients
                    print_clients(head);

                    // Close the SSL connection and the client socket
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    close(client_socket);

                    // Terminate the child process
                    exit(EXIT_SUCCESS);
                }
                else {
                    // Null-terminate the received data
                    buffer[bytes_received] = '\0';

                    // Process the received data
                    printf("Received data from client: %s\n", buffer);

                    // Send a response back to the client
                    const char* response = "Response from server";
                    ssize_t bytes_sent = SSL_write(ssl, response, strlen(response));
                    if (bytes_sent == -1) {
                        perror("write");
                        // Handle error if needed
                    }
                    else {
                        printf("Response sent to the client\n");
                    }
                }
            }
        }
        else {
            // This is the parent process
            close(client_socket);
        }
    }

    // Cleanup SSL
    SSL_CTX_free(ctx);
    EVP_cleanup();

    // Cleanup linked list
    cleanup(&head);

    // Delete routing table configurations
    delete_routing_table();

    return 0;
}
