#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_IP "10.0.0.29"  // Server IP address
#define SERVER_PORT 7777       // Server port number
#define TUN_DEVICE "/dev/net/tun"
#define TUN_NAME "tun0"
#define VPN_SERVER_IP "10.8.0.1"
#define NETMASK "255.255.0.0"
#define MTU 1500



int create_tun_device(char *dev)
{
    struct ifreq ifr;
    int fd, err;

    if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ){
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
    if( *dev )
       strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 )
    {
       printf("Need Permissions");
       close(fd);
       return err;
    }
    strcpy(dev, ifr.ifr_name);
    printf("[->] Virtual network device '%s' created.\n", ifr.ifr_name);
    return fd;
}



static void run(char *cmd) 
{
  printf("[+] Execute `%s`\n", cmd);
  if (system(cmd)) 
  {
    printf("[-] ");
    perror(cmd);
    exit(1);
  }
}


int configure_interface(char* ip)
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ifconfig tun0 %s/16 mtu %d up", ip, MTU);
    run(cmd);

    return 0;
}

int configure_routing() 
{
    char cmd[1024];

    snprintf(cmd, sizeof(cmd), "sysctl -w net.ipv4.ip_forward=1");
    run(cmd);

    snprintf(cmd, sizeof(cmd), "iptables -t nat -A POSTROUTING -o %s -j MASQUERADE", TUN_NAME);
    run(cmd);

    snprintf(cmd, sizeof(cmd), "iptables -I FORWARD 1 -i %s -m state --state RELATED,ESTABLISHED -j ACCEPT", TUN_NAME);
    run(cmd);
    
    snprintf(cmd, sizeof(cmd), "iptables -I FORWARD 1 -o %s -j ACCEPT", TUN_NAME);
    run(cmd);
    
    snprintf(cmd, sizeof(cmd), "ip route add 10.8.0.0/24 via %s", SERVER_IP);
    run(cmd);

    snprintf(cmd, sizeof(cmd), "ip route add 0/1 via %s dev %s", VPN_SERVER_IP, TUN_NAME);
    run(cmd);
    
    snprintf(cmd, sizeof(cmd), "ip route add 128/1 via %s dev %s", VPN_SERVER_IP, TUN_NAME);
    run(cmd);

    return 0;
}


void delete_routing_config()
{
    char cmd[1024];

    snprintf(cmd, sizeof(cmd), "iptables -t nat -D POSTROUTING -o %s -j MASQUERADE", TUN_NAME);
    run(cmd);

    snprintf(cmd, sizeof(cmd), "iptables -D FORWARD -i %s -m state --state RELATED,ESTABLISHED -j ACCEPT", TUN_NAME);
    run(cmd);

    snprintf(cmd, sizeof(cmd), "iptables -D FORWARD -o %s -j ACCEPT", TUN_NAME);
    run(cmd);
    
    snprintf(cmd, sizeof(cmd), "ip route del 0/1");
    run(cmd);

    snprintf(cmd, sizeof(cmd), "ip route del 128/1");
    run(cmd);


    snprintf(cmd, sizeof(cmd), "ip route del 10.8.0.0/24");
    run(cmd);

    printf("Routing configuration deleted successfully.\n");
}

int main()
{
    int sockfd;
    struct sockaddr_in server_addr;
    char server_ip[] = SERVER_IP;
    int server_port = SERVER_PORT;

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_BIO_strings();

    // Create SSL context
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_2_client_method());
    if (ctx == NULL) {
        perror("SSL_CTX_new");
        exit(EXIT_FAILURE);
    }

    // Load CA certificate
    if (!SSL_CTX_load_verify_locations(ctx, "cacert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Create SSL connection
    SSL *ssl;
    ssl = SSL_new(ctx);

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set up server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &(server_addr.sin_addr)) <= 0) {
        perror("Invalid server IP address");
        exit(EXIT_FAILURE);
    }

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // Attach SSL connection to the socket
    SSL_set_fd(ssl, sockfd);

    // Perform SSL handshake
    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify the server certificate
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        fprintf(stderr, "Server certificate verification failed\n");
        exit(EXIT_FAILURE);
    }

    // Receive data from the server
    char buffer[1024];
    int recv_bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (recv_bytes == -1) {
        perror("Receive failed");
        exit(EXIT_FAILURE);
    }

    // Null-terminate the received data
    buffer[recv_bytes] = '\0';

    // Print the received data
    printf("Received: %s\n", buffer);

    char Client_ip[1024];
    strcpy(Client_ip, buffer);
    printf("The client IP is: %s\n", Client_ip);
    int tun_fd;
    char tun_name[] = TUN_NAME;
    printf("The tun device is: %s\n", tun_name);

    // Create the TUN device
    tun_fd = create_tun_device(tun_name);
    if (tun_fd < 0) {
        fprintf(stderr, "Failed to create TUN device\n");
        exit(EXIT_FAILURE);
    }

    printf("TUN device '%s' created\n", tun_name);

    // Configure the TUN interface
    if (configure_interface(Client_ip) < 0) {
        fprintf(stderr, "Failed to configure TUN interface\n");
        close(tun_fd);
        exit(EXIT_FAILURE);
    }

    printf("TUN interface configured: IP=%s, Netmask=%s\n", Client_ip, NETMASK);

    // Configure routing
    if (configure_routing() < 0) {
        fprintf(stderr, "Failed to configure routing\n");
        close(tun_fd);
        exit(EXIT_FAILURE);
    }

    printf("Routing configured: Default route via %s\n", VPN_SERVER_IP);

    // Perform other operations or start sending/receiving data through the TUN interface
    getchar();

    close(tun_fd);

    delete_routing_config();

    // Close SSL connection and free SSL context
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    // Close the socket
    close(sockfd);

    return 0;
}