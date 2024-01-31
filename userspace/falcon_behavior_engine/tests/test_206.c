#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main() {
    int sockfd;
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    for (int port = 1000; port <= 1010; port++) {  // Trying to connect to ports from 1000 to 1010
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("Could not create socket");
            continue;
        }

        addr.sin_port = htons(port);

        if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            printf("Failed to connect to port %d\n", port);
        } else {
            printf("Connected to port %d\n", port);
        }

        close(sockfd);
    }

    return 0;
}
