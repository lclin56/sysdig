#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define TARGET_IP "8.8.8.8"  // 使用一个公共的非本地IP地址进行测试
#define TARGET_PORT 80       // 示例端口

int main() {
    int sockfd;
    struct sockaddr_in target_addr;
    char buffer[1024] = "Hello, World!";
    ssize_t sent_bytes, recv_bytes;

    // 创建一个socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0); // 使用SOCK_DGRAM进行UDP通信
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 设置接收超时
    struct timeval timeout;
    timeout.tv_sec = 1;  // 超时时间：1秒
    timeout.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Setsockopt failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 设置目标地址
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(TARGET_PORT);
    target_addr.sin_addr.s_addr = inet_addr(TARGET_IP);

    // 使用sendto发送数据
    sent_bytes = sendto(sockfd, buffer, strlen(buffer), 0, (const struct sockaddr *) &target_addr, sizeof(target_addr));
    if (sent_bytes < 0) {
        perror("Sendto failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("Data sent to %s:%d\n", TARGET_IP, TARGET_PORT);

    // 使用recvfrom接收数据
    recv_bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
    if (recv_bytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("Recvfrom timed out\n");
        } else {
            perror("Recvfrom failed");
        }
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    buffer[recv_bytes] = '\0';  // 确保字符串正确终止
    printf("Data received: %s\n", buffer);

    // 关闭socket
    close(sockfd);
    return 0;
}
