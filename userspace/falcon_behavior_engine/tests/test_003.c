#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    char buffer[1024]; // 读取缓冲区
    ssize_t bytes_read;

    // 获取程序的可执行路径
    char exe_path[1024];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len == -1) {
        perror("readlink");
        return 1;
    }
    exe_path[len] = '\0'; // 确保路径字符串正确终止

    // 打开可执行文件进行读取
    int fd = open(exe_path, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return 1;
    }

    // 从文件中读取数据
    bytes_read = read(fd, buffer, sizeof(buffer));
    if (bytes_read == -1) {
        perror("read");
        close(fd);
        return 1;
    }

    printf("Read %zd bytes from %s\n", bytes_read, exe_path);

    // 关闭文件描述符
    close(fd);

    return 0;
}
