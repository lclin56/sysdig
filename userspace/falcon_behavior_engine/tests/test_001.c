#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    // 获取当前可执行文件路径
    char path[1024];
    ssize_t length = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (length != -1) {
        path[length] = '\0';

        // 删除自身可执行文件
        if (unlink(path) == 0) {
            printf("Executable file deleted successfully.\n");
        } else {
            printf("Failed to delete executable file.\n");
        }
    } else {
        printf("Failed to get executable file path.\n");
    }

    return 0;
}
