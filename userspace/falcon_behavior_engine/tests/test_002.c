#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    FILE *fp;
    char *filename = "test_file.txt";

    // 尝试打开文件进行写入，如果文件不存在则创建它
    fp = fopen(filename, "w");
    if (fp == NULL) {
        perror("Error opening file");
        return -1;
    }

    // 向文件写入数据
    fprintf(fp, "This is a test file to trigger 'Dropped new files' rule.\n");

    // 关闭文件
    fclose(fp);

    printf("File '%s' created and data written.\n", filename);

    return 0;
}
