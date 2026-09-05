#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>

static int g_counter;

void on_signal(int sig) {
    g_counter++;
    printf("caught signal\n");
}

void log_message(char *user_input) {
    printf(user_input);
}

void run_command(char *user_cmd) {
    char buf[128];
    snprintf(buf, sizeof(buf), "ls %s", user_cmd);
    system(buf);
}

int open_checked(const char *path) {
    if (access(path, W_OK) == 0) {
        return open(path, O_RDWR);
    }
    return -1;
}

static int recurse(int n) {
    return recurse(n + 1);
}

void copy_sized(void) {
    int len = -1;
    char buf[16];
    memcpy(buf, "hello world", (size_t)len);
}

int main(void) {
    signal(SIGINT, on_signal);
    recurse(0);
    copy_sized();
    return 0;
}
