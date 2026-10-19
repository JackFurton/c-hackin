#include <stdio.h>
#include <string.h>

static const char secret[] = "hunter2";
int attempts;

static int check(const char *guess)
{
    attempts++;
    return strcmp(guess, secret) == 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: %s <password>\n", argv[0]);
        return 1;
    }
    puts(check(argv[1]) ? "access granted" : "nope");
    return 0;
}
