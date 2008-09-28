#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ERR \
        do { \
            fprintf(stderr, \
                    "Unexpected error occurred(%s:%d), errno = %d.\n", \
                    __FILE__, __LINE__, errno); \
        } while (0)

int
main(int argc, char *argv[])
{
    int sock, len, slen;
    struct sockaddr_in laddr, faddr;
    char buf[2048];

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        ERR;
        exit(1);
    }
    /* bind */
    memset(&laddr, 0, sizeof(laddr));
    laddr.sin_family = AF_INET;
    laddr.sin_addr.s_addr = inet_addr("0.0.0.0");
    laddr.sin_port = htons(12345);
    if (bind(sock, (struct sockaddr *)&laddr, sizeof(laddr)) == -1) {
        ERR;
        exit(1);
    }
    /* do service */
    while (1) {
        slen = sizeof(faddr);
        len = recvfrom(sock, buf, sizeof(buf), 0, 
                       (struct sockaddr *)&faddr, (socklen_t *)&slen);
        if (len == -1) {
            ERR;
            exit(1);
        }
        /* echo */
        if (sendto(sock, buf, len, 0, (struct sockaddr *)&faddr, 
                   sizeof(faddr)) == -1)
        {
            ERR;
            exit(1);
        }
    }
    return 0;
}
