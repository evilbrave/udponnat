#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define ERR \
        do { \
            fprintf(stderr, \
                    "Unexpected error occurred(%s:%d), errno = %d.\n", \
                    __FILE__, __LINE__, errno); \
        } while (0)
#define TEST_LOOP   1000

int
main(int argc, char *argv[])
{
    struct sockaddr_in raddr;
    int sock, ret, i, len, lost, total_ms, j;
    struct timeval tv, btv, etv;
    char buf[2048];

    /* parse command */
    if (argc != 3) {
        fprintf(stderr, "Usage: %s host port\n", argv[0]);
        exit(1);
    }
    memset(&raddr, 0, sizeof(raddr));
    raddr.sin_family = AF_INET;
    raddr.sin_port = htons(atoi(argv[2]));
    raddr.sin_addr.s_addr = inet_addr(argv[1]);

    /* create socket */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        ERR;
        exit(1);
    }
    /* set timeout for udp receive */
    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = 3;
    ret = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (ret == -1) {
        ERR;
        exit(1);
    }
    /* test begin */
    lost = 0;
    total_ms = 0;
    for (i = 0; i < TEST_LOOP; i++) {
        /* make send buf */
        len = snprintf(buf, sizeof(buf), "%d", i);
        /* send */
        if (sendto(sock, buf, len + 1, 0, (struct sockaddr *)&raddr, sizeof(raddr)) == -1) {
            ERR;
            exit(1);
        }
        /* get send time */
        gettimeofday(&btv, NULL);
        /* recv */
        while (1) {
            len = recvfrom(sock, buf, sizeof(buf) - 1, 0, NULL, NULL);
            if (len == -1) {
                if (errno == EAGAIN)  {
                    lost++;
                    goto next_loop;
                }
                ERR;
                exit(1);
            }
            buf[len] = '\0';
            /* check */
            if (strlen(buf) != len - 1)
                /* wrong packet */
                goto next_recv;
            for (j = 0; j < len - 1; j++) {
                if (!isdigit(buf[j]))
                    /* wrong packet */
                    goto next_recv;
            }
            /* received */
            break;
next_recv:
            continue;
        }
        /* get recv time */
        gettimeofday(&etv, NULL);
        total_ms += (etv.tv_sec - btv.tv_sec) * 1000 + (etv.tv_usec - btv.tv_usec) / 1000;
next_loop:
        continue;
    }

    /* output results */
    printf("total send: %d, lost: %d\n", TEST_LOOP - lost, lost);
    printf("average loop time: %d(ms)\n", 
           (TEST_LOOP - lost == 0) ? -1 : total_ms / (TEST_LOOP - lost));

    return 0;
}
