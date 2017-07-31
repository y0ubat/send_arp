#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#pragma pack(push,1)


struct packet_eth
{
    u_int8_t daddr[6];
    u_int8_t saddr[6];
    u_int16_t type;
};

struct arp_packet {
    u_int16_t htype;
    u_int16_t ptype;
    u_int8_t  hlen;
    u_int8_t  plen;
    u_int16_t oper;
    u_int8_t  sha[6];
    u_int8_t  spa[4];
    u_int8_t  tha[6];
    u_int8_t  tpa[4];
    u_int8_t  trail[18];
};

#pragma pack(pop)

char *get_mac(char *test)
{
    int fd;
    struct ifreq ifr;
    char *iface = test;
    unsigned char *mac = NULL;

    memset(&ifr, 0, sizeof(ifr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

    if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
        mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    }

    close(fd);

    return mac;

}

int main(int argc, char *argv[])
{
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */
    struct arp_packet;
    unsigned char *my_mac = {0};

    if(argc != 4)
        printf("[Using] ./program interface dip sip\n");

    my_mac = get_mac(argv[1]);
    printf("My_Mac : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n" , my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);

    return(0);
}
