#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>



char all_packet[255] = {0};

#pragma pack(push,1)


struct packet_eth
{
    u_int8_t dmac[6];
    u_int8_t smac[6];
    u_int16_t type;
};

struct packet_arp {
    u_int16_t htype;
    u_int16_t ptype;
    u_int8_t  hlen;
    u_int8_t  plen;
    u_int16_t oper;
    u_int8_t  sha[6];
    u_int8_t  spa[4];
    u_int8_t  tha[6];
    u_int8_t  tpa[4];
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

void send_packet(char *interface,char *my_mac,char *sip,char *dip)
{

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    struct packet_eth *eth;
    struct packet_arp *arp;
    int res;

    for(int i=0;i<6;i++)
        eth->dmac[i] = 0xff;

    memcpy(eth->smac,my_mac,6);
    memcpy(eth->type,ntohs(0x0806),2);

    memcpy(all_packet,eth,sizeof(struct packet_eth *));



    memcpy(arp->htype,ntohs(0x0001),1);
    memcpy(arp->ptype,ntohs(0x0800),2);
    memcpy(arp->hlen,"\x06",1);
    memcpy(arp->plen,"\x04",1);
    memcpy(arp->oper,ntohs(0x0001),2);
    memcpy(arp->sha,my_mac,6);
    memcpy(arp->spa,ntohs(sip),4);
    memcpy(arp->tha,eth->dmac,6);
    memcpy(arp->tpa,ntohs(dip),4);

    memcpy(all_packet+14,arp,sizeof(struct packet_arp *));

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Couldn't open device %s: %s", interface, errbuf);
        exit(1);
    }

    res = pcap_sendpacket(handle, ((u_char*)&all_packet), sizeof(struct packet_arp *));

    if(res != 0)
    {
        printf("Error sending packet: %s", pcap_geterr(handle));
        exit(1);
    }

    printf("complete\n");

    pcap_close(handle);




}


int main(int argc, char *argv[])
{

    unsigned char *my_mac = {0};

    if(argc != 4)
        printf("[Using] ./program [interface] [dip] [sip]\n");

    my_mac = get_mac(argv[1]);
    printf("My_Mac : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n" , my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);




    return(0);
}
