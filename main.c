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

void send_packet(char *interface,char *sip,char *dip)
{

    struct packet_eth eth;
    struct packet_arp arp;
    int tmp = 0;

    for(int i=0;i<6;i++)
        eth.dmac[i] = 0xff;

    memcpy(eth.smac,get_mac("ens33"),6);

    eth.type = ntohs(0x0806);

    memcpy(all_packet,&eth,14);

    arp.htype = ntohs(0x0001);
    arp.ptype = ntohs(0x0800);
    arp.hlen = "\x06";
    arp.plen = "\x04";
    arp.oper = ntohs(0x0001);

    memcpy(arp.sha,get_mac("ens33"),6);

    tmp = ntohsl(sip);

    memcpy(arp.spa,sip,4);
    tmp =0;
    memcpy(arp.tha,&eth.dmac,6);
    tmp = ntohl(dip);
    memcpy(arp.tpa,dip,4);

    memcpy(all_packet+14,&arp,28);
}


int main(int argc, char *argv[])
{

    unsigned char *my_mac = {0};
    struct in_addr addr,addr2;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    int res;

    /*  if(argc != 4)
    {
        printf("[Using] ./program [interface] [sip] [dip]\n");
        exit(1);
    }*/



  //  inet_pton(AF_INET,"192.168.1.145",&addr.s_addr);
    //inet_pton(AF_INET,"192.168.1.1",&addr2.s_addr);
    send_packet("ens33",inet_addr("192.168.1.145"),inet_addr("192.168.1.1"));

    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        //     printf("Couldn't open device %s: %s", interface, errbuf);
        exit(1);
    }

    res = pcap_sendpacket(handle, ((u_char*)&all_packet), (sizeof(struct packet_arp)+sizeof(struct packet_eth)));
    printf("%d\n",res);

    if(res != 0)
    {
        printf("Error sending packet: %s", pcap_geterr(handle));
        exit(1);
    }

    printf("complete\n");

    pcap_close(handle);


    return(0);
}
