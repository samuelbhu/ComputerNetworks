#include "frameio.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

frameio net;             // gives us access to the raw network
message_queue ip_queue;  // message queue for the IP protocol stack
message_queue arp_queue; // message queue for the ARP protocol stack

struct ether_frame       // handy template for 802.3/DIX frames
{
   octet dst_mac[6];     // destination MAC address
   octet src_mac[6];     // source MAC address
   octet prot[2];        // protocol (or length)
   octet data[1500];     // payload
};

void* packet_printer(void*);

pthread_t packet;

int main()
{
	net.open_net("enp3s0");
	pthread_create(&packet,NULL,packet_printer,NULL);
	for( ; ;) sleep(1);
}

void* packet_printer(void *arg)
{
	ether_frame buffer;

	while(1)
	{
	   int n = net.recv_frame(&buffer,sizeof(buffer));
	   if ( n < 42 ) continue; // bad frame!
	   if((buffer.src_mac[5] == 201) && (buffer.prot[1] == 0))
	     {
	       printf("buf %d ",buffer.prot[0]);
	       printf("buf %d \n",buffer.prot[1]);
	       for(int i=0;i<42;i++)
		 {
		   //printf("i%d ",i);
		   printf(" %02x ", buffer.data[i]);
		   if(i== 21 || i==41)
		     printf(" \n");
		 }
	     }
	}
}
