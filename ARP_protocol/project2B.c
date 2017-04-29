#include "util.h"
#include "frameio.h" 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <list>
#include <iostream>

#define SIZE_CACHE 100

struct ether_frame       // handy template for 802.3/DIX frames
{
   octet dst_mac[6];     // destination MAC address
   octet src_mac[6];     // source MAC address
   octet prot[2];        // protocol (or length)
   octet data[1500];     // payload
};
struct arp_ether_frame       // handy template for 802.3/DIX frames
{
   octet dst_mac[6];     // destination MAC address
   octet src_mac[6];     // source MAC address
   octet prot[2];        // protocol (or length)
   octet data[32];     // payload
};
struct arp_frame
{
	octet mac_type[2];
	octet protocol_type[2];
	octet mac_len;
	octet protocol_len;
	octet opcode[2];
	octet sender_mac[6];
	octet sender_ip[4];
	octet target_mac[6];
	octet target_ip[4];
};
struct arp_pairs
{
	octet mac[6];
	octet ip[4];
};



frameio net;             // gives us access to the raw network
message_queue ip_queue;  // message queue for the IP protocol stack
message_queue arp_queue; // message queue for the ARP protocol stack
pthread_t threads;
arp_pairs cache[SIZE_CACHE];
int cache_index = 0;

void* receive_frame(void* arg);
void* arp_pair_updater(void *arg);
void* arp_requester(void* arg);
bool add_pair(octet* mac,octet* ip);



int main()
{
	
	net.open_net("enp3s0");

	// Thread for putting packets on queues
	pthread_create(&threads,NULL,receive_frame,NULL);
	// Thread that pulls arp frames and updates the arp cache
	pthread_create(&threads,NULL,arp_pair_updater,NULL);
	// Thread that continually sends arp requests
	pthread_create(&threads,NULL,arp_requester,NULL);
	for( ; ;) sleep(1);
}

void* receive_frame(void* arg)
{	
	std::cout << "RECIEVE FRAME THREAD STARTED" << std::endl;
	ether_frame buffer;
	while(1)
	{
	   int n = net.recv_frame(&buffer,sizeof(buffer));
	   if ( n < 42 ) continue; // bad frame!
	    switch ( buffer.prot[0]<<8 | buffer.prot[1] )
      	{
          case 0x800:
             ip_queue.send(PACKET,buffer.data,n);
             break;
          case 0x806:
             arp_queue.send(PACKET,buffer.data,n);
             break;
		  default:
			  break;
      	}	
	}
}
void* arp_pair_updater(void *arg)
{
	arp_frame received;
	int request_size;
	event_kind type = PACKET;
	std::cout << "ARP PAIRING THREAD STARTED" << std::endl;
	while(1)
	{
		request_size = arp_queue.recv(&type,(void*)&received,(int)sizeof(received));
		if(received.sender_ip[0] == 192 && received.sender_ip[1] == 168)
			add_pair(received.sender_mac, received.sender_ip);
	}
}
void* arp_requester(void* arg)
{
	arp_frame message;
	arp_ether_frame ether_message;
	octet myip[4] =  {0xC0,0xA8,0x01,0x14};
	octet target_ip[4] =  {0xC0,0xA8,0x01,0x0A};
	octet target = 10;
	octet target_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	while(1)
	{	
		for (int i = 0; i < SIZE_CACHE; ++i)
		{
			if(cache[i].ip[3] == target)
				{
					memcpy(target_mac, cache[i].mac, sizeof(target_mac));
				}
				
		}
		
		//Arp Part
		message.mac_type[0] = 0x00;
		message.mac_type[1] = 0x01;
		message.protocol_type[0] = 0x08;
		message.protocol_type[1] = 0x00;
		message.mac_len = 6;
		message.protocol_len = 4;
		message.opcode[1] = 0x01; //request ARP
		memcpy(message.sender_mac,net.get_mac(), sizeof(message.sender_mac));
		memcpy(message.sender_ip,myip,sizeof(myip));
		memcpy(message.target_mac, target_mac, sizeof(target_mac));
		memcpy(message.target_ip,target_ip,sizeof(target_ip));
		
		//Ether Frame Part
		memcpy(ether_message.dst_mac,message.target_mac,sizeof(message.target_mac));
		memcpy(ether_message.src_mac,message.sender_mac,sizeof(message.sender_mac));
		ether_message.prot[0] = 0x08;
		ether_message.prot[1] = 0x06;
		memcpy(ether_message.data, &message, sizeof(message));
		std::cout << "ARP REQUESTER THREAD STARTED" << std::endl;
		if(target_mac[0] == 0xff) 
				std::cout << "not found" << std::endl;
		else
			std::cout << "found" << std::endl;
		//send message
		std::cout << net.send_frame(&ether_message,sizeof(ether_message));
		sleep(1);
	}
}
bool add_pair(octet* mac,octet* ip)
{
	/*for (int i = 0; i < 6; ++i)
	{
		printf("%02x ",*(mac+i));
	
	}
	printf("\n");
	for (int i = 0; i < 4; ++i)
	{
		printf("%u ",*(ip+i));
	
	}
	printf("\n");*/
	for (int i = 0; i < SIZE_CACHE; ++i)
	{
		if(cache[i].ip[3] == *(ip+3))
			{
				std::cout << "already in cache" <<std::endl;
				return 0;
			}

	}
	 memcpy(&cache[cache_index].mac,mac,sizeof(cache[cache_index].mac));
	 memcpy(&cache[cache_index].ip,ip,sizeof(cache[cache_index].ip));
	 printf("%02x %u \n", cache[cache_index].mac[5], cache[cache_index].ip[3]);
	 cache_index < SIZE_CACHE ? cache_index++: cache_index = 0;
	 return 1;

}