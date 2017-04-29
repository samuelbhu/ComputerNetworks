#include "frameio.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <list>
#include <iostream>

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

void* arp_reply(void*);
void* receive_arp(void*);
bool construct_send(arp_frame *request);

pthread_t threads;


int main()
{
	net.open_net("enp3s0");
	pthread_create(&threads,NULL,receive_arp,NULL);
	pthread_create(&threads,NULL,arp_reply,NULL);
	for( ; ;) sleep(1);
}

void* receive_arp(void* arg)
{	ether_frame buffer;

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

void* arp_reply(void *arg)
{
	arp_frame request;
	octet myip[4] =  {0xC0,0xA8,0x01,0x28};
	bool ip_match = true;
	int request_size;
	event_kind type = PACKET;
	while(1)
	{
		request_size = arp_queue.recv(&type,(void*)&request,(int)sizeof(request));
		//Check if it is a request
		if(request.opcode[1] == 0x01 && request.target_ip[3] == 0x28)
		{
			//Check IP ADDR
			for(int i = 0; i < 4; ++i)
			{
				if(request.target_ip[i] != myip[i])
					ip_match = false;

			}
			
			if(ip_match)
				construct_send(&request);	
		}	 

		
	}
}

bool construct_send(arp_frame *request)
{
	arp_frame reply;
	arp_ether_frame ether_reply;
	for(int i=0; i<sizeof(ether_reply.data); i++)
	{
		ether_reply.data[i] = 0;
	}

	std::cout << "FOUND ARP REQUEST TO US!" << std::endl;

	//Arp Reply Part
	reply.mac_type[0] = 0x00;
	reply.mac_type[1] = 0x01;
	reply.protocol_type[0] = 0x08;
	reply.protocol_type[1] = 0x00;
	reply.mac_len = 6;
	reply.protocol_len = 4;
	reply.opcode[1] = 0x02; //switch to a reply ARP
	memcpy(reply.sender_mac,net.get_mac(), sizeof(request->sender_mac));
	memcpy(reply.sender_ip,request->target_ip,sizeof(request->target_ip));
	memcpy(reply.target_mac, request->sender_mac, sizeof(request->sender_mac));
	memcpy(reply.target_ip,request->sender_ip,sizeof(request->sender_ip));
	//Ether Frame Part
	memcpy(ether_reply.dst_mac,reply.target_mac,sizeof(reply.target_mac));
	memcpy(ether_reply.src_mac,reply.sender_mac,sizeof(reply.sender_mac));
	ether_reply.prot[0] = 0x08;
	ether_reply.prot[1] = 0x06;
	memcpy(ether_reply.data, &reply, sizeof(reply));

for (int i = 0; i < sizeof(ether_reply.dst_mac); ++i)
	{
		printf("%02x",ether_reply.dst_mac[i]);
	
	}
	std::cout<<std::endl;
	for (int i = 0; i < sizeof(ether_reply.src_mac); ++i)
	{
		printf("%02x",ether_reply.src_mac[i]);
	
	}
	std::cout<<std::endl;
	for (int i = 0; i < sizeof(ether_reply.prot); ++i)
	{
		printf("%02x",ether_reply.prot[i]);
	
	}
	std::cout<<std::endl;
		for (int i = 0; i < sizeof(ether_reply.data); ++i)
	{
		printf("%02x",ether_reply.data[i]);
		
	}
	std::cout<<std::endl;
	
	

	std::cout << std::endl;
	std::cout << net.send_frame(&ether_reply,sizeof(ether_reply));
	std::cout << sizeof(ether_reply) << std::endl;	
}

