#include "util.h"
#include "frameio.h" 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <list>
#include <iostream>
#include <arpa/inet.h>
#include <time.h>
#include <vector>

// Project 3 Samuel Bhushan & Hailey Parkin
// Step 1 Identify ICMP Packets

std::vector<unsigned short> sequences;
bool vector_in_use = false;
short seq = 0;

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
struct ip_frame
{
	octet version_ihl;
	octet dscp_ecn;
	octet total_length[2];
	octet ID[2];
	octet flags_frag[2];
	octet ttl; 
	octet protocol;
	octet header_checksum[2];
	octet src_ip[4];
	octet dst_ip[4];
	octet data[1480];
	
};
struct icmp_frame
{
	 octet type;
	 octet code;
	 octet checksum[2];
	 octet restofheader[4];
	 octet data[1472];
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
frameio net;
message_queue ip_queue;
message_queue arp_queue;
pthread_t threads;
void* receive_frame(void* arg);
void* ip_checker(void* arg);
bool icmp_checker(void* ip_data, int size);
void process_icmp(void* ip_data, int size, octet* dest, void* id);
void find_mac(void* mac,void* ip);
void* send_icmp(void *arg);
void arp_mac(void* mac, void* ip);
bool send_ip(void* ip_data, int size, octet* dest, octet* idpart);

int main()
{
	net.open_net("enp3s0");
	// Thread for putting packets on queues
	pthread_create(&threads,NULL,receive_frame,NULL);
	pthread_create(&threads,NULL,ip_checker,NULL);
	pthread_create(&threads,NULL,send_icmp,NULL);
	for(;;)
		sleep(1);
}

void* receive_frame(void* arg)
{	
	//std::cout << "RECIEVE FRAME THREAD STARTED" << std::endl;
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
void* ip_checker(void *arg)
{
	ip_frame received;
	int ip_size;
	int sum;
	octet initial_chksum[2];
	event_kind pck = PACKET;
	//std::cout << "ICMP FILTER THREAD STARTED" << std::endl;
	while(1)
	{
		ip_size = ip_queue.recv(&pck,&received,sizeof(received));

		// VALIDATE IP PACKET
		initial_chksum[0] = received.header_checksum[0];
		initial_chksum[1] = received.header_checksum[1];
		received.header_checksum[0]= 0;
		received.header_checksum[1] = 0;
		sum = chksum((octet*)&received,20,0);
		received.header_checksum[0] = ~sum >> 8;
    	received.header_checksum[1] = ~sum & 0xff;
    	if(!(initial_chksum[0] == received.header_checksum[0] &&
    		initial_chksum[1] == received.header_checksum[1]))
    	{
			//std::cout << "Bad IP checksum " << std::endl;
			continue;
		}    				
    	// Check if ICMP
 		if(!(received.protocol == 1))
 		{
 			//std::cout << "Wrong Protocol " << std::endl;
 			continue;
 		}
 		// Validate the ICMP packet
		if(!icmp_checker(received.data, 64))
		{
			//std::cout << "Bad ICMP checksum " << std::endl;
			continue;
		}
		process_icmp(received.data,64,received.src_ip,&received.ID);
		printf("ICMP Packet received \n");
	}
}

bool icmp_checker(void* ip_data, int size)
{
	int sum;
	octet initial_chksum[2];

	icmp_frame* icmp = new icmp_frame;
	icmp = (icmp_frame*)ip_data;

	initial_chksum[0] = icmp->checksum[0];
	initial_chksum[1] = icmp->checksum[1];
	icmp->checksum[0]= 0x00;
	icmp->checksum[1] = 0x00;
	sum = chksum((octet*)icmp,size,0);
	icmp->checksum[0] = ~sum >> 8;
    icmp->checksum[1] = ~sum & 0xff;
    if(initial_chksum[0] == icmp->checksum[0] &&
    	initial_chksum[1] == icmp->checksum[1])
    {
    	return true;
    }
    return false;

}
void process_icmp(void* ip_data, int size, octet* dest, void* id)
{
	octet* idpart =(octet*) id;
	icmp_frame* icmp = (icmp_frame*)ip_data;
	icmp_frame icmp_out;
	int sum;
	unsigned short recv_seq;
	if(icmp->type == 0x08)
	{
		//printf("got icmp request\n");
		//respond to request
		icmp_out.type = 0x00; // zero for echo reply(ping) 
		icmp_out.code = 0x00;	
		for (int i = 0; i < 4; ++i)
		{
			icmp_out.restofheader[i] = icmp->restofheader[i]; //not using this
		}
		memcpy(&icmp_out.data,&icmp->data,56);

		icmp_out.checksum[0]=0;
		icmp_out.checksum[1]=0;
		sum = chksum((octet*)&icmp_out,64,0);
		icmp_out.checksum[0]=~sum >> 8;
		icmp_out.checksum[1]=~sum & 0xff;

		send_ip(&icmp_out, 64, dest, idpart);
	}
	else if(icmp->type == 0x0)
	{
		//printf("got icmp reply\n");
		recv_seq = icmp->restofheader[2]*256 + icmp->restofheader[3];
		//memcpy(&recv_seq,&icmp->restofheader,2);
		printf("sequence number: %d\n", recv_seq);
		while(vector_in_use)
			sleep(1); //wait for vector
		vector_in_use = true;
		for (int i = 0; i < sequences.size(); ++i)
		{
			if(sequences[i] == recv_seq)
			{
				sequences.erase(sequences.begin()+i);
				std::cout << "yay received reply to our request" << std::endl;
				break;
			}
		}
		vector_in_use = false;
		
	}

}
bool send_ip(void* ip_data, int size, octet* dest, octet* idpart)
{
	ip_frame packet;
	ether_frame ether;
	int checksum;


	// Make the IP header

	memcpy(&packet.data, ip_data,size);
	packet.version_ihl = 0x45;
	packet.dscp_ecn = 0x00;

	packet.total_length[0] =(size + 20)>> 8;
	packet.total_length[1] = (size+20) & 0xff;

	memcpy(&packet.ID,&idpart,2);
	packet.flags_frag[2] =0x02;
	packet.ttl = 64; 
	packet.protocol = 0x01;

	packet.src_ip[0] = 0xC0;
	packet.src_ip[1] = 0xA8;
	packet.src_ip[2] = 0x01;
	packet.src_ip[3] = 0x0A;

	packet.dst_ip[0] = dest[0];
	packet.dst_ip[1] = dest[1];
	packet.dst_ip[2] = dest[2];
	packet.dst_ip[3] = dest[3];


	// Calculate IP Checksum and add it
	packet.header_checksum[0]=0;
	packet.header_checksum[1]=0;
	checksum = chksum((octet*)&packet,20,0);
	packet.header_checksum[0]=~checksum >> 8;
	packet.header_checksum[1]=~checksum & 0xff;

	// Stuff into etherframe and send
	find_mac(&ether.dst_mac,packet.dst_ip);
	memcpy(ether.src_mac,net.get_mac(),sizeof(ether.src_mac));
	ether.prot[0] = 0x08;
	ether.prot[1] = 0x00;
	memcpy(ether.data,&packet,84); // copy IP into ether data
	
	net.send_frame(&ether,84+14);
	return 1;
}
void* send_icmp(void *arg)
{
	bool result;

	icmp_frame icmp_out;
	unsigned char* out = new unsigned char[65];
	char user_input[15];
	octet target_ip[4];
	struct sockaddr_in hexip;
	int sum;
	
	while(1)
	{
		// Get and convert IP
		std::cout << "Desired IP address: " << std::endl;
		std::cin >> user_input;
		inet_pton(AF_INET,user_input,&(hexip.sin_addr));
		for (int i = 0; i < 4; ++i)
			target_ip[i] = (hexip.sin_addr.s_addr >>(8*i)) & 0xff;

		// Construct ICMP
		icmp_out.type = 0x08; // eight for echo request(ping) 
		icmp_out.code = 0x00;
		
		icmp_out.restofheader[0] = 0xde; 
		icmp_out.restofheader[1] = 0xad;

		//add sequence number
		while(vector_in_use)
			sleep(1);   //wait for vector to be free
		vector_in_use = true;
		seq++;
		sequences.push_back(seq);
		icmp_out.restofheader[2] = seq >> 8; 
		icmp_out.restofheader[3] = seq & 0xff; 
		vector_in_use = false;

		//calculate checksum
		icmp_out.checksum[0]=0;
		icmp_out.checksum[1]=0;
		sum = chksum((octet*)&icmp_out,64,0);
		icmp_out.checksum[0]=~sum >> 8;
		icmp_out.checksum[1]=~sum & 0xff;

		// Send out ICMP
		memcpy(out,&icmp_out,64);
		octet id[2] = {0xbe,0xef};
		result = send_ip(out,64,target_ip,id);
		
		if(result);
			//std::cout << "ICMP send success" << std::endl;
		else
			std::cout << "ICMP send failure" << std::endl;
		sleep(1);
	}	
}
void find_mac(void* mac,void* ip)
{
	octet* addr = (octet*)ip;
	bool is_lan = true;
	octet myip[4] = {0xc0,0xA8,0x01,0xA};
	octet route_ip[4] = {0xc0,0xA8,0x01,0x1};
	octet target_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	for (int i = 0; i < 3; ++i)
	{
		if(addr[i] != myip[i])
			is_lan = false;
	}
 	if(is_lan)
 	{
 		// Get the mac
 		arp_mac(&target_mac,addr);
 	}
 	else
 	{
 		// get the router's mac
 		arp_mac(&target_mac,route_ip);	
 	}
	memcpy(mac,target_mac,6);
}
void arp_mac(void* mac, void* ip)
{
	octet myip[4] =  {0xC0,0xA8,0x01,0xA};
	octet* target_mac = (octet*)mac;
	octet* target_ip = (octet*)ip;
	// Make ARP packet
	arp_frame message;
	arp_ether_frame ether_message;
	message.mac_type[0] = 0x00;
	message.mac_type[1] = 0x01;
	message.protocol_type[0] = 0x08;
	message.protocol_type[1] = 0x00;
	message.mac_len = 6;
	message.protocol_len = 4;
	message.opcode[1] = 0x01; //request ARP

	memcpy(&message.sender_mac,net.get_mac(), sizeof(message.sender_mac));
	memcpy(&message.sender_ip,myip,sizeof(myip));
	memcpy(&message.target_mac, target_mac, sizeof(message.target_mac));
	memcpy(&message.target_ip,target_ip,sizeof(message.target_ip));
	
	//Ether Frame Part
	memcpy(ether_message.dst_mac,message.target_mac,sizeof(message.target_mac));
	memcpy(ether_message.src_mac,message.sender_mac,sizeof(message.sender_mac));
	ether_message.prot[0] = 0x08;
	ether_message.prot[1] = 0x06;
	memcpy(ether_message.data, &message, sizeof(message));

	//std::cout << "Sending ARP!" << std::endl;
	net.send_frame(&ether_message,sizeof(ether_message));
	
	arp_frame received;
	bool found = false;
	bool same;
	int request_size;
	event_kind type = PACKET;
	while(!found)
	{
		request_size = arp_queue.recv(&type,(void*)&received,(int)sizeof(received));
		//printf("received size: %d!\n",request_size);
		same = true;
		for (int i = 0; i < 4; ++i)
		{
			if(received.sender_ip[i] != *(target_ip+i))
				same = false;
		}
		if(same)
		{
			//found the arp reply
			//std::cout << "Found ARP!" << std::endl;
			memcpy(mac,&received.sender_mac,sizeof(received.sender_mac));
			found = true;
		}

	}
}
