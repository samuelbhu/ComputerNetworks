#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <errno.h>
#include <fstream>
using namespace std;

//
// default IP address (if not specified on the command line
//
#define IP_ADDR "192.168.1.20"




int main(int argc, char *argv[])
{
	//FILE
	fstream file;
	file.open("out_from_client.txt",fstream::out);
	//file<<"file opened"<<endl;

	int thesocket;
   thesocket = socket(PF_INET, SOCK_STREAM, 0);
   if(thesocket == -1) cout <<"socket not created"<<endl;
   // larger container for a generalized address
   sockaddr address;
   	
	// address container for an inaddress
	sockaddr_in *socketIn = (sockaddr_in *) &address;
	// Zero out inaddress part and set listening location (server addr)
	memset(socketIn,0,sizeof(sockaddr_in));
  	socketIn->sin_family = PF_INET;
	socketIn->sin_port = htons(5600);
	socketIn->sin_addr.s_addr = htonl(INADDR_ANY);

	int error;
	error = bind(thesocket, (const struct sockaddr*)&address, sizeof(sockaddr_in));
	if(error == -1)
	{
		cout<<strerror(errno)<<"  unsuccessful bind"<<endl;
	}

	int backlog = 5;
	error = listen(thesocket, backlog);
	if(error != 0) cout<<error<<"  unsuccessful listening"<<endl;

	int client_data_size = sizeof(sockaddr_in);
	int acceptedSocket;
	acceptedSocket = accept(thesocket, &address, (socklen_t*)&client_data_size);

	if(acceptedSocket == -1) cout<<"acceptance error"<<endl;

   char buffer = 0;
   while(read(acceptedSocket,&buffer,1)>0)
   { 
      file<<buffer;
	   cout<<buffer;
   }

   file.close();
	close(thesocket);
}