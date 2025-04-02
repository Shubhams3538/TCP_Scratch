// By default when we create a raw packet the OS handles everything for us TCP IP and Congestion control algo everything
// but as we are creating from scratch we will bypass os control over this port

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <unistd.h>

// IP header is a minimum 20B header field in the Network layer since we are trying to send packets but not using os given
// stack we need to create our own ip for that we are defining the structure of the ipheader

// there is also an extra field which can be 40B that means total ipheader can be 60B at max 
// but the header len filed is only 4bit max value we can store in 4bit is 16B so to store the len of 60B ip field we divide it 
// with 4 to get actual header len take header len filed * 4 === actual ip header len
struct ipheader{

    unsigned char  iph_ihl:4, iph_ver:4; // IP Header length & version
    unsigned char  iph_tos;              // Type of Service
    unsigned short iph_len;              // IP Packet length (header + data)
    unsigned short iph_ident;            // Identification
    unsigned short iph_flags_offset;     // Fragmentation flags + offset
    unsigned char  iph_ttl;              // Time To Live
    unsigned char  iph_protocol;         // Protocol (TCP, UDP, etc.)
    unsigned short iph_chksum;           // Checksum
    struct in_addr iph_src, iph_dst;     // Source and destination IP
};

// to validate that our entire packet is correctly tranported we have two options that is either checksum or CRC here in ip we 
// use checksum which is a way to know if we have got the correct packet and there is no corruption 

// Function to calculate IP checksum

// HOW IS CHECKSUM CALCULATED? 
/*
We divide the header into 16-bit (2-byte) words.
then sum up all these 16-bit words (if there's an odd byte, pad it with zeros)
Add any carry bits (if the sum exceeds 16 bits, add the overflow back)
Take the one's complement (flip all bits)
Insert the result into the checksum field before sending the packet.

*/
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char*)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// **** THE MAIN IS PURELY FOR TESTING AS WE WILL IMPLEMENT THE SAME THING IN tcp_syn.c WE WILL COMBINE BOTH OUR IP AND TCP THERE*****
// IT IS HERE TO CHECK IF WE HAVE IMPLEMENTED THE IP CORRECTLY OR NOT AND FOR UNDERSTANDING





// int main() {
    // int sock;
    // struct sockaddr_in dest;
    // char packet[sizeof(struct ipheader)];

    // // this is a way to create a raw packet in Linux don't know how it works but fine no need 
    // sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // //  creating socket  returns a file descriptor , which is a non-negative integer (0, 1, 2, etc.).
    // // However, if socket creation fails, it returns -1.
    // if (sock < 0) {
    //     perror("Socket creation failed");
    //     return 1;
    // }

    // // Enable IP Header inclusion


    // // this line basically tells Linux that we will include our own ipheader so don't provide one 
    // int one = 1;
    // // setsockopt(socket,which protocol,telling we are including our own ip header,opt,len of opt in this case int)
    // // returns 0 for sucessfull , -1 if it fails , return 1 to exit the program
    // if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
    //     perror("setsockopt failed");
    //     return 1;
    // }

    // // Prepare the destination address
    // dest.sin_family = AF_INET;

    // dest.sin_addr.s_addr = inet_addr("127.0.0.1"); // Destination IP for now i m using my own loopback address

    // // Fill in the IP header
    // struct ipheader *ip = (struct ipheader *) packet;
    // ip->iph_ver = 4;
    // ip->iph_ihl = 5;
    // ip->iph_tos = 0;
    // ip->iph_len = htons(sizeof(struct ipheader));
    // ip->iph_ident = htons(54321);
    // ip->iph_flags_offset = 0;
    // ip->iph_ttl = 64;
    // ip->iph_protocol = IPPROTO_RAW;
    // ip->iph_src.s_addr = inet_addr("192.168.182.130"); // My Private ip
    // ip->iph_dst.s_addr = dest.sin_addr.s_addr;
    // ip->iph_chksum = checksum(packet, sizeof(struct ipheader));

    // // Send the packet
    // if (sendto(sock, packet, sizeof(struct ipheader), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
    //     perror("Packet sending failed");
    //     return 1;
    // }

    // printf("Raw IP packet sent successfully!\n");

    // close(sock);
    // return 0;
    // // STEPS TO VERIFY IF CODE TILL HERE IS WORKING OR NOT 
    // // after completing till here we need to check if the code we have written till now is correct or not my sending an ip
    // // packet to ourselves we can do that using packet sniffer in ubuntu 
    // // command to so is ---> sudo tcpdump -i ens33 -n icmp or ip or google it.

    // // there might be multiple problems one might face 
    // // 1st when you run your code from ide it will not be permitted to run because ide doesn't have adminstrator permission to do 
    // // for that go the terminal and then type these commands 

    // /* 
    // sudo setcap cap_net_raw=eip ./raw_socket
    // ./raw_socket
    // */

    // // step 2 now to see if the packet is sent from your ip and reaching your loopback address or not open another terminal and
    // // use this command ---> sudo tcpdump -i lo -n -X host 127.0.0.1
    // // this will simply filter req coming to loopback address

    // // we are done with ip now we will create our own tcp header and merge tcp and ip packets together for a sucessfull transmission

   // return 0;
 //}


 