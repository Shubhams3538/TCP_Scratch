    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <netinet/tcp.h>
    #include <netinet/ip.h>
    #include <sys/socket.h>
    #include <sys/select.h>
    #include <sys/time.h>

    // Custom TCP header struct (20 bytes)
    struct tcphdr_custom {
        uint16_t source;
        uint16_t dest;
        uint32_t seq;
        uint32_t ack_seq;
        uint8_t doff_res;
        uint8_t flags;
        uint16_t window;
        uint16_t check;
        uint16_t urg_ptr;
    };

    // Pseudo-header for checksum calculation
    struct pseudo_header {
        uint32_t source_address;
        uint32_t dest_address;
        uint8_t placeholder;
        uint8_t protocol;
        uint16_t tcp_length;
    };

    // Function to calculate checksum
    unsigned short checksum(void *b, int len) {
        unsigned short *buf = b;
        unsigned int sum = 0;
        unsigned short result;
        for (sum = 0; len > 1; len -= 2)
            sum += *buf++;
        if (len == 1)
            sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        result = ~sum;
        return result;
    }

    int main() {
        int sock;
        struct sockaddr_in dest;
        uint16_t src_port = 12345;
        uint16_t dst_port = 80;
        char src_ip[] = "192.168.182.130";
        char dst_ip[] = "192.168.182.130";

        printf("Before running this program, run the following command to prevent kernel RST:\n");
        printf("sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport %d -j DROP\n", src_port);
        printf("Press Enter to continue...\n");
        getchar();

        // Create raw socket
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) {
            perror("Socket creation failed");
            return 1;
        }

        // Enable IP_HDRINCL (we'll provide the IP header)
        int one = 1;
        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            perror("setsockopt failed");
            return 1;
        }

        // Buffers for packet and pseudo-header
        char packet[sizeof(struct iphdr) + sizeof(struct tcphdr_custom)];
        memset(packet, 0, sizeof(packet));
        struct iphdr *iph = (struct iphdr *)packet;
        struct tcphdr_custom *tcph = (struct tcphdr_custom *)(packet + sizeof(struct iphdr));

        // Destination setup
        dest.sin_family = AF_INET;
        dest.sin_port = htons(dst_port);
        dest.sin_addr.s_addr = inet_addr(dst_ip);

        // Construct IP header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr_custom));
        iph->id = htons(54321);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        iph->saddr = inet_addr(src_ip);
        iph->daddr = dest.sin_addr.s_addr;
        iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

        // Construct TCP header (SYN)
        tcph->source = htons(src_port);
        tcph->dest = htons(dst_port);
        tcph->seq = htonl(0);
        tcph->ack_seq = 0;
        tcph->doff_res = (5 << 4); // Data offset (5 * 4 = 20 bytes)
        tcph->flags = 2; // SYN flag
        tcph->window = htons(65535);
        tcph->check = 0;
        tcph->urg_ptr = 0;

        // Construct pseudo-header for checksum
        struct pseudo_header psh;
        psh.source_address = inet_addr(src_ip);
        psh.dest_address = dest.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr_custom));

        char pseudo_packet[sizeof(struct pseudo_header) + sizeof(struct tcphdr_custom)];
        memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
        memcpy(pseudo_packet + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr_custom));
        tcph->check = checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));

        // Send SYN packet
        if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("Packet send failed");
            close(sock);
            return 1;
        } else {
            printf("Raw TCP SYN packet sent successfully!\n");
        }

        // Receive SYN-ACK by filtering packets
        struct iphdr *recv_iph;
        struct tcphdr_custom *recv_tcph;
        int syn_ack_received = 0;
        uint32_t received_seq = 0;

        printf("Waiting for SYN-ACK response...\n");

        char buffer[4096];
        int bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (bytes_received < 0) {
            perror("Failed to receive packet");
            close(sock);
            return 1;
        }

        recv_iph = (struct iphdr *)buffer;
        int ip_header_len = recv_iph->ihl * 4;

        // Check if it's a TCP packet
        if (recv_iph->protocol == IPPROTO_TCP) {
            recv_tcph = (struct tcphdr_custom *)(buffer + ip_header_len);
            if ((recv_tcph->flags & 0x12) == 0x12) { // SYN+ACK flags
                received_seq = ntohl(recv_tcph->seq);
                printf("SYN-ACK received! Seq: %u\n", received_seq);
                syn_ack_received = 1;
            }
        }

        if (!syn_ack_received) {
            printf("No SYN-ACK received. Exiting.\n");
            close(sock);
            return 1;
        }

        // Add a delay before sending the ACK
        printf("Waiting 1 second before sending ACK...\n");
        sleep(1);

        // Send ACK
        struct pseudo_header psh_ack;
        psh_ack.source_address = inet_addr(src_ip);
        psh_ack.dest_address = inet_addr(dst_ip);
        psh_ack.placeholder = 0;
        psh_ack.protocol = IPPROTO_TCP;
        psh_ack.tcp_length = htons(sizeof(struct tcphdr_custom));

        memset(packet, 0, sizeof(packet));
        iph = (struct iphdr *)packet;
        tcph = (struct tcphdr_custom *)(packet + sizeof(struct iphdr));

        iph->ihl = 5;
        iph->version = 4;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr_custom));
        iph->protocol = IPPROTO_TCP;
        iph->saddr = inet_addr(src_ip);
        iph->daddr = inet_addr(dst_ip);
        iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

        tcph->source = htons(src_port);
        tcph->dest = htons(dst_port);
        tcph->seq = htonl(1);  // Sequence number for the ACK
        tcph->ack_seq = htonl(received_seq + 1);  // Acknowledge SYN-ACK
        tcph->doff_res = (5 << 4);
        tcph->flags = 16; // ACK flag

        memcpy(pseudo_packet, &psh_ack, sizeof(struct pseudo_header));
        memcpy(pseudo_packet + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr_custom));
        tcph->check = checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));

        printf("Sending ACK: seq=%u, ack_seq=%u\n", ntohl(tcph->seq), ntohl(tcph->ack_seq));
        if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("ACK send failed");
            close(sock);
            return 1;
        } else {
            printf("ACK sent successfully!\n");
        }

        close(sock);
        return 0;
    }