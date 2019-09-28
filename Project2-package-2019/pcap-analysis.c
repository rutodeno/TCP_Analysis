///////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////
//  CIS 549: Wireless Mobile Communications
//  Project #2
///////////////////////////////////////////
//
// Detailed information is available at the link below
//    https://wiki.wireshark.org/Development/LibpcapFileFormat
//
// Modify TCPDUMP file
// TCPDUMP file format is
//
// Global Header < -- The pcap file contains this structure at the beginning.
//
// struct pcap_file_header {
//	unsigned int magic;            4 bytes	//	magic number
//	unsigned short version_major;  2 bytes	//	major version number
//	unsigned short version_minor;  2 bytes	// 	minor version number
//	unsigned int thiszone;         4 bytes	//	GMT to local correction
//	unsigned int sigfigs;          4 bytes	//	accuracy of timestamps
//	unsigned int snaplen;          4 bytes	//	max length of captured packets, in octets
//	unsigned int linktype;         4 bytes	//	data link type
//	};
//
//
// And then One packet per line in the pcap file
//
// Record (Packet) Header
//
// struct pcap_pkthdr{
//	unsigned int time_sec;            4 bytes	//	timestamp seconds
//	unsigned int time_usec;           4 bytes	//	timestamp microseconds
//	unsigned int captured_len;        4 bytes	//	number of octets of packet saved in file
//	unsigned int off_wire_pkt_length; 4 bytes	//	actual length of packet
//	};
//
// Wireshark displays following information only in the Frame View
// struct captured_packet { 	Total size of this structure is same as captured_len above.
//    source MAC address                 6 bytes
//    Destination MAC address            6 bytes
//    Packet type (IP packet = 8)       2 bytes
//    IP header length(if pkt type is IP)1 bytes
//     ........
//
// REPEAT "pacp_pkthdr" and "captured_packet" structures until the end of the captured file.
//
////////////////////////////////////////////////////////////////////////////////////////////////

#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <math.h>

#define TCP_TYPE_NUM 6
#define LEFT 0
#define RIGHT 1
#define YES 1
#define NO 0

#define MAX_TCP_SESSION_CONNECTION_STORAGE 100

/*Packet Information Array Location */
#define IP_HDR_LEN_LOC 14 /*IP Packet header Length */
#define TCP_TYPE_LOC 23 /*TCP packet type */
#define TCP_SRC_PORT 34 /*Two bytes */
#define TCP_DST_PORT 36 /*Two bytes */
#define SEQ_NUM 38 /*4 Bytes */
#define ACK_NUM 42 /*4 Bytes */
#define IP_ADDR_START_LOC_VLAN_TYPE 30
#define IP_ADDR_START_LOC_IP_TYPE 26
#define IP_PKT_SIZE_LOC_VLAN_TYPE 20 // 2 bytes from this location
#define IP_PKT_SIZE_LOC_IP_TYPE 16 // 2 bytes from this location

// EtherType value
// 0x0800 : IPv4 datagram.
// 0x0806 : ARP frame
// 0x8100 : IEEE 802.1Q frame
// 0x86DD : IPv6 frame
#define ETHER_PROTOCOL_TYPE_LOC 12 // 14 bytes for enternet frame
#define IP_PAYLOAD_TYPE_LOC 23 /*ICMP type 1 Byte  and value is 0X01 */
#define ICMP_TYPE_LOC 34 /*1 byte */

/*packet information */
#define IP_PAYLOAD_ICMP 1
#define ICMP_REQUEST 8
#define ICMP_REPLY 0
#define VLAN_TYPE 129 /*HEX=81 00*/
#define IP_TYPE 8 /*packet type */
#define NUM_PKT 1000 /*number of packets in a tcpdump file */
#define MAX_PKT_LEN 1700


#if defined(_WIN32)
typedef unsigned int u_int;
#endif

unsigned int pkt_header[NUM_PKT][4];
unsigned char one_pkt[NUM_PKT][MAX_PKT_LEN];



unsigned int bits_to_ui(char* x, int byte_count, int order)
/*********************************************/
/* Convert bits to unsigned int  */
/*********************************************/
{
    unsigned int displayMask = 1;
    int i, j, location = 0;
    unsigned int result = 0;

    if (order == 0) {
        for (j = byte_count - 1; j >= 0; j--) {
            for (i = 1; i <= 8; i++) {
                if (x[j] & displayMask) {
                    result = result + pow(2, location);
                    //printf("1");
                }
                else {
                    //printf("0");
                }

                location++;
                x[j] >>= 1;
            }
        }

        //printf("\n");
    }
    else {
        for (j = 0; j < byte_count; j++) {
            for (i = 1; i <= 8; i++) {
                if (x[j] & displayMask)
                    result = result + pow(2, location);
                location++;
                x[j] >>= 1;
            }
        }
    }

    return result;
}

void ping_response_time_finder(char* in_filename)
{
    FILE* fd;
    unsigned int file_header[6], pkt_header[NUM_PKT][4], captured_len;
    unsigned char one_pkt[NUM_PKT][MAX_PKT_LEN];
    int k = 0;
    double start_time, end_time;
    int looking_for_start;

    fd = fopen(in_filename, "rb");
    if (fd < 0) {
        perror("Unable to open input file");
        exit(1);
    }

    if (fread(file_header, sizeof(unsigned int), 6, fd) == 0) {
        perror("File header Error");
        exit(1);
    }

    looking_for_start = YES;

    while (!feof(fd)) {
        for (k = 0; k < MAX_PKT_LEN; k++)
            one_pkt[0][k] = '\0';

        fread(pkt_header[0], sizeof(unsigned int), 4, fd);
        captured_len = pkt_header[0][2];
        if (captured_len == 0) {
            // do nothing
        }
        else {
            if (looking_for_start == YES) {
                fread(&one_pkt[0][0], sizeof(unsigned char), captured_len, fd);
                start_time = (double)pkt_header[0][0] + (((double)pkt_header[0][1]) / 1000000);

                if ((unsigned int)one_pkt[0][IP_PAYLOAD_TYPE_LOC] == IP_PAYLOAD_ICMP && (unsigned int)one_pkt[0][ICMP_TYPE_LOC] == ICMP_REQUEST) {
                    looking_for_start = NO;
                }
            }
            else {
                fread(&one_pkt[0][0], sizeof(unsigned char), captured_len, fd);
                end_time = (double)pkt_header[0][0] + (((double)pkt_header[0][1]) / 1000000);

                if ((unsigned int)one_pkt[0][IP_PAYLOAD_TYPE_LOC] == IP_PAYLOAD_ICMP && (unsigned int)one_pkt[0][ICMP_TYPE_LOC] == ICMP_REPLY) {
                    looking_for_start = YES;

                    printf("%d.%d.%d.%d %d %f\n", (unsigned int)one_pkt[0][26], (unsigned int)one_pkt[0][27],
                        (unsigned int)one_pkt[0][28], (unsigned int)one_pkt[0][29], captured_len, end_time - start_time);
                }
            }
        }
    }

    fclose(fd);

} /*end func */

void fix_frame_len(char* in_filename, char* output_filename)
{
    FILE *fd_in, *fd_out;
    unsigned int file_header[6], pkt_header[NUM_PKT][4], captured_len;
    unsigned char one_pkt[NUM_PKT][MAX_PKT_LEN];
    fd_in = fopen(in_filename, "rb");
    if (fd_in < 0) {
        perror("Unable to open input file");
        exit(1);
    }

    fd_out = fopen(output_filename, "wb");
    if (fd_out < 0) {
        perror("Unable to open output file");
        exit(1);
    }

    if (fread(file_header, sizeof(unsigned int), 6, fd_in) == 0) {
        perror("File header Error");
        exit(1);
    }

    fwrite(file_header, sizeof(unsigned int), 6, fd_out);

    fread(pkt_header[0], sizeof(unsigned int), 4, fd_in);
    captured_len = pkt_header[0][2];

    fread(&one_pkt[0][0], sizeof(unsigned char), captured_len, fd_in);
    while (!feof(fd_in)) {
        fread(pkt_header[0], sizeof(unsigned int), 4, fd_in);
        captured_len = pkt_header[0][2];

        if (captured_len > 0) {
            fread(&one_pkt[0][0], sizeof(unsigned char), captured_len, fd_in);
            if ((unsigned int)one_pkt[0][ETHER_PROTOCOL_TYPE_LOC] == 0x08) // 0x0800 : IPv4 datagram.
                pkt_header[0][3] = ((unsigned int)one_pkt[0][IP_PKT_SIZE_LOC_IP_TYPE] << 8) + (unsigned int)one_pkt[0][IP_PKT_SIZE_LOC_IP_TYPE + 1] + 14;
            else if ((unsigned int)one_pkt[0][ETHER_PROTOCOL_TYPE_LOC] == 0x81) // 0x8100 : IEEE 802.1Q frame
                pkt_header[0][3] = ((unsigned int)one_pkt[0][IP_PKT_SIZE_LOC_IP_TYPE + 4] << 8) + (unsigned int)one_pkt[0][IP_PKT_SIZE_LOC_IP_TYPE + 5] + 18;

            if (!feof(fd_in)) {
                fwrite(pkt_header[0], sizeof(unsigned int), 4, fd_out);
                fwrite(one_pkt[0], sizeof(unsigned char), captured_len, fd_out);
            }
        }
    }

    fclose(fd_in);
    fclose(fd_out);
}

void ip_address_change(char* in_filename, char* output_filename)
{
    FILE *fd_in, *fd_out;
    unsigned int file_header[6], pkt_header[NUM_PKT][4], captured_len;
    unsigned char one_pkt[NUM_PKT][MAX_PKT_LEN];
    unsigned int src_ip_1st_digit, src_ip_2nd_digit, src_ip_3rd_digit, src_ip_4th_digit;
    unsigned int dst_ip_1st_digit, dst_ip_2nd_digit, dst_ip_3rd_digit, dst_ip_4th_digit;
    unsigned int src_port_num, dst_port_num;
    unsigned int seq_n = 0, ack_n = 0;

    fd_in = fopen(in_filename, "rb");
    if (fd_in < 0) {
        perror("Unable to open input file");
        exit(1);
    }

    fd_out = fopen(output_filename, "wb");
    if (fd_out < 0) {
        perror("Unable to open output file");
        exit(1);
    }

    if (fread(file_header, sizeof(unsigned int), 6, fd_in) == 0) {
        perror("File header Error");
        exit(1);
    }

    fwrite(file_header, sizeof(unsigned int), 6, fd_out);
    fread(pkt_header[0], sizeof(unsigned int), 4, fd_in);
    captured_len = pkt_header[0][2];

    fread(&one_pkt[0][0], sizeof(unsigned char), captured_len, fd_in);

    src_ip_1st_digit = (unsigned int)one_pkt[0][26];
    src_ip_2nd_digit = (unsigned int)one_pkt[0][27];
    src_ip_3rd_digit = (unsigned int)one_pkt[0][28];
    src_ip_4th_digit = (unsigned int)one_pkt[0][29];
    dst_ip_1st_digit = (unsigned int)one_pkt[0][30];
    dst_ip_2nd_digit = (unsigned int)one_pkt[0][31];
    dst_ip_3rd_digit = (unsigned int)one_pkt[0][32];
    dst_ip_4th_digit = (unsigned int)one_pkt[0][33];

    if (dst_ip_1st_digit == 192 && dst_ip_2nd_digit == 11 && dst_ip_3rd_digit == 68 && dst_ip_4th_digit == 196) {
        one_pkt[0][30] = 192;
        one_pkt[0][31] = 11;
        one_pkt[0][32] = 68;
        one_pkt[0][33] = 1;
    }

    if (src_ip_1st_digit == 192 && src_ip_2nd_digit == 11 && src_ip_3rd_digit == 68 && src_ip_4th_digit == 196) {
        one_pkt[0][26] = 192;
        one_pkt[0][27] = 11;
        one_pkt[0][28] = 68;
        one_pkt[0][29] = 1;
    }

    while (!feof(fd_in)) {
        fread(pkt_header[0], sizeof(unsigned int), 4, fd_in);
        captured_len = pkt_header[0][2];

        fread(&one_pkt[0][0], sizeof(unsigned char), captured_len, fd_in);

        src_ip_1st_digit = (unsigned int)one_pkt[0][26];
        src_ip_2nd_digit = (unsigned int)one_pkt[0][27];
        src_ip_3rd_digit = (unsigned int)one_pkt[0][28];
        src_ip_4th_digit = (unsigned int)one_pkt[0][29];
        dst_ip_1st_digit = (unsigned int)one_pkt[0][30];
        dst_ip_2nd_digit = (unsigned int)one_pkt[0][31];
        dst_ip_3rd_digit = (unsigned int)one_pkt[0][32];
        dst_ip_4th_digit = (unsigned int)one_pkt[0][33];

        if (dst_ip_1st_digit == 192 && dst_ip_2nd_digit == 11 && dst_ip_3rd_digit == 68 && dst_ip_4th_digit == 196) {
            one_pkt[0][30] = 192;
            one_pkt[0][31] = 11;
            one_pkt[0][32] = 68;
            one_pkt[0][33] = 1;
        }

        if (src_ip_1st_digit == 192 && src_ip_2nd_digit == 11 && src_ip_3rd_digit == 68 && src_ip_4th_digit == 196) {
            one_pkt[0][26] = 192;
            one_pkt[0][27] = 11;
            one_pkt[0][28] = 68;
            one_pkt[0][29] = 1;
        }

        if (!feof(fd_in)) {
            fwrite(pkt_header[0], sizeof(unsigned int), 4, fd_out);
            fwrite(one_pkt[0], sizeof(unsigned char), captured_len, fd_out);
        }
    }

    fclose(fd_in);
    fclose(fd_out);
}



void tcp_analysis(char *in_filename, char *out_filename)
{
    //
    // Problem 2:
    //
	printf("You need to add your code here for Problem 2\n");
	printf("You may add more supporting functions if needed, but keep this function name unmodified.\n");


	///// Instruction //////
	// This is just for you to understand the framework.
	// You can do anyway you would like to program as long as keep this function name same
	////////////////////////
	//
	// When you create an outputfile, write following two lines first and then start writing each TCP session informatin per line.
	// TCP_session_count, serverIP, clientIP, serverPort, clientPort, num_of_packetSent(server->client), TotalIPtrafficBytesSent(server->client), TotaluserTrafficBytesSent(server->client), sessionDuration, bps_IPlayerThroughput(server->client), bps_Goodput(server->client)
	// =========================================================================================================================

	///////////////////////
	// open the input file
	// open the output file

    FILE *fd_in, *fd_out;
    unsigned int fileheader[6], pkt_header[NUM_PKT][4], captured_len;
	// read file_header from the input file
	// copy the file header in to the output file

    

    /*

	while (!feof(fd_in))
	{
		// read one packet header
		// extract capture_length info
		// read one packet

		if (is this IP packet ?)
		{
			if (is this TCP packet ?)
			{
				if (is this TCP SYN packet ?)
				{
					// this is starting of TCP sessionDuration
					// So, record
					// session_start_time = packet capture time
					// source IP, destination IP, src_port, dst_port
					// you need to keep track of this session until TCP FIN packet for this TCP session
					// To identify TCP session you need to check the TCP IP addresses and port numbers
					// how to find source and destination port number? Here are two ways of doint it. You may use one of these or use your own way as well.
					/////////////////////////////////
					// method 1:
					//src_port_num = (unsigned int)one_pkt[0][TCP_SRC_PORT];
					//src_port_num = src_port_num << 8;
					//src_port_num += (unsigned int)one_pkt[0][TCP_SRC_PORT+1];
					// dst_port_num = (unsigned int)one_pkt[0][TCP_DST_PORT];
					// dst_port_num = dst_port_num << 8;
					// dst_port_num += (unsigned int)one_pkt[0][TCP_DST_PORT+1];
					/////////////////////////////////
					// Method 2:
					// src_port_num = bits_to_ui(memcpy(src_port_num_char,&one_pkt[0][TCP_SRC_PORT],2),2,0);
					// dst_port_num = bits_to_ui(memcpy(dst_port_num_char,&one_pkt[0][TCP_DST_PORT],2),2,0);
					/////////////////////////////////

				}
				else if (is this TCP FIN packet ?)
				{
					// This is the end of TCP session
					// So, record
					// session_end_time = Packet capture time
					// You may calculate output information for this TCP connection and write in to the output file here OR you may do it after all packets are analyzed.
					// You may record all TCP connection information in an array for later analysis
					// and write in to a file at the end of the program

					// Now if you found the TCP SYN packet and FIN packet that belongs to the same TCP session, then you can calculate the TCP session duration
					// TCP sessin duration =TCP FIN packet capture time - TCP SYN packet capture time.
					// Careful. this TCP SYN and FIN packets are not just any SYN or FIN packet. These should be indicating the same TCP session.

				}
				else
				{
					// this is TCP data packet
					// summing up the total captured byte size,
					// calculate user data size and summing up until TCP session finishes
					//
					// TotalIPtrafficBytesSent includes all protocol headers and user data,
					// and TotaluserTrafficBytesSent only counts the user data without any protocol header.
					// To get TotaluserTrafficBytesSent, you may add all TCP payload size in a single TCP session.

				}
			}
			else
			{
				// this is not TCP packet so ignore
			}
		}
		else
		{
			// this is not IP packet, so ignore
		}
	}	// end of WHILE (keep reading packets until the end of the file

	// close both file here
    */
}




void tcp_port_change(char *in_filename, char *out_filename)
{
    //
    /*
        This function modifies the port number for each TCP session 
    */
    //

	FILE *fd_in , *fd_out;
    unsigned int new_port_number = 4999;
	unsigned int file_header[6], pkt_header[NUM_PKT][4], captured_len;
    unsigned char one_pkt[NUM_PKT][MAX_PKT_LEN];
    unsigned int src_ip_1st_digit, src_ip_2nd_digit, src_ip_3rd_digit, src_ip_4th_digit;
    unsigned int src_port_num;
    unsigned int seq_n = 0, ack_n = 0;
    unsigned int protocol_used = pkt_header[0][IP_PKT_SIZE_LOC_IP_TYPE];

    fd_in = fopen(in_filename, "rb");
    if (fd_in < 0) {
        perror("Unable to open input file");
        exit(1);
    }

    fd_out = fopen(out_filename, "wb");
    if (fd_out < 0) {
        perror("Unable to open output file");
        exit(1);
    }

    if(fread(file_header, sizeof(unsigned int), 6, fd_in) == 0) {
        perror("File header Error");
        exit(1);
    }

    fwrite(file_header, sizeof(unsigned int), 6, fd_out);
    fread(pkt_header[0], sizeof(unsigned int), 4, fd_in);
	captured_len = pkt_header[0][2];

    fread(&one_pkt[0][0], sizeof(unsigned char), captured_len, fd_in);

    unsigned int tempArray[2] = {0};
    int i = 0;
    //unsigned int checker = 0;

    while (!feof(fd_in)) {
        fread(pkt_header[0], sizeof(unsigned int), 4, fd_in);
        captured_len = pkt_header[0][2];

        fread(&one_pkt[0][0], sizeof(unsigned char), captured_len, fd_in);
         // print the source port number
         // then change it to 5000
        

        if ((unsigned int)one_pkt[0][ETHER_PROTOCOL_TYPE_LOC] == 0x08) { // 0x0800 : IPv4 datagram.

            src_ip_1st_digit = (unsigned int)one_pkt[0][26];
            src_ip_2nd_digit = (unsigned int)one_pkt[0][27];
            src_ip_3rd_digit = (unsigned int)one_pkt[0][28];
            src_ip_4th_digit = (unsigned int)one_pkt[0][29];

            if ((unsigned int)one_pkt[0][TCP_TYPE_LOC] == 6 && src_ip_1st_digit == 192 && src_ip_2nd_digit == 11 && src_ip_3rd_digit == 68 && src_ip_4th_digit == 196) { // check whether its TCP
                src_port_num = (unsigned int)one_pkt[0][TCP_SRC_PORT];
                src_port_num = src_port_num << 8;
                src_port_num += (unsigned int)one_pkt[0][TCP_SRC_PORT + 1];

                tempArray[i] = src_port_num;

                // only looking for unique sessions
                if (tempArray[0] != tempArray[1]) {
                    new_port_number++;
                } 

                unsigned int firstBits = new_port_number >> 8;
                unsigned int lastBits = new_port_number & 0XFF;
                firstBits << 8;
                one_pkt[0][TCP_SRC_PORT] = firstBits ;
                one_pkt[0][TCP_SRC_PORT+1] = lastBits;

                //checker = (unsigned int)one_pkt[0][TCP_SRC_PORT];
                //checker = checker << 8;
                //checker += (unsigned int)one_pkt[0][TCP_SRC_PORT + 1];
                
                //printf(" %d ", ( checker ));

                i++;
                if (i > 1) 
                    i = 0;

                if(!feof(fd_in)) {
                    fwrite(pkt_header[0], sizeof(unsigned int), 4, fd_out);
                    fwrite(one_pkt[0], sizeof(unsigned char), captured_len, fd_out);
                }            
            }
        }
    }if(!feof(fd_in)) {
                    fwrite(pkt_header[0], sizeof(unsigned int), 4, fd_out);
                    fwrite(one_pkt[0], sizeof(unsigned char), captured_len, fd_out);
                }

    fclose(fd_in);
    fclose(fd_out);
	//printf("You need to add your code her for Problem 1\n");
	//printf("You may add more supporting functions if needed, but keep this function name unmodified.\n");
}

int main(int argc, char* argv[])
{
    printf("Selected Option: %s\n", argv[1]);

    if (strcmp(argv[1], "ping-delay") == 0) {
        ping_response_time_finder(argv[2]);
    }
    else if (strcmp(argv[1], "fix-length") == 0) {
        fix_frame_len(argv[2], argv[3]);
    }
     else if (strcmp(argv[1], "ip-address-change") == 0) {
        ip_address_change(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "tcp-port-change") == 0) {
        // call your function
        tcp_port_change(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "tcp-analysis") == 0) {
        // call your function
        tcp_analysis(argv[2], argv[3]);
    }
    else {
        printf("Four options are available.\n");
        printf("===== Four command line format description =======\n");
        printf("1:  ./pcap-analysis ping-delay input-trace-filename\n");
        printf("2:  ./pcap-analysis fix-length input-trace-filename output-trace-filename\n");
        printf("3:  ./pcap-analysis ip-address-change input-trace-filename output-trace-filename\n");
        printf("4:  ./pcap-analysis tcp-port-change  input-trace-filename output-trace-filename\n");
        printf("5:  ./pcap-analysis tcp-analysis  input-trace-filename  output-filename\n");
        printf("===== END =======\n");
    }
} /*end prog */
