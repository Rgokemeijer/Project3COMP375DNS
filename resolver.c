#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

#include "dns.h"

#define MAX_QUERY_SIZE 1024
#define MAX_RESPONSE_SIZE 4096

struct flag_values{
	bool response;
	uint8_t opcode;
	bool authoritative;
	bool truncated;
	bool recursion_desired;
	bool recursion_available;
	bool reserved;
	bool answer_authenticated;
	bool non_authenticated_data;
	uint8_t reply_code;
};

struct query{
	char name[173]; //DO NOT CHANGE!!!
	uint8_t type, class;
};

struct answer{
	char name[138]; //DO NOT CHANGE!!!
	uint8_t type, class, data_length;
	uint32_t ttl;
	uint8_t extra_data[123]; //NO!!! ugh fine
};

struct query get_query_data(uint8_t response[], int *offset)
{
	struct query query_data;
	*offset += getStringFromDNS(response, response + *offset, query_data.name);
	query_data.type = ((uint16_t)response[*offset] << 8) + response[*offset + 1];
	query_data.class = ((uint16_t)response[*offset+2] << 8) + response[*offset + 3];
	*offset += 4;
	// printf("Read Query offset now %d", *offset);
	return query_data;
}

struct answer get_answer_data(uint8_t response[], int *offset)
{
	// printf("Read answe offset now %d", *offset);
	struct answer answer_data;
	*offset += getStringFromDNS(response, response + *offset, answer_data.name);
	// printf("%s, %d\n", answer_data.name, answer_data.name);
	answer_data.type = ((uint16_t)response[*offset] << 8) + response[*offset + 1];
	answer_data.class = ((uint16_t)response[*offset+2] << 8) + response[*offset + 3];
	answer_data.ttl = ((uint32_t)response[*offset + 4] << 24) + ((uint32_t)response[*offset + 5] << 16);
	answer_data.ttl += ((uint16_t)response[*offset + 6] << 8) + response[*offset + 7];
	answer_data.data_length = ((uint16_t)response[*offset+8] << 8) + response[*offset + 9];
	for(int i = 0; i < answer_data.data_length; i++){
		answer_data.extra_data[i] = response[*offset + i + 10];
	}	
	*offset += 10 + answer_data.data_length;
	// printf("Read answer finished offset now %d", *offset);
	// printf("\n%s", answer_data.name);
	// printf("\n%d", answer_data.type);
	// printf("\n%d", answer_data.class);
	// printf("\n%d", answer_data.ttl);
	// printf("\n%d", answer_data.data_length);
	// for(int i = 0; i < 4; i++){
	// 	printf("\n%u", answer_data.extra_data[i]);
	// }
	// printf("\n%d", answer_data.type);
	// printf("\n%d", response);
	return answer_data;
}

struct flag_values get_flag_values(uint16_t flags)
{
	struct flag_values flag_vals; 
	flag_vals.reply_code = flags & 15;
	flags = flags >> 4;
	flag_vals.non_authenticated_data = flags & 1;
	flags = flags >> 1;
	flag_vals.answer_authenticated = flags & 1;
	flags = flags >> 1;
	flag_vals.reserved = flags & 1;
	flags = flags >> 1;
	flag_vals.recursion_available = flags & 1;
	flags = flags >> 1;
	flag_vals.recursion_desired = flags & 1;
	flags = flags >> 1;
	flag_vals.truncated = flags & 1;
	flags = flags >> 1;
	flag_vals.authoritative = flags & 1;
	flags = flags >> 1;
	flag_vals.opcode = flags & 15;
	flags = flags >> 4;
	flag_vals.response = flags & 1;
	flags = flags >> 1;
}

void bytes_to_str(uint8_t* bytes, char* addr){
	printf("%u.%u", bytes[0], bytes[1]);
	sprintf(addr, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
	// printf("%s", addr);
	// return addr;
}
// Note: uint8_t* is a pointer to 8 bits of data.

/**
 * Constructs a DNS query for hostname's Type A record.
 *
 * @param query Pointer to memory where query will stored.
 * @param hostname The host we are trying to resolve
 * @return The number of bytes in the constructed query.
 */

int construct_query(uint8_t *query, char *hostname, bool is_mx)
{
	memset(query, 0, MAX_QUERY_SIZE);

	// first part of the query is a fixed size header
	DNSHeader *hdr = (DNSHeader*)query;

	// set ID to 5... you should randomize this!
	hdr->id = htons(5);

	// set header flags to request iterative query
	hdr->flags = htons(0x0000);	

	// 1 question, no answers or other records
	hdr->q_count=htons(1);
	hdr->a_count=htons(0);
	hdr->auth_count=htons(0);
	hdr->other_count=htons(0);

	// We are going to have to wade into pointer arithmetic here since our
	// struct is a fixed size but our queries will be variably sized.

	// add the name
	int query_len = sizeof(DNSHeader); 
	int name_len = convertStringToDNS(hostname,query+query_len);
	query_len += name_len; 
	
	// set the query type to A (i.e. 1)
	if (!is_mx){
		uint16_t *type = (uint16_t*)(query+query_len);
		*type = htons(1);
		query_len+=2;
	}
	else{
		uint16_t *type = (uint16_t*)(query+query_len);
		*type = htons(15);
		query_len+=2;
	}

	// finally the class: INET
	uint16_t *class = (uint16_t*)(query+query_len);
	*class = htons(1);
	query_len += 2;
 
	return query_len;
}

/**
 * Returns a string with the IP address (for an A record) or name of mail
 * server associated with the given hostname.
 *
 * @param hostname The name of the host to resolve.
 * @param is_mx True (1) if requesting the MX record result, False (0) if
 *    requesting the A record.
 *
 * @return A string representation of an IP address (e.g. "192.168.0.1") or
 *   mail server (e.g. "mail.google.com"). If the request could not be
 *   resolved, NULL will be returned.
 */
char* resolve(char *hostname, bool is_mx) {

	if (is_mx == false) {
		printf("Requesting A record for %s\n", hostname);
	}
	else {
		printf("Requesting MX record for %s\n", hostname);
	}

	// create a UDP (i.e. Datagram) socket
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		exit(0);
	}
	// Create a time value structure and set it to five seconds.
	struct timeval tv;
	memset(&tv, 0, sizeof(struct timeval));
	tv.tv_sec = 5;

	/* Tell the OS to use that time value as a time out for operations on
	 * our socket. */
	int res = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv,
			sizeof(struct timeval));

	if (res < 0) {
		perror("setsockopt");
		exit(0);
	}

	// The following is the IP address of USD's local DNS server. It is a
	// placeholder only (i.e. you shouldn't have this hardcoded into your final
	// program).
	in_addr_t nameserver_addr = inet_addr("172.16.7.15");
	
	struct sockaddr_in addr; 	// internet socket address data structure
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53); // port 53 for DNS
	addr.sin_addr.s_addr = nameserver_addr; // destination address (any local for now)

	// uint8_t is a standard, unsigned 8-bit value.
	// You should use that type for all buffers used for sending to and
	// receiving from the DNS server.
	uint8_t query[MAX_QUERY_SIZE]; 
	int query_len=construct_query(query, hostname, is_mx);

	int send_count = sendto(sock, query, query_len, 0,
							(struct sockaddr*)&addr, sizeof(addr));

	if (send_count<0) { 
		perror("Send failed");
		exit(1);
	}

	socklen_t len = sizeof(struct sockaddr_in);

	uint8_t response[MAX_RESPONSE_SIZE];

	/* Blocking calls will now return error (-1) after the timeout period with
	 * errno set to EAGAIN. */
	res = recvfrom(sock, response, MAX_RESPONSE_SIZE, 0, 
					(struct sockaddr *)&addr, &len);

	if (res < 1) {
		if (errno == EAGAIN) {
			printf("Timed out!\n");
		} else {
			perror("recv");
		}
	}

	// TODO: The server's response will be located in the response array for you
	// to further process and extract the needed information.
	// Remember that DNS is a binary protocol: if you try printing out response
	// as a string, it won't work correctly.
	memset(query, 0, MAX_QUERY_SIZE);
	DNSHeader *hdr = (DNSHeader*)query;
	hdr->id = ((uint16_t)response[0] << 8) + response[1];
	hdr->flags = ((uint16_t)response[2] << 8) + response[3];
	hdr->q_count = ((uint16_t)response[4] << 8) + response[5];
	hdr->a_count = ((uint16_t)response[6] << 8) + response[7];
	hdr->auth_count = ((uint16_t)response[8] << 8) + response[9];
	hdr->other_count = ((uint16_t)response[10] << 8) + response[11];

	struct flag_values flag_vals = get_flag_values(hdr->flags);
	int offset = 12;
	struct query queries[hdr->q_count];
	for(int i = 0; i < hdr->q_count; i++){
		queries[i] = get_query_data(response, &offset);
	};
	struct answer answers[hdr->a_count + hdr->auth_count];
	for (int i = 0; i < hdr->a_count + hdr->auth_count; i++){
		// printf("Getting answer\n");
		// printf("%d", response[offset]);
		// printf("%d", response[offset]);
		// printf("%d", response[offset]);
		// printf("%d", response[offset]);
		// printf("%d", response[offset]);

		answers[i] = get_answer_data(response, &offset);
	};

	char *address = malloc(17);
	for(int i = 0; i < 4; i++){
		printf("%u\n", answers[0].extra_data[i]);
	}
	if (is_mx){
		char *server_name = malloc(200);
		getStringFromDNS(response, answers[0].extra_data, server_name); // If mx there is no answer only auth and other
		return server_name;
	}
	
	bytes_to_str(answers[0].extra_data, address);
	return address;
}


int main(int argc, char **argv) {
	if (argc < 2) {
		// TODO: provide a more helpful message on how to use the program
		printf("Invalid program usage for %s!\n", argv[0]);
	}

	char *answer = resolve("catalogs.sandiego.edu", false);

	if (answer != NULL) {
		printf("Answer: %s\n", answer);
	}
	else {
		printf("Could not resolve request.\n");
	}

	return 0;
}
