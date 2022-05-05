/* Authors: Russell Gokemeijer, Jared Fleiter, Tyler Kreider
* Date: 04/04/22
* This project is an implementation of DNS protocol to build an iterative DNS query resolver.
*
*/

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


//defines a struct that will be used to parse the flag
//setion in the header of the response
// This code is not needed
// struct flag_values{
// 	bool response;
// 	uint8_t opcode;
// 	bool authoritative;
// 	bool truncated;
// 	bool recursion_desired;
// 	bool recursion_available;
// 	bool reserved;
// 	bool answer_authenticated;
// 	bool non_authenticated_data;
// 	uint8_t reply_code;
// };

//Stores information that is included in the query
struct query{
	char name[173]; //DO NOT CHANGE!!!
	uint8_t type, class;
};

//stores answer data
struct answer{
	char name[138]; //DO NOT CHANGE!!!
	uint8_t type, class, data_length;
	uint32_t ttl;
	uint8_t extra_data[223]; //NO!!!
};


/**	parses the data we received in the query response
 * 
 *
 * @param response, the entire DNS response
 * @param offset, The location of the start of the query in the dns response
 *
 * @return returns the parsed data put into query_data
 */
struct query get_query_data(uint8_t response[], int *offset)
{
	struct query query_data;
	*offset += getStringFromDNS(response, response + *offset, query_data.name);
	query_data.type = ((uint16_t)response[*offset] << 8) + response[*offset + 1];
	query_data.class = ((uint16_t)response[*offset+2] << 8) + response[*offset + 3];
	*offset += 4;
	return query_data;
}


/**
 * Get Answer data. Takes in a the DNS message
 * and parses it into a answer data struct.
 *
 * @param response, this is the entire DNS message that will be read.
 * @param offset, this is an int to where the start of this response is.
 *
 * @return returns the previously defined struct that holds a response.
 */
struct answer get_answer_data(uint8_t response[], int *offset)
{
	struct answer answer_data;
	*offset += getStringFromDNS(response, response + *offset, answer_data.name);
	answer_data.type = ((uint16_t)response[*offset] << 8) + response[*offset + 1];
	answer_data.class = ((uint16_t)response[*offset+2] << 8) + response[*offset + 3];
	answer_data.ttl = ((uint32_t)response[*offset + 4] << 24) + ((uint32_t)response[*offset + 5] << 16);
	answer_data.ttl += ((uint16_t)response[*offset + 6] << 8) + response[*offset + 7];
	answer_data.data_length = ((uint16_t)response[*offset+8] << 8) + response[*offset + 9];
	for(int i = 0; i < answer_data.data_length; i++){
		answer_data.extra_data[i] = response[*offset + i + 10];
	}	
	*offset += 10 + answer_data.data_length;
	return answer_data;
}

/**
 * Get flag value data. Takes in an integer and pulls out the different bits.
 *
 * @param flags, this is the integer that will be broken into its bits
 *
 * @return returns the previously defined struct that holds all flags.
 */
// This code is not used
// struct flag_values get_flag_values(uint16_t flags)
// {
// 	struct flag_values flag_vals; 
// 	flag_vals.reply_code = flags & 15;
// 	flags = flags >> 4;
// 	flag_vals.non_authenticated_data = flags & 1;
// 	flags = flags >> 1;
// 	flag_vals.answer_authenticated = flags & 1;
// 	flags = flags >> 1;
// 	flag_vals.reserved = flags & 1;
// 	flags = flags >> 1;
// 	flag_vals.recursion_available = flags & 1;
// 	flags = flags >> 1;
// 	flag_vals.recursion_desired = flags & 1;
// 	flags = flags >> 1;
// 	flag_vals.truncated = flags & 1;
// 	flags = flags >> 1;
// 	flag_vals.authoritative = flags & 1;
// 	flags = flags >> 1;
// 	flag_vals.opcode = flags & 15;
// 	flags = flags >> 4;
// 	flag_vals.response = flags & 1;
// 	flags = flags >> 1;
//	return flag_vals;
// }

// previous declerations for functions to be used later
char *send_query(char* root_ip, char* hostname, bool is_mx, int sock, char *query_ans);
char *analyze_request(struct answer *answers, uint8_t *response, int num_answers, char *hostname, bool is_mx, int sock, char *query_ans);

/**
 *converts the byte data into a string form of the IP address.
 *
 * @param bytes the data we want to convert
 * @param addr the address we want to put converted data into 
 *
 * @return: no return
 */
void bytes_to_str(uint8_t* bytes, char* addr){
	sprintf(addr, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
}

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

	// generates a random ID to use
	hdr->id = htons(rand() % 65536);

	// set header flags to request iterative query
	hdr->flags = htons(0x0000);	

	// 1 question, no answers or other records
	hdr->q_count=htons(1);
	hdr->a_count=htons(0);
	hdr->auth_count=htons(0);
	hdr->other_count=htons(0);

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
	// else sends query type to 15 for mx
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

/** Searches for the location in the answers struct with a matching DNS record type
 * 
 *
 * @param answers, the array of answer structs
 * @param type, the type of DNS record to search for
 * @param num_answers, the number of answers in the answers struct
 * @param response, the dns response to be used for string parsing
 *
 * @return returns an int which is the location in answers that has the correct DNS type (ns, cname, mx)
 */
int search_for(struct answer *answers, int type, int num_answers){
	for(int i = 0; i < num_answers; i++){
		if (answers[i].type == type){
			return i;
		}
	}
	return -1;
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
	FILE *root_servers = fopen("root-servers.txt", "r");
	char root_ip[256];
    while (fgets(root_ip, sizeof(root_ip), root_servers)) {
		// trys every root serve
		char *query_ans = malloc(200);
		char* ans = send_query(root_ip, hostname, is_mx, sock, query_ans);
		if (strcmp(ans, "SOA") == 0){
			fclose(root_servers);
			exit(0);
		}
		if (query_ans != NULL){ // If it returns a string that is answer otherwise try next root server
			fclose(root_servers);
			return query_ans;
		}
	
		printf("Could not find response trying next root server.\n");
	}
	fclose(root_servers);
	return NULL;
}

/** 
 * Send Query takes in the query and an IP and sends that query looking for a response. 
 * @param dest_ip, ip we want to send to
 * @param hostname, hostname we are trying to resolve
 * @param is_mx, if it is an mx request or not
 * @param sock, the socket we are connecting to 
 * @return returns 0 for error and 1 for no error
*/

char *send_query(char* dest_ip, char* hostname, bool is_mx, int sock, char *query_ans){
	uint8_t query[MAX_QUERY_SIZE]; 
	int query_len=construct_query(query, hostname, is_mx);
	uint8_t response[MAX_RESPONSE_SIZE];
	in_addr_t nameserver_addr = inet_addr(dest_ip);
	
	struct sockaddr_in addr; 	// internet socket address data structure
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53); // port 53 for DNS
	addr.sin_addr.s_addr = nameserver_addr; // destination address (any local for now)

	// uint8_t is a standard, unsigned 8-bit value.
	// You should use that type for all buffers used for sending to and
	// receiving from the DNS server.
	int send_count = sendto(sock, query, query_len, 0,
							(struct sockaddr*)&addr, sizeof(addr));

	if (send_count<0) { 
		perror("Send failed");
		exit(1);
	}

	socklen_t len = sizeof(struct sockaddr_in);


	/* Blocking calls will now return error (-1) after the timeout period with
	* errno set to EAGAIN. */
	int res = recvfrom(sock, response, MAX_RESPONSE_SIZE, 0, 
					(struct sockaddr *)&addr, &len);

	if (res < 1) {
		if (errno == EAGAIN) {
			printf("Timed out!\n");
		} else {
			perror("recv");
		}
	}
	// The server's response is be located in the response array
	// Below that data is processed and the needed information is extracted.
	memset(query, 0, MAX_QUERY_SIZE);
	DNSHeader *hdr = (DNSHeader*)query;
	hdr->id = ((uint16_t)response[0] << 8) + response[1];
	hdr->flags = ((uint16_t)response[2] << 8) + response[3];
	hdr->q_count = ((uint16_t)response[4] << 8) + response[5];
	hdr->a_count = ((uint16_t)response[6] << 8) + response[7];
	hdr->auth_count = ((uint16_t)response[8] << 8) + response[9];
	hdr->other_count = ((uint16_t)response[10] << 8) + response[11];

	// struct flag_values flag_vals = get_flag_values(hdr->flags);
	int offset = 12; // this offset is initial set to 12 to account for flag values and ID
	// struct query queries[hdr->q_count];
	// The struct does not need to be created but the loop must go through to get the correct offset value
	for(int i = 0; i < hdr->q_count; i++){
		get_query_data(response, &offset);
	};
	int num_answers = hdr->a_count + hdr->auth_count + hdr->other_count;
	struct answer answers[num_answers];
	for (int i = 0; i < num_answers; i++){
		answers[i] = get_answer_data(response, &offset);
	};
	return analyze_request(answers, response, num_answers, hostname, is_mx, sock, query_ans);
}	


/**
 *  Checks what type of response (ns, cname, mx) and then reads data accordingly using 
 * an iterative strategy. Returns the address once the correct request type is found.
 * This function calls itself recursively with new requests.
 *
 * @param answers, the list of structs of all of the answers in the response
 * @param response, The entire DNS response that was received.
 * @param num_answers, number of responses from request
 * @param hostname, the hostname we are trying to resolve
 * @param is_mx, if an mx request or not
 * @param sock, the socket we are connecting to 
 *
 * @return returns a recursive send_query call or an address
 */
char *analyze_request(struct answer *answers, uint8_t *response, int num_answers, char *hostname, bool is_mx, int sock, char* query_ans){
	int type = answers[0].type;
	if (type == 2){ // NS response
		char new_serv[256]; 
		getStringFromDNS(response, answers[0].extra_data, new_serv);
		for (int i = 0; i < num_answers; i++){
			// Checks if the Name Servers IP is given in one of the answers
			if (answers[i].type == 1 && strcmp(answers[i].name, new_serv)){
				char new_addr[17];
				bytes_to_str(answers[i].extra_data, new_addr);
				printf("Received an NS response now querying %s to %s\n", hostname, new_addr);
				return send_query(new_addr, hostname, is_mx, sock, query_ans);
			}
		}
		// We do this because sometimes no matching A responses
		int which_ans = search_for(answers, 1, num_answers);
		if (which_ans > -1){
			char new_addr[17];
			bytes_to_str(answers[which_ans].extra_data, new_addr);
			printf("Received an NS response now querying %s to %s\n", hostname, new_addr);
			return send_query(new_addr, hostname, is_mx, sock, query_ans);
		}
		printf("Received an NS response without a type A response. Sending request to find the NS's IP.\n");
		char *ip = resolve(new_serv, false);
		printf("Found the NS's IP. Now querying %s to %s\n", hostname, ip);
		char stack_ip[17];
		strcpy(stack_ip, ip);
		free(ip);
		return send_query(stack_ip, hostname, is_mx, sock, query_ans);
	}
	else if (type == 1){ //type A
		bytes_to_str(answers[0].extra_data, query_ans);
		return query_ans;
	}

	else if (type == 5){ // CNAME
		char new_name[256];
		getStringFromDNS(response, answers[0].extra_data, new_name);
		printf("Was CNAME actual name: %s\n", new_name);
		free(query_ans);
		return resolve(new_name, is_mx);
	}
	//if mx type
	else if (type == 15){
		// Plus two is to skip the preferences filed of mx type responses
		getStringFromDNS(response, answers[0].extra_data + 2, query_ans);
		return query_ans;
	}
	//if SOA type
	else if (type == 6){ 
		printf("Invalid Hostname.\n");
		free(query_ans);
		return "SOA";
	}
	free(query_ans);
	return NULL;
}

/**
 * This is our main function that will read the command line arguments and calls resolve with 
 *correct corresponding parameters
 *
 * @param argc the number of command line arguments
 * @param argv an array with the command line arguments
 *
 * @return 0 when complete
 */
int main(int argc, char **argv) {
	if (argc < 2) {
		printf("Invalid program usage for %s!\n", argv[0]);
		printf("Include the hostname you would like to resolve as an argument.\nIf you would like to make a MX request make the first parameter -m\n");
		exit(1);
	}
	bool not_mx = strcmp("-m", argv[1]);
	char *answer;

	//command line has "-m" flag
	if (!not_mx) {
		answer = resolve(argv[2], true);
	}
	//command line doesn't have "-m" flag
	else{
		answer = resolve(argv[1], false);
	}
	if (answer != NULL) {
		printf("Answer: %s\n", answer);
	}
	else {
		printf("Could not resolve request.\n");
	}
	free(answer);
	return 0;
}
