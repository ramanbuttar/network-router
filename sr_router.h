/*-----------------------------------------------------------------------------
 * File: sr_router.h 
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H 
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
 
/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0) 
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255 
#define PACKET_DUMP_SIZE 1024 
#define ARP_TTL 5

#define TTL 15 /* ARP Cache entry's max TTL */

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router. 
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   			/* socket to server */
    char user[32]; 			/* user name */
    char host[32]; 			/* host name */ 
    unsigned short topo_id;
    struct sockaddr_in sr_addr; 	/* address to server */
    struct sr_if* if_list; 		/* list of interfaces */
    struct sr_rt* routing_table; 	/* routing table */
    FILE* logfile;
};

/* struct defined for arp table entry */
struct arp_entry
{
	uint8_t		mac_addr[ETHER_ADDR_LEN];	/* Hardware Address (MAC) */
	uint32_t	ip_addr;			/* Protocol Address (IP) */
	time_t		ttl;				/* TTL for entry in ARP Cache */
	struct arp_entry* next;
};

/* struct defined for queued packets waiting for ARP replies */
struct queued_packet
{
    uint8_t		ttl;				/* number of ARP */
    uint32_t            ip;        			/* dest address of outgoing packet */
    uint8_t*            packet;   			/* packet to be sent */
    unsigned int        len;      			/* length of packet */
    char  		interface[ETHER_ADDR_LEN];	/* interface name */
    struct queued_packet* next;     			/* link to next queue element */
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* convert format from host to network */
uint16_t htons(uint16_t val);	/* short */
uint32_t htonl(uint32_t val);	/* long */

/* Debug - Printing Headers */
void printIPAddr(uint32_t ipaddr);
void printMACAddr(unsigned char macaddr[ETHER_ADDR_LEN]);
void printEthernetHeader(struct sr_ethernet_hdr* hdr);
void printARPHeader(struct sr_arphdr* hdr);
void printICMPHeader(struct icmp* hdr);
void printIPHeader(struct ip* hdr);

uint16_t calcChecksum(void *data, uint16_t len);

/* ARP Table methods */
void addARPEntry( uint32_t ipaddr, uint8_t macaddr[ETHER_ADDR_LEN] );
uint8_t* getARPEntry( uint32_t ipaddr );
void printARPTable();

/* Packet Queue methods */
void addPacketToQueue( uint32_t ip, uint8_t* q_packet, unsigned int len, char* interface );
void sendQueuedPackets( struct sr_instance* sr, uint32_t ip );
void resendARPRequests( struct sr_instance* sr );

/* Handle ARP */
void handleARP(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void sendARPRequest( struct sr_instance* sr, uint32_t ip, struct sr_if* interface );
void sendARPReply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);

/* Handle ICMP */
void handleICMP(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void sendICMPmessage(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, uint8_t type, uint8_t code );

/* Handle Packet Forwarding */
void forwardPacket(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);

/* Helper methods */
int isRouterInterface(struct sr_instance* sr, uint32_t ip);
struct sr_if* getInterface(struct sr_instance* sr, uint32_t ip);
char* getGatewayInterface(struct sr_instance* sr);
uint32_t getGateway(struct sr_instance* sr);


/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */

