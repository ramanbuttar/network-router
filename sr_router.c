/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>

#include <string.h>
#include <arpa/inet.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

#define DEBUG_PRINT

#ifdef DEBUG_PRINT
  #define DEBUG(x) x
#else
  #define DEBUG(x)
#endif

uint16_t htons(uint16_t val)
{
	return (val<<8) | (val>>8);
}

uint32_t htonl(uint32_t val)
{
	return (htons(val>>16) | (uint32_t)htons(val&0x0000FFFF)<<16);
}

/* arp cache */
struct arp_entry* table;

/* packet queue */
struct queued_packet* packet_queue;

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* init arp table */

    /* Add initialization code here! */

} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    DEBUG(printf("*** Received packet of length %d -> \n",len);)
  
    struct sr_ethernet_hdr *ethr_hdr = (struct sr_ethernet_hdr *)packet;

    if (htons(ethr_hdr->ether_type) == ETHERTYPE_ARP) {
	/* ARP Packet */
	printf("ARP");
	handleARP(sr, packet, len, interface);
	
    } else if (htons(ethr_hdr->ether_type) == ETHERTYPE_IP) {
	/* IP Packet */
    	printf("IP");
	struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
	
	/* validate checksum */
	uint16_t temp = ip_hdr->ip_sum;

	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = calcChecksum(ip_hdr, sizeof(struct ip));

	/* check checksum of incoming ICMP packet */
	if (temp != ip_hdr->ip_sum) {
		printf("\ndrop sum");
		/* invalid checksum drop packet */
		return;
	}
	
	/* Add valid incoming packet's IP/MAC in ARP Table */
	addARPEntry( ip_hdr->ip_src.s_addr, ethr_hdr->ether_shost );

	
	/* drop packet if ttl is 0 */
	if( ip_hdr->ip_ttl <= 1 ) {
		/* send ICMP TTL expired */		

		sendICMPmessage(sr, packet, len, interface, 11, 0 );
		printf("\ndrop ttl send ICMP Expired");
		/* drop stale packet */
		return;
	}

	/* Packet directed to one of Router's interfaces */
	if ( !isRouterInterface(sr, ip_hdr->ip_dst.s_addr) ) {
		/*  forward packet if not for us!  */

		/* decrement ttl */
		ip_hdr->ip_ttl -= 1;
		
		/* update checksum */
		ip_hdr->ip_sum = 0;
		ip_hdr->ip_sum = calcChecksum(ip_hdr, sizeof(struct ip));

		forwardPacket(sr, packet, len, interface);

	} else if (ip_hdr->ip_p == IPPROTO_ICMP) {
		/* ICMP */
	    	printf(" ICMP");
		handleICMP(sr, packet, len, interface);
	} else if (ip_hdr->ip_p == IPPROTO_TCP) {
	    	printf(" TCP");
		sendICMPmessage(sr, packet, len, interface, 3, 3 );
	} else if (ip_hdr->ip_p == IPPROTO_UDP) {
	    	printf(" UDP");
		sendICMPmessage(sr, packet, len, interface, 3, 3 );
	} else {
	   	printf(" IP");
	}

    } else {
	/* Packet Type Undefined */
	printf("NONE");
    }
	resendARPRequests( sr );

}/* end sr_ForwardPacket */


void printIPAddr(uint32_t ipaddr) 
{
	printf("%d.%d.%d.%d",
		((unsigned char*)&ipaddr)[0],
		((unsigned char*)&ipaddr)[1],
		((unsigned char*)&ipaddr)[2],
		((unsigned char*)&ipaddr)[3]);
}

void printMACAddr(unsigned char macaddr[ETHER_ADDR_LEN]) 
{
	printf("%x:%x:%x:%x:%x:%x",
		macaddr[0],
		macaddr[1],
		macaddr[2],
		macaddr[3],
		macaddr[4],
		macaddr[5]);
}

void printEthernetHeader(struct sr_ethernet_hdr* hdr)
{
	printf("\n__Ethernet HEADER__");

	printf("\nEthernet Source MAC: ");
	printMACAddr(hdr->ether_shost);

	printf("\nEthernet Dest MAC: ");
	printMACAddr(hdr->ether_dhost);	

	printf("\nEthernet Type: %d", hdr->ether_type);	
	printf("\n");
}

void printARPHeader(struct sr_arphdr* hdr)
{		
	printf("\n__ARP HEADER__");

	printf("\nSource IP: ");
	printIPAddr(hdr->ar_sip);

	printf("\nSource MAC: ");
	printMACAddr(hdr->ar_sha);

	printf("\nDest IP: ");
	printIPAddr(hdr->ar_tip);

	printf("\nDest MAC: ");
	printMACAddr(hdr->ar_tha);

	printf("\nHRD: %u", hdr->ar_hrd);	/* format of hardware address   */
	printf("\nPRO: %u", hdr->ar_pro);   	/* format of protocol address   */
	printf("\nHLN: %u", hdr->ar_hln);	/* length of hardware address   */
	printf("\nPLN: %u", hdr->ar_pln);	/* length of protocol address   */
	printf("\nOPC: %u", hdr->ar_op);	
	printf("\n");
}

void printICMPHeader(struct icmp* hdr)
{		
	printf("\n__ICMP HEADER__");	
	printf("\nICMP Type: %d", hdr->icmp_type);
	printf("\nICMP Code: %d", hdr->icmp_code);
	printf("\nICMP Checksum: %d", htons(hdr->icmp_sum));
	printf("\nICMP ID: %d", htons(hdr->icmp_id));
	printf("\nICMP Sequence: %d", htons(hdr->icmp_seq));
	printf("\n");
}

void printIPHeader(struct ip* hdr)
{		
	printf("\n__IP HEADER__");
	printf("\nHeader Length: %u", hdr->ip_hl);	
	printf("\nHeader Version: %u", hdr->ip_v);
	printf("\nType of Service: %u", hdr->ip_tos);
	printf("\nLength: %u", ntohs(hdr->ip_len));
	printf("\nID: %u", hdr->ip_id);
	printf("\nOffset: %u", hdr->ip_off);
	printf("\nTTL: %u", hdr->ip_ttl);
	printf("\nChecksum: %u", hdr->ip_sum);
	printf("\nSource IP: %s", inet_ntoa(hdr->ip_src));
	printf("\nDest IP: %s", inet_ntoa(hdr->ip_dst));
	printf("\n");
}

uint16_t calcChecksum(void *data, uint16_t len)
{
     register uint32_t sum = 0;
 
     for (;;) {
         if (len < 2)
             break;
         sum += *((uint16_t *)data);
         data+=2;
         len -= 2;
     }
     if (len)
         sum += *(uint8_t *) data;
 
     while ((len = (uint16_t) (sum >> 16)) != 0)
         sum = (uint16_t) sum + len;
 
     return ~( (uint16_t) sum );
}

int isRouterInterface(struct sr_instance* sr, uint32_t ip)
{
	struct sr_if* cp = sr->if_list;
	while (cp != NULL){
		if (cp->ip == ip) {
			return 1;		
		}
		cp = cp->next;
	}
	return 0;
}

struct sr_if* getInterface(struct sr_instance* sr, uint32_t ip)
{
	struct sr_rt* cp = sr->routing_table;
	while (cp != NULL){
		if (cp->dest.s_addr == ip) {
			return sr_get_interface(sr, cp->interface);		
		}
		cp = cp->next;
	}
	return NULL;
}

/* add ARP entry to table */
void addARPEntry( uint32_t ipaddr, uint8_t macaddr[ETHER_ADDR_LEN] )
{
	/* first entry being added to table */
	struct arp_entry* pp = table;
	struct arp_entry* cp = table;
				
	while( cp != NULL )
	{
		if( cp->ip_addr == ipaddr )
		{
			/* copy MAC addr just incase it has changed */
			memcpy( cp->mac_addr, macaddr, sizeof(cp->mac_addr) );
			/* reset ttl */
			cp->ttl = time(NULL) + TTL;
			/* entry found, we are finished */
			return;
		}
		pp = cp;
		cp = cp->next;
	}

	/* create a new arp_entry for ip address */
	cp = malloc( sizeof(struct arp_entry) );

	cp->ip_addr = ipaddr;
	memcpy( cp->mac_addr, macaddr, sizeof(cp->mac_addr) );
	cp->ttl = time(NULL) + TTL;
	cp->next = NULL;

	/* first entry in table */
	if( table == NULL )
	{
		table = cp;
	}
	/* add to end of table */
	else
	{
		pp->next = cp;
	}
}

/* ARP entries are invalidated after TTL milloseconds
 * this method removes all out of date entries whenever there
 * is a request for an expired or inexistent ARP entry */
uint8_t* getARPEntry( uint32_t ipaddr )
{
        /* first entry being added to table */
	struct arp_entry* pp = table;
	struct arp_entry* cp = table;
	
	while( cp != NULL )
	{
		/* check if current entry is out of date
		 * if so remove it */
		if( time(NULL) > cp->ttl )
		{
			/* if we are clearing the first element
			 * we need to adjust the head pointer */
			if( cp == table )
			{
				table = cp->next;
				pp = table;
				free(cp);
				cp = table;
			}
			else
			{
				pp->next = cp->next;
				free(cp);
				cp = pp->next;
			}
			
		}
		/* else check if there is an ip match
		 * if there is return it */
		else if( cp->ip_addr == ipaddr )
		{
			return cp->mac_addr;
		}
		/* if entry was either out of date or
		 * not the one we want proceed to next */
		else
		{
			pp = cp;
			cp = cp->next;
		}
	}

	/* wasn't found */
	return NULL;
}

void printARPTable()
{
    	/* first entry being added to table */
	struct arp_entry* cp = table;
	
	while( cp != NULL )
	{
	    printf("\nMAC: ");
	    DebugMAC(cp->mac_addr);
	    printf(" IP: ");
	    printIPAddr(cp->ip_addr);
	    printf("\n");
	    cp = cp->next;
	}
}

void sendARPRequest( struct sr_instance* sr, uint32_t ip, struct sr_if* interface )
{
	assert(interface);
	uint8_t mac_broadcast[ETHER_ADDR_LEN] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	uint8_t mac_broadcast2[ETHER_ADDR_LEN] = {0x00,0x00,0x00,0x00,0x00,0x00};

	uint8_t* temp = malloc( sizeof(struct etherARP) );
	struct etherARP* temp_etherARP = (struct etherARP*)temp;

	memcpy(temp_etherARP->ether.ether_shost, interface->addr, ETHER_ADDR_LEN);
	memcpy(temp_etherARP->ether.ether_dhost, &mac_broadcast, ETHER_ADDR_LEN);
	temp_etherARP->ether.ether_type = htons(ETHERTYPE_ARP);

	memcpy(temp_etherARP->arp.ar_sha, interface->addr, ETHER_ADDR_LEN);
	
	/* check this out :S */
	memcpy(temp_etherARP->arp.ar_tha, &mac_broadcast2, ETHER_ADDR_LEN);
	
	temp_etherARP->arp.ar_sip = interface->ip;
	temp_etherARP->arp.ar_tip = ip;

	temp_etherARP->arp.ar_hrd = htons(ARPHDR_ETHER);	/* format of hardware address   */
	temp_etherARP->arp.ar_pro = htons(ETHERTYPE_IP);   	/* format of protocol address   */
	temp_etherARP->arp.ar_hln = ETHER_ADDR_LEN;		/* length of hardware address   */
	temp_etherARP->arp.ar_pln = sizeof(ip);			/* length of protocol address   */
	temp_etherARP->arp.ar_op = htons(ARP_REQUEST);	

	sr_send_packet(sr, temp, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr), interface->name);

	/* 
	* printf("\n****************************************************************\n");
	* printEthernetHeader(&temp_etherARP->ether);
	* printARPHeader(&temp_etherARP->arp);
	* printf("SIZE %d\n", sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));
	* printf("\n================================================================\n");
	*/

	free(temp);
}

void sendARPReply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
	struct sr_ethernet_hdr *ethr_hdr = (struct sr_ethernet_hdr *)packet;	
	struct sr_if *this_if = sr_get_interface(sr, interface);
	struct sr_arphdr *arp_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));

	/*
	* printARPHeader(arp_hdr); 
	* printEthernetHeader(ethr_hdr);
	* printf("\n------\n");
	*/ 

	memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
	arp_hdr->ar_tip = arp_hdr->ar_sip;

	memcpy(arp_hdr->ar_sha, this_if->addr, ETHER_ADDR_LEN);
	arp_hdr->ar_sip = this_if->ip;

	arp_hdr->ar_op = htons(ARP_REPLY);

	memcpy(ethr_hdr->ether_dhost, ethr_hdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(ethr_hdr->ether_shost, this_if->addr, ETHER_ADDR_LEN);

	/*
	 * printf("\nSEND RESPONSE__");
	 * printEthernetHeader(ethr_hdr);
	 * printARPHeader(arp_hdr); 
	 * printf("\n");
	 */
	sr_send_packet(sr, packet, len, interface);	
}

void handleARP(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
	struct sr_ethernet_hdr *ethr_hdr = (struct sr_ethernet_hdr *)packet;
	struct sr_arphdr *arp_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));

	/* Add incoming packet's IP/MAC in ARP Table */
	addARPEntry( arp_hdr->ar_sip, ethr_hdr->ether_shost );

	if (htons(arp_hdr->ar_op) == ARP_REQUEST) {
 
		/* check if an interface or ip on subnet */
		if( isRouterInterface( sr, arp_hdr->ar_tip ) || getInterface(sr, arp_hdr->ar_tip) ) {
			sendARPReply(sr, packet, len, interface );
		}
		else if( !strcmp(getGatewayInterface(sr), interface) ){
			/* shady logic */
			sendARPReply(sr, packet, len, interface );
			DEBUG(printf("not gateway");)
		}
						
	} else if (htons(arp_hdr->ar_op) == ARP_REPLY) {
		/* Handling an ARP Reply to extract information */
		printf(" Reply");
		sendQueuedPackets(sr, arp_hdr->ar_sip);		
	}
}

char* getGatewayInterface(struct sr_instance* sr)
{
	struct sr_rt* rt = sr->routing_table;
	struct in_addr temp;
	inet_aton("0.0.0.0", &temp);
	while ( rt ) {
		if (rt->dest.s_addr == temp.s_addr){
			return rt->interface;
		}
		rt = rt->next;
	}
	return NULL;
}

uint32_t getGateway(struct sr_instance* sr)
{
	struct sr_rt* rt = sr->routing_table;
	struct in_addr temp;
	inet_aton("0.0.0.0", &temp);
	while ( rt ) {
		if (rt->dest.s_addr == temp.s_addr){
			return rt->gw.s_addr;
		}
		rt = rt->next;
	}
	return 0;
}

void handleICMP(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
	struct sr_ethernet_hdr *ethr_hdr = (struct sr_ethernet_hdr *)packet;	
	struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
	struct icmp *icmp_hdr = (struct icmp *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
	struct sr_if *this_if = sr_get_interface(sr, interface);

	/* validate icmp checksum */
	uint16_t temp = icmp_hdr->icmp_sum;
	icmp_hdr->icmp_sum = 0;
	icmp_hdr->icmp_sum = calcChecksum(icmp_hdr, htons(ip_hdr->ip_len) - sizeof(struct ip));

	/* check checksum of incoming ICMP packet */
	if (temp != icmp_hdr->icmp_sum) {
		/* drop invalid packet */
		return;	
	}

	icmp_hdr->icmp_type = ICMP_ECHO_REPLY;
	icmp_hdr->icmp_sum = 0;
	icmp_hdr->icmp_sum = calcChecksum(icmp_hdr, htons(ip_hdr->ip_len) - sizeof(struct ip));
	
	uint32_t temp_addr = ip_hdr->ip_src.s_addr;
	ip_hdr->ip_src.s_addr = ip_hdr->ip_dst.s_addr;
	ip_hdr->ip_dst.s_addr = temp_addr;

	ip_hdr->ip_ttl = 128;

	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = calcChecksum(ip_hdr, sizeof(struct ip));

	memcpy(ethr_hdr->ether_dhost, ethr_hdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(ethr_hdr->ether_shost, this_if->addr, ETHER_ADDR_LEN);

	/*
	* printICMPHeader(icmp_hdr);
	* printEthernetHeader(ethr_hdr);
	* ntIPHeader(ip_hdr);
	* printf("\n");
	*/

	sr_send_packet(sr, packet, htons(ip_hdr->ip_len) + sizeof(struct sr_ethernet_hdr), interface);
	/*printICMPHeader(icmp_hdr);*/
	/*printf("\n...............................\n");*/
	sendICMPmessage(sr, packet, len, interface, 11, 0 );


}

void addPacketToQueue( uint32_t ip, uint8_t* q_packet, unsigned int len, char* interface )
{
    /* create new queued packet */
    struct queued_packet* new_entry = malloc( sizeof(struct queued_packet) );
    assert( new_entry );

    new_entry->ttl = ARP_TTL;
    new_entry->ip = ip;
    new_entry->len = len;
    memcpy( new_entry->interface, interface, ETHER_ADDR_LEN );

    /* allocate memory for packet */
    new_entry->packet = malloc( len );
    assert( new_entry->packet );
    memcpy( new_entry->packet, q_packet, len );


    new_entry->next = NULL;

    struct queued_packet* cp = packet_queue;

    if( !cp ) {
    	packet_queue = new_entry;
    }
    else {
    /* traverse queue until end is reached */
        while( cp->next )
    	{
    	   cp = cp->next;
    	}
	/* add new packet to end of queue */
	cp->next = new_entry;
    }

}

void sendQueuedPackets( struct sr_instance* sr, uint32_t ip )
{
    struct queued_packet* cp = packet_queue;
    struct queued_packet* pp = packet_queue;

    /* traverse queue until end is reached */
    while( cp )
    {
        if( cp->ip == ip )
        {
            printf("send packet to ");
            printIPAddr( cp->ip );

	    struct sr_ethernet_hdr *ethr_hdr = (struct sr_ethernet_hdr *)cp->packet;	
	    uint8_t* mac = getARPEntry(ip);
	    /* MAC address should be in the ARP table since a reply was just received */ 
	    assert(mac);
	    memcpy(ethr_hdr->ether_dhost, mac, ETHER_ADDR_LEN);
            sr_send_packet(sr, cp->packet, cp->len, cp->interface);

            /* remove packet from queue and deallocate associated memory */
            if( cp == packet_queue )
            {
                /* if first element */
                packet_queue = cp->next;
                pp = packet_queue;
                free(cp->packet);
                free(cp);
                cp = packet_queue;
            }
            else
            {
                /* not first element */
                pp->next = cp->next;
                free(cp->packet);
                free(cp);
                cp = pp->next;
            }
        }
        else
        {
            pp = cp;
            cp = cp->next;
        }
    }
}

void resendARPRequests( struct sr_instance* sr )
{
    struct queued_packet* cp = packet_queue;
    struct queued_packet* pp = packet_queue;
	
    /* traverse queue until end is reached */
    while( cp )
    {
        printf("\nResending ARP Requests for Queued Packets.\n");
        if( cp->ttl == 0 )
        {
            /* remove packet from queue and deallocate associated memory */
            if( cp == packet_queue )
            {
                /* if first element */
                packet_queue = cp->next;
                pp = packet_queue;
                free(cp->packet);
                free(cp);
                cp = packet_queue;
            }
            else
            {
                /* not first element */
                pp->next = cp->next;
                free(cp->packet);
                free(cp);
                cp = pp->next;
            }

	    /* ICMP HOST Unreachable */
	    printf("\nhost unreachable\n");
	    sendICMPmessage(sr, cp->packet, cp->len, cp->interface, 3, 0);
        }
        else
        {
	    /* decrement ttl */
	    cp->ttl -= 1;
	    /* send arp request again */
	    sendARPRequest( sr, cp->ip, sr_get_interface(sr, cp->interface) );
            pp = cp;
            cp = cp->next;
        }
    }
}

void sendICMPmessage(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, uint8_t type, uint8_t code )
{
	struct sr_ethernet_hdr *ethr_hdr = (struct sr_ethernet_hdr *)packet;	
	struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
	struct sr_if *this_if = sr_get_interface(sr, interface);

	uint8_t* temp = malloc( sizeof(struct etherICMP) );
	assert(temp);

	struct sr_ethernet_hdr* temp_ether = (struct sr_ethernet_hdr*)temp;
	struct ip* temp_ip = (struct ip*)(temp + sizeof(struct sr_ethernet_hdr));
	struct icmp* temp_icmp = (struct icmp*)(temp + sizeof(struct ip) + sizeof(struct sr_ethernet_hdr));

	uint8_t* pad = temp + sizeof(struct ip) + sizeof(struct sr_ethernet_hdr) + sizeof(struct icmp);
	
	memcpy(pad, ip_hdr, 32);
	
	/* ICMP Header */
	temp_icmp->icmp_type = type;
	temp_icmp->icmp_code = code;
	temp_icmp->icmp_id = 3;
	temp_icmp->icmp_seq = time(NULL)%0xFFFF;
	temp_icmp->icmp_sum = 0;
	temp_icmp->icmp_sum = calcChecksum(temp_icmp, 60 - sizeof(struct ip));
	
	/* IP Header */
	temp_ip->ip_hl  = ip_hdr->ip_hl;
	temp_ip->ip_v   = ip_hdr->ip_v;
	temp_ip->ip_tos = ip_hdr->ip_tos;
	temp_ip->ip_len = htons( 60 );
	temp_ip->ip_id  = ip_hdr->ip_id;
	temp_ip->ip_off = ip_hdr->ip_off;

	temp_ip->ip_ttl = 128;
	temp_ip->ip_p   = IPPROTO_ICMP;

	temp_ip->ip_src.s_addr = this_if->ip;
	temp_ip->ip_dst.s_addr = ip_hdr->ip_src.s_addr;

	temp_ip->ip_sum = 0;
	temp_ip->ip_sum = calcChecksum(temp_ip, sizeof(struct ip));

	/* Ethernet Header */
	memcpy(temp_ether->ether_shost, this_if->addr, ETHER_ADDR_LEN);
	memcpy(temp_ether->ether_dhost, ethr_hdr->ether_shost, ETHER_ADDR_LEN);
	temp_ether->ether_type = htons(ETHERTYPE_IP);


	sr_send_packet(sr, temp, sizeof(struct etherICMP), interface);
	
	/*printf("\n****************************************************************\n");*/
	/* printEthernetHeader(ethr_hdr); */
	/* printEthernetHeader(temp_ether); */
	/*printICMPHeader(temp_icmp);*/
	/* printf("\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"); */
	/* printIPHeader(ip_hdr); */	
	/* printIPHeader(temp_ip); */
	/*printf("\n================================================================\n");*/
	
	free(temp);
}

void forwardPacket(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
	
	/* Check if packet directed to an IP Address in Routing Table */
	struct sr_ethernet_hdr *ethr_hdr = (struct sr_ethernet_hdr *)packet;	
	struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
	struct sr_if* myInterface = getInterface(sr, ip_hdr->ip_dst.s_addr);
	
	/* printf("\nIP: "); */
	/* printIPAddr(ip_hdr->ip_dst.s_addr); */
	if ( myInterface ) {
		/* if IP Address found in Routing Table */
		uint8_t* mac = getARPEntry(ip_hdr->ip_dst.s_addr);
		if (mac) {
			/* MAC Address for IP found in ARP Table */
			/* forward the packet to destination IP */
			/*printf("\nforward");*/
			memcpy(ethr_hdr->ether_dhost, mac, ETHER_ADDR_LEN);
			memcpy(ethr_hdr->ether_shost, myInterface->addr, ETHER_ADDR_LEN);
			sr_send_packet(sr, packet, htons(ip_hdr->ip_len) + sizeof(struct sr_ethernet_hdr), myInterface->name);

		} else {
			/* Add to Queue */ 
			/* Make an ARP Request */
			/* printf("\nqueue and make arp request"); */
			/*printf("MAKE AND ARP REQUEST ");
			*printIPAddr(ip_hdr->ip_dst.s_addr);
			*printf(" %s\n", myInterface->name);*/

			memcpy(ethr_hdr->ether_shost, myInterface->addr, ETHER_ADDR_LEN);
			addPacketToQueue( ip_hdr->ip_dst.s_addr, packet, len, myInterface->name );			
			sendARPRequest( sr, ip_hdr->ip_dst.s_addr, myInterface );
		}
	} else {
		uint8_t* mac = getARPEntry(ip_hdr->ip_dst.s_addr);
		char* gateway = getGatewayInterface(sr);
		assert(gateway);
		struct sr_if* gatewayInterface = sr_get_interface(sr, gateway);
		assert(gatewayInterface);
		if (mac) {
			/* MAC Address for IP found in ARP Table */
			/* forward the packet to destination IP */
			/*printf("\nforward");*/
			memcpy(ethr_hdr->ether_dhost, mac, ETHER_ADDR_LEN);
			memcpy(ethr_hdr->ether_shost, gatewayInterface->addr, ETHER_ADDR_LEN);
			sr_send_packet(sr, packet, htons(ip_hdr->ip_len) + sizeof(struct sr_ethernet_hdr), gateway);

		} else {
			printf("\n--something seriously wrong--  ");
			
			/* Wait for an ARP Request Response */
			memcpy(ethr_hdr->ether_shost, gatewayInterface->addr, ETHER_ADDR_LEN);
			addPacketToQueue( ip_hdr->ip_dst.s_addr, packet, len, gatewayInterface->name );
			/* vns isn't responding to our arp request */
			sendARPRequest( sr, ip_hdr->ip_dst.s_addr, gatewayInterface );

			/* Forward all packets to Gateway IP Address */
			/* memcpy(ethr_hdr->ether_shost, gatewayInterface->addr, ETHER_ADDR_LEN); */
			/* memcpy(ethr_hdr->ether_dhost, getARPEntry(getGateway(sr)), ETHER_ADDR_LEN); */
			/*sr_send_packet(sr, packet, htons(ip_hdr->ip_len) + sizeof(struct sr_ethernet_hdr), gatewayInterface->name ); */
		}

	}
}



