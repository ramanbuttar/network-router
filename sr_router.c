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
#include "sr_pwospf.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"

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

    pwospf_init(sr); 
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

	#ifdef ROUTER_DEBUG
		if (strcmp(sr->debug_iface, interface) == 0) {
			printf("%s interface dropped. Packet not received.\n", interface);
			return;
		}
	#endif

    DEBUG(printf("*** Received packet of length %d *** \n",len);)
  
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

		/* check checksum of incoming IP packet */
		if (temp != ip_hdr->ip_sum) {
			printf("\nPacket Dropped - Invalid IP Checksum");
			/* invalid checksum drop packet */
			return;
		}
		
		/* Add valid incoming packet's IP/MAC in ARP Table */
		addARPEntry( ip_hdr->ip_src.s_addr, ethr_hdr->ether_shost );

		
		/* drop packet if ttl is 0 */
		if( ip_hdr->ip_ttl <= 1 ) {
			/* send IP TTL expired */		

			sendICMPmessage(sr, packet, len, interface, 11, 0 );
			printf("\nPacket Dropped - IP TTL Expired");
			/* drop stale packet */
			return;
		}
		
		if (ip_hdr->ip_p == IPPROTO_PWOSPF) {
			/* PWOSPF */
			printf(" PWOSPF");
			handlePWOSPF(sr, packet, len, interface);

		/* Packet directed to one of Router's interfaces */
		} else if( !isRouterInterface(sr, ip_hdr->ip_dst.s_addr) ) {
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
		   	printf(" Unknown");
		}

    } else {
		/* Packet Type Undefined */
		printf(" NONE");
    }
	printf("\n");
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
	printf("\nPRO: %u", hdr->ar_pro);   /* format of protocol address   */
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
	/* This method will require both routing tables to be traversed */

	/* Dynamic PWOSPF Routing Table */

	uint32_t highest_mask = htonl(0);
	struct sr_if* best_if = 0;

	struct sr_rt* cp = sr->pwospf_table;

	while (cp != NULL) {
		if ((ip & cp->mask.s_addr) == cp->dest.s_addr) {
					
			if (htonl(cp->mask.s_addr) >= highest_mask){
				highest_mask = htonl(cp->mask.s_addr);
				best_if = sr_get_interface(sr, cp->interface);
			}
		}		
		cp = cp->next;
	}

	/* Static Routing Table */
	if (best_if == NULL) {
		struct sr_rt* cp = sr->routing_table;
		while (cp != NULL){
			if ( (ip & cp->mask.s_addr) == cp->dest.s_addr ) {
				return sr_get_interface(sr, cp->interface);		
			}
			cp = cp->next;
		}
		return NULL;
	}
	return best_if;
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
	uint8_t mac_broadcast[ETHER_ADDR_LEN] = ETHER_BROADCAST;
	uint8_t mac_broadcast2[ETHER_ADDR_LEN] = ETHER_BZERO;

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

	printf("ARP REQUEST going out from %s\n", interface->name);

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
	while ( rt ) {
		if (rt->dest.s_addr == htonl(0)){
			return rt->interface;
		}
		rt = rt->next;
	}
	return NULL;
}

uint32_t getGateway(struct sr_instance* sr)
{
	struct sr_rt* rt = sr->routing_table;
	while ( rt ) {
		if (rt->dest.s_addr == htonl(0)){
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

	ip_hdr->ip_ttl = IP_MAX_TTL;

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
	
	printf(" - Reply through %s\n", interface);
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
	    /*sendICMPmessage(sr, cp->packet, cp->len, cp->interface, 3, 0);*/
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

	temp_ip->ip_ttl = IP_MAX_TTL;
	temp_ip->ip_p   = IPPROTO_ICMP;

	temp_ip->ip_src.s_addr = this_if->ip;
	temp_ip->ip_dst.s_addr = ip_hdr->ip_src.s_addr;

	temp_ip->ip_sum = 0;
	temp_ip->ip_sum = calcChecksum(temp_ip, sizeof(struct ip));
	/* NOTE: Checksum should be calculated for IP Header AND its payload (ICMP data) */

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
		if (myInterface->n_ip != 0x00) {
			if ( (ip_hdr->ip_dst.s_addr & myInterface->n_mask) != (myInterface->ip & myInterface->n_mask) ) {

				/* if IP Address found in Routing Table */
				uint8_t* mac = getARPEntry(myInterface->n_ip);
				if (mac) {

					/* MAC Address for IP found in ARP Table */
					/* forward the packet to destination IP */
					/*printf("\nforward");*/
					
					memcpy(ethr_hdr->ether_dhost, mac, ETHER_ADDR_LEN);
					memcpy(ethr_hdr->ether_shost, myInterface->addr, ETHER_ADDR_LEN);
					/*printf("\nFORWARDING to Neighbour via %s\n", myInterface->name);*/
					sr_send_packet(sr, packet, htons(ip_hdr->ip_len) + sizeof(struct sr_ethernet_hdr), myInterface->name);
				}

			} else {
			
				memcpy(ethr_hdr->ether_shost, myInterface->addr, ETHER_ADDR_LEN);
				addPacketToQueue( ip_hdr->ip_dst.s_addr, packet, len, myInterface->name );			
				sendARPRequest( sr, ip_hdr->ip_dst.s_addr, myInterface );
			}
		} else {
			/* if IP Address found in Routing Table */
			uint8_t* mac = getARPEntry(ip_hdr->ip_dst.s_addr);
			if (mac) {				
				memcpy(ethr_hdr->ether_dhost, mac, ETHER_ADDR_LEN);
				memcpy(ethr_hdr->ether_shost, myInterface->addr, ETHER_ADDR_LEN);
				/*printf("\nFORWARDING to Destination via %s\n", myInterface->name);*/
				sr_send_packet(sr, packet, htons(ip_hdr->ip_len) + sizeof(struct sr_ethernet_hdr), myInterface->name);
			}
			else {
				memcpy(ethr_hdr->ether_shost, myInterface->addr, ETHER_ADDR_LEN);
				addPacketToQueue( ip_hdr->ip_dst.s_addr, packet, len, myInterface->name );			
				sendARPRequest( sr, ip_hdr->ip_dst.s_addr, myInterface );
			}
		}
	} else {
		uint8_t* mac = getARPEntry(ip_hdr->ip_dst.s_addr);
		char* gateway = getGatewayInterface(sr);
		if (!gateway) {
			/* Gateway not found . Drop Packet */
			printf("No Gateway\n");
			return;
		}
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

/* PWOSPF */

void handlePWOSPF(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
    struct ospfv2_hdr *hdr = (struct ospfv2_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
	/* verify protocol version*/
	if (hdr->version != OSPF_V2 ) {
		return;
	}
	
	/* validate checksum */
	uint16_t temp = hdr->csum;

	hdr->csum = 0;
	hdr->csum = calcChecksum(hdr, ntohs(hdr->len));

	/* check checksum of incoming PWOSPF packet */
	if (temp != hdr->csum) {
		printf("\nPacket Dropped - Invalid PWOSPF Checksum");
		/* invalid checksum drop packet */
		return;
	}
	
	/* Compare Area ID to receiving Interface's Area ID */
    struct sr_if* if_in = sr_get_interface(sr, interface);
	if (hdr->aid != htonl(if_in->ip & 0xff)) {
		return;
	}

	/* Check Authentication Type*/
	if (hdr->autype != OSPF_DEFAULT_AUTHKEY) {
		return;
	}

	/* Check PWOSPF Type */
	if ( hdr->type == OSPF_TYPE_HELLO )
	{
		printf(" HELLO\n");
		handleHello(sr, packet, if_in);
	}

	else if ( hdr->type == OSPF_TYPE_LSU )
	{
		printf(" LSU: %s\n", interface);

		struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
	    struct ospfv2_lsu_hdr *lsu_hdr = (struct ospfv2_lsu_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));

		if (isRouterInterface(sr, ip_hdr->ip_src.s_addr)) {
			printf("Packet Dropped - Routing Loop\n");			
			/* Drop packet since source IP is one of this router's interface IPs */ 
			return;
		}

		if ((lsu_hdr->seq < if_in->seq - 1) &&  (lsu_hdr->seq < if_in->seq - SEQUENCE_RANGE)) {
			printf("Packet Dropped - Sequence Number mismatch\n");
			/* Drop packet since sequence number is in range for our sent LSUs for this interface */ 
			return;
		}

		pwospf_iface_lock(sr->ospf_subsys);
		/* printf("Interface Get - LOCK\n"); */

		pwospf_db_lock(sr->ospf_subsys);
		/* printf("DB Add Entry - LOCK\n"); */

		/* Do Database Processing */
		putAdsInDB(sr, packet, if_in);

		/* printf("DB Add Entry - LOCK\n"); */
		pwospf_db_unlock(sr->ospf_subsys);


		/* printf("Interface Get - UNLOCK\n"); */
		pwospf_iface_unlock(sr->ospf_subsys);
		
		/* flood all neighbours */
		floodLSUs(sr, packet, len, interface);
	}
}


void handleHello(struct sr_instance* sr, uint8_t * packet, struct sr_if* interface)
{
    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
	struct ospfv2_hdr *hdr = (struct ospfv2_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    struct ospfv2_hello_hdr *hello_hdr = (struct ospfv2_hello_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));

	/* Check packet's network mask to receiving interface's network mask */
	if (hello_hdr->nmask != interface->n_mask) {
		printf("Packet Dropped - Invalid Neighbour Mask\n");
		return;
	}

	/* Check packet's HELLOINT value to receiving interface's HELLOINT value */
	if (htons(hello_hdr->helloint) != interface->helloint) {
		printf("Packet Dropped - Invalid HELLOINT Value\n");
		return;
	}
        
	pwospf_iface_lock(sr->ospf_subsys);
	/* printf("Interface TTL Set - LOCK\n"); */

	if (interface->n_ip == 0x00){
		/* Neighbour doesn't exist so create one */
		interface->n_ip = ip_hdr->ip_src.s_addr;
		interface->n_mask = hello_hdr->nmask;
		interface->n_id = hdr->rid;
		interface->time = time(NULL);
		/*printf("New Neighbour Added from %s - SEND LSU\n", interface->name);*/
		sendLSUs(sr);
	} else if (ip_hdr->ip_src.s_addr == interface->n_ip) {
		/* Neighbour exists - check if HELLO msg is from this interface's neighbour */
		/* update the neighbor's "last hello packet received" timer in DATABASE */
		interface->time = time(NULL);
	}

	pwospf_db_lock(sr->ospf_subsys);
	/* printf("DB Add Entry - LOCK\n"); */

	if (addPWOSPFEntry(interface->n_ip, hello_hdr->nmask, interface->n_id, ip_hdr->ip_ttl, time(NULL), interface)){
		computePWOSPFTable(sr);
	}
	

	/* printf("DB Add Entry - UNLOCK\n"); */
    pwospf_db_unlock(sr->ospf_subsys);

	/* printf("Interface TTL Set - UNLOCK\n"); */
    pwospf_iface_unlock(sr->ospf_subsys);

	/* HELLO Message was not from receiving interface's neighbour so drop it */
}

void printHelloHeader(struct ospfv2_hdr *hdr, struct ospfv2_hello_hdr *hello_hdr)
{
	printf("\n__HELLO HEADER__");
	if (hdr != NULL) {
		printf("\nVersion: %u", hdr->version);
		printf("\nType: %u", hdr->type);
		printf("\nLength: %u", htons(hdr->len));

		printf("\nRouter ID: ");
		printIPAddr(hdr->rid);
		printf("\nArea ID: %u", htonl(hdr->aid));

		printf("\nAuthentication Type: %u", hdr->autype);
		/*printf("\nAuthentication Data: %u", hdr->audata);*/
	}

	if (hello_hdr != NULL) {
		printf("\nMask ID: ");
		printIPAddr(hello_hdr->nmask);
		printf("\nInterval: %u", htons(hello_hdr->helloint));
	}
	printf("\n");
}


/* add PWOSPF entry to database */
int addPWOSPFEntry(uint32_t ip, uint32_t mask, uint32_t rid, uint8_t hop, time_t cur_time, struct sr_if* interface)
{
	int bool = 0;	

	/* first entry being added to table */
	struct pwospf_entry* pp = pwospf_db;
	struct pwospf_entry* cp = pwospf_db;
				
	while( cp != NULL )
	{
		
		if( cp->subnet == (ip & mask) && (cp->interface == interface))
		{
			if ( hop > cp->hop ) {
				/* More Optimal Route Found */
				cp->subnet = ip & mask;
				cp->mask = mask;
				cp->hop = hop;
				cp->rid = rid;
				cp->interface = interface;

				/* Trigger Router Table Update */
				bool = 1;
			}
		
			/* reset ttl */			cp->ttl = cur_time;
			return bool;
		}
		pp = cp;
		cp = cp->next;
	}

	/* create a new pwospf_entry */
	cp = malloc( sizeof(struct pwospf_entry) );

	cp->subnet = ip & mask;
	cp->mask = mask;
	cp->hop = hop;
	cp->ttl = cur_time;
	cp->rid = rid;
	cp->interface = interface;
	cp->next = NULL;

	/* Trigger Router Table Update */
	bool = 1;

	/* first entry in table */
	if( pwospf_db == NULL )
	{
		pwospf_db = cp;
	}
	/* add to end of table */
	else
	{
		pp->next = cp;
	}
	return bool;
}

struct pwospf_entry* getPWOSPFEntry(uint32_t ip)
{
	struct pwospf_entry* cp = pwospf_db;
	struct pwospf_entry* found = NULL;

	while( cp != NULL )
	{
		if( cp->subnet == (ip & cp->mask) && (cp->subnet > found->subnet))
		{
			found =  cp;
		}
		cp = cp->next;
	}
	return found;
}


void printLSUHeader(struct ospfv2_hdr *hdr, struct ospfv2_lsu_hdr *lsu_hdr)
{
	printf("\n__LSU HEADER__");
	if (hdr != NULL) {
		printf("\nVersion: %u", hdr->version);
		printf("\nType: %u", hdr->type);
		printf("\nLength: %u", htons(hdr->len));

		printf("\nRouter ID: ");
		printIPAddr(hdr->rid);
		printf("\nArea ID: %u", htonl(hdr->aid));

		printf("\nAuthentication Type: %u", hdr->autype);
		/*printf("\nAuthentication Data: %u", hdr->audata);*/
	}

	if (lsu_hdr != NULL) {
		printf("\nSequence: %u", htons(lsu_hdr->seq));
		printf("\nTTL: %u", lsu_hdr->ttl);
		printf("\nNum of Ads: %u", htonl(lsu_hdr->num_adv));
	}
	printf("\n");
}

void floodLSUs(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
	struct sr_if* this_if = sr->if_list;


    while (this_if != NULL) {
		/*printf("THIS INTERFACE: %s = %s\n", this_if->name, interface);*/
		if (strcmp(this_if->name, interface) != 0) {
			if (this_if->n_ip != 0x00) {
				/*printf("Forwarding LSU Update %s --> %s\n", interface, this_if->name);*/
				floodLSUPacket(sr, packet, len, this_if->name);
			} 
		}
		this_if = this_if->next;
	}

}

void floodLSUPacket(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
	struct sr_ethernet_hdr *ethr_hdr = (struct sr_ethernet_hdr *)packet;		
	struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
    struct ospfv2_hdr *lsu_hdr = (struct ospfv2_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    struct ospfv2_lsu_hdr *lsu = (struct ospfv2_lsu_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));

	struct sr_if* myInterface = sr_get_interface(sr, interface);

    /* LSU */
	lsu->ttl -= 1;
	
	if (lsu->ttl <= 1) {
		/* Drop packet since LSU TTL <= 1 */
		printf("Packet Dropped - LSU TTL <= 1\n");
		return;
	}

    /* LSU Header */
    lsu_hdr->csum = 0;
    lsu_hdr->csum = calcChecksum(lsu_hdr, ntohs(lsu_hdr->len));

	/* IP Header */
	/* decrement ttl */
	ip_hdr->ip_ttl -= 1;
		
	/* ip_hdr->ip_src.s_addr = myInterface->ip; */
	ip_hdr->ip_dst.s_addr = myInterface->n_ip;

	/* update checksum */
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = calcChecksum(ip_hdr, sizeof(struct ip));

	/* Ethernet Header */
	uint8_t* mac = getARPEntry(ip_hdr->ip_dst.s_addr);
	if (mac) {
		/* MAC Address for IP found in ARP Table */
		memcpy(ethr_hdr->ether_dhost, mac, ETHER_ADDR_LEN);
		memcpy(ethr_hdr->ether_shost, myInterface->addr, ETHER_ADDR_LEN);
		sr_send_packet(sr, packet, sizeof(struct ip) + sizeof(struct sr_ethernet_hdr) + ntohs(lsu_hdr->len), myInterface->name);
	} else {
		/* Put in Queue */
		printf("ARP ENTRY NOT FOUND\n");
	}

}

void putAdsInDB(struct sr_instance* sr, uint8_t* packet, struct sr_if* interface)
{
	int i, bool = 0;
	struct ospfv2_lsu_hdr *lsu_hdr = (struct ospfv2_lsu_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));
	struct ospfv2_lsu *lsu;

	int count = htonl(lsu_hdr->num_adv);
	for (i = 0; i < count; i += 1) {
		lsu = (struct ospfv2_lsu *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr)
										   + sizeof(struct ospfv2_lsu_hdr) + i*sizeof(struct ospfv2_lsu) );
		if (lsu->rid == htons(0)) {
			bool |= addPWOSPFEntry(lsu->subnet, lsu->mask, lsu->rid, lsu_hdr->ttl, time(NULL), interface);
		} else {
			bool |= addPWOSPFEntry(lsu->subnet, lsu->mask, lsu->rid, lsu_hdr->ttl-1, time(NULL), interface);
		}
	}
	if (bool) {
		computePWOSPFTable(sr);
		sendLSUs(sr);
	}
}

void printDB()
{
	struct pwospf_entry* cp = pwospf_db;
	
	printf("\n***********\n");
	while( cp != NULL )
	{
	    printf(" Subnet: ");
	    printIPAddr(cp->subnet);
	    printf("\n");
	    printf(" Mask: ");
	    printIPAddr(cp->mask);
	    printf("\n");
	    printf(" Router ID: ");
	    printIPAddr(cp->rid);
	    printf("\n");
	    printf(" Hop: %u\n", cp->hop);
	    /*printf(" TTL: %d\n", cp->ttl);*/
	    printf(" Interface: %s\n", cp->interface->name);
	    printf("\n");

	    cp = cp->next;

	}
	printf("\n***********\n");
}

void printDBCount()
{
	int count = 0;
	struct pwospf_entry* cp = pwospf_db;
	
	while( cp != NULL )
	{
		count += 1;
	    cp = cp->next;

	}
	printf("\nNumber of Entries: %d\n", count);
}


void computePWOSPFTable(struct sr_instance* sr)
{
	pwospf_rt_lock(sr->ospf_subsys);
	/* printf("PWOSPF Routing Table Add Entry - LOCK\n"); */

	sr_clear_pwospf_rt(sr);

	struct pwospf_entry* p1 = pwospf_db;
	struct pwospf_entry* p2 = pwospf_db;
	struct pwospf_entry* best_so_far = pwospf_db;
	
	while( p1 != NULL )
	{
		best_so_far = p1;
		p2 = p1->next;		
		
		while( p2 != NULL )
		{
			if (p2->subnet == best_so_far->subnet && p2->mask == best_so_far->mask) {
				if (p2->hop > best_so_far->hop) {
					best_so_far = p2;
				}
			}
			p2 = p2->next;
		}
	
		sr_add_pwospf_rt_entry(sr, best_so_far->subnet, best_so_far->rid /* AHHHHHH! GATEWAY */, best_so_far->mask, best_so_far->interface->name);		

	    p1 = p1->next;
	}
	
	sr_print_pwospf_table(sr);

	pwospf_rt_unlock(sr->ospf_subsys);
	/* printf("PWOSPF Routing Table Add Entry - UNLOCK\n"); */


}

