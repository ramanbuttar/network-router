/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 * date: Tue Nov 23 23:24:18 PST 2004 
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include "sr_pwospf.h"
#include "sr_router.h"

#include "pwospf_protocol.h"
#include "sr_if.h"

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <malloc.h>

#include <string.h>
#include <stdlib.h>

/* -- declaration of main thread function for pwospf subsystem --- */
static void* pwospf_run_thread(void* arg);
static void* pwospf_run_iface_thread(void* arg);
static void* pwospf_run_lsu_thread(void* arg);
static void* pwospf_run_db_thread(void* arg);

#ifdef ROUTER_DEBUG
	static void* pwospf_run_debug_thread(void* arg);
#endif


/*---------------------------------------------------------------------
 * Method: pwospf_init(..)
 *
 * Sets up the internal data structures for the pwospf subsystem 
 *
 * You may assume that the interfaces have been created and initialized
 * by this point.
 *---------------------------------------------------------------------*/

int pwospf_init(struct sr_instance* sr)
{
	/* Seed Random with current time */
	srand( time(NULL) );

    assert(sr);

    sr->ospf_subsys = (struct pwospf_subsys*)malloc(sizeof(struct
                                                      pwospf_subsys));

    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);
    pthread_mutex_init(&(sr->ospf_subsys->iface_lock), 0);
	sr->ospf_subsys->lsu_timer = time(NULL);
    pthread_mutex_init(&(sr->ospf_subsys->db_lock), 0);
    pthread_mutex_init(&(sr->ospf_subsys->rt_lock), 0);


    /* -- handle subsystem initialization here! -- */


    /* -- start thread subsystem -- */
    if( pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr)) { 
        perror("pthread_create");
        assert(0);
    }

    if( pthread_create(&sr->ospf_subsys->iface_thread, 0, pwospf_run_iface_thread, sr)) { 
        perror("iface_pthread_create");
        assert(0);
    }

    if( pthread_create(&sr->ospf_subsys->lsu_thread, 0, pwospf_run_lsu_thread, sr)) { 
        perror("iface_pthread_create");
        assert(0);
    }

    if( pthread_create(&sr->ospf_subsys->lsu_thread, 0, pwospf_run_db_thread, sr)) { 
        perror("iface_pthread_create");
        assert(0);
    }

	#ifdef ROUTER_DEBUG
	    if( pthread_create(&sr->ospf_subsys->lsu_thread, 0, pwospf_run_debug_thread, sr)) { 
	        perror("iface_pthread_create");
	        assert(0);
	    }
	#endif


	/* Update Interface List to include HELLO Interval value */
	assert(sr->if_list);
    struct sr_if* this_if = sr->if_list;
    while (this_if != NULL){
		this_if->helloint = OSPF_DEFAULT_HELLOINT;
		this_if->n_ip = 0x00;
		this_if->n_mask = htonl(0xfffffffe);
		this_if->n_id = 0x00;
		this_if->seq = rand() % 1000;
		this_if = this_if->next;
	}

	/* Initialize PWOSPF Routing Table to NULL */
	sr->pwospf_table = NULL;

    return 0; /* success */
} /* -- pwospf_init -- */


/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Main thread of pwospf subsystem. 
 *
 *---------------------------------------------------------------------*/

static void* pwospf_run_thread(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;

    while(1)
    {
        /* -- PWOSPF subsystem functionality should start  here! -- */

        /*printf("%u second trigger - SEND HELLO BROADCAST\n", OSPF_DEFAULT_HELLOINT);*/
		broadcastHello(sr);
        sleep(OSPF_DEFAULT_HELLOINT);
    };
} /* -- run_ospf_thread -- */













/*---------------------------------------------------------------------
 * Method: pwospf_iface_lock
 *
 * Interface Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_iface_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->iface_lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_iface_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_iface_unlock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->iface_lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_run_iface_thread
 *
 * Main thread of pwospf subsystem. 
 *
 *---------------------------------------------------------------------*/

static void* pwospf_run_iface_thread(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;

    while(1)
    {
        /* -- PWOSPF subsystem functionality should start  here! -- */

        pwospf_iface_lock(sr->ospf_subsys);
		/* printf("Interface TTL Check - LOCK\n"); */
		if ( checkInterfaceTTL(sr) )
		{
			printf("interface neighbour dropped - SEND LSU\n");
			sendLSUs(sr);
		}
		/* printf("Interface TTL Check - UNLOCK\n"); */
        pwospf_iface_unlock(sr->ospf_subsys);
		
        sleep(1);
    };
} /* -- run_ospf_thread -- */






/*---------------------------------------------------------------------
 * Method: pwospf_run_lsu_thread
 *
 * Main thread of pwospf subsystem. 
 *
 *---------------------------------------------------------------------*/

static void* pwospf_run_lsu_thread(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;

    while(1)
    {
        /* -- PWOSPF subsystem functionality should start  here! -- */
		
		if (sr->ospf_subsys->lsu_timer + OSPF_DEFAULT_LSUINT < time(NULL)) {
	        pwospf_iface_lock(sr->ospf_subsys);
			/* printf("Send LSUs - LOCK\n"); */
			/*printf("%u second trigger - SEND LSU\n", OSPF_DEFAULT_LSUINT);*/
			sendLSUs(sr);
			/* printf("Send LSUs - UNLOCK\n");  */
	        pwospf_iface_unlock(sr->ospf_subsys);
		}
			sleep(1);
    };
} /* -- run_ospf_thread -- */






/*---------------------------------------------------------------------
 * Method: pwospf_db_lock
 *
 * Interface Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_db_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->db_lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_db_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_db_unlock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->db_lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_run_db_thread
 *
 * Main thread of pwospf subsystem. 
 *
 *---------------------------------------------------------------------*/

static void* pwospf_run_db_thread(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;

    while(1)
    {
        /* -- PWOSPF subsystem functionality should start  here! -- */
        pwospf_db_lock(sr->ospf_subsys);
		/* printf("DB Cleanup - LOCK\n"); */
		/*printf("%u second trigger - CLEAN DB\n", OSPF_TOPO_ENTRY_TIMEOUT / 2);*/
		cleanDB(sr);
		/* printf("DB Cleanup - UNLOCK\n");  */
        pwospf_db_unlock(sr->ospf_subsys);

		/*sleep(OSPF_TOPO_ENTRY_TIMEOUT / 4);*/
		sleep(1);
    };
} /* -- run_ospf_thread -- */




/*---------------------------------------------------------------------
 * Method: pwospf_rt_lock
 *
 * Interface Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_rt_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->rt_lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_rt_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_rt_unlock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->rt_lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */




#ifdef ROUTER_DEBUG
	static void* pwospf_run_debug_thread(void* arg)
	{
	    struct sr_instance* sr = (struct sr_instance*)arg;

	    while(1)
	    {

		/* DEBUGGINg THREAD */
		scanf("%s", sr->debug_iface);

	    };
} /* -- run_ospf_thread -- */
#endif



void sendHello(struct sr_instance* sr, struct sr_if* if_out)
{
	uint8_t* temp = malloc(sizeof(struct ospfv2_hello));
	struct sr_ethernet_hdr *ether = (struct sr_ethernet_hdr *)temp;	
	struct ip *ip_hdr = (struct ip *)(temp + sizeof(struct sr_ethernet_hdr));	
    struct ospfv2_hdr *hdr = (struct ospfv2_hdr *)(temp + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    struct ospfv2_hello_hdr *hello_hdr = (struct ospfv2_hello_hdr *)(temp + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));

    /* Hello Header */
    hello_hdr->nmask = if_out->n_mask;
    hello_hdr->helloint = htons(OSPF_DEFAULT_HELLOINT);
   	hello_hdr->padding = 0x0000;

    /* Header */
    hdr->version = OSPF_V2;
    hdr->type = OSPF_TYPE_HELLO;
    hdr->len = htons(sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr));
   
    /*struct sr_if* rid_if = sr_get_interface(sr, "eth0");*/
    /*hdr->rid = rid_if->ip;*/
   	hdr->rid = if_out->ip;
    hdr->aid = htonl(if_out->ip & 0xff);

    hdr->autype = OSPF_DEFAULT_AUTHKEY;
    hdr->audata = 0x0;

    hdr->csum = 0;
	/* AHHH! checksum may need htons() */
    hdr->csum = calcChecksum(hdr, htons(hdr->len));

	/* IP Header */
	ip_hdr->ip_hl  = htons(sizeof(struct ip));
	ip_hdr->ip_v   = htons(4);
	ip_hdr->ip_tos = 0; /* Not Supported */
	ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr));
	ip_hdr->ip_id  = 0; /* Not Supported */
	ip_hdr->ip_off = 0; /* Not Supported */

	ip_hdr->ip_ttl = IP_MAX_TTL;
	ip_hdr->ip_p   = IPPROTO_PWOSPF;

	ip_hdr->ip_src.s_addr = if_out->ip;
	ip_hdr->ip_dst.s_addr = htonl(OSPF_AllSPFRouters);

	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = calcChecksum(ip_hdr, sizeof(struct ip));

	/* Ethernet Header */
	uint8_t mac_broadcast[ETHER_ADDR_LEN] = ETHER_BROADCAST;
	memcpy(ether->ether_dhost, mac_broadcast, ETHER_ADDR_LEN);
	memcpy(ether->ether_shost, if_out->addr, ETHER_ADDR_LEN);
	ether->ether_type = htons(ETHERTYPE_IP);

	sr_send_packet(sr, temp, sizeof(struct ospfv2_hello), if_out->name);
}

void broadcastHello(struct sr_instance* sr)
{
    struct sr_if* if_out = sr->if_list;
    while (if_out != NULL){
		sendHello(sr, if_out);
		if_out = if_out->next;
	}
}

int checkInterfaceTTL(struct sr_instance* sr)
{
	int sendUpdate = 0;
	struct sr_if* interface = sr->if_list;
    while (interface != NULL){
		if (interface->n_ip != 0x00 && (interface->time + OSPF_NEIGHBOR_TIMEOUT < time(NULL))) {
			interface->n_ip = 0x00;
			interface->n_id = 0x00;
			interface->time = 0x00;
			/* printf(" %s was kicked out\n", interface->name); */
			sendUpdate = 1;
		}
		interface = interface->next;
	}
	return sendUpdate;
}


void sendLSU(struct sr_instance* sr, struct sr_if* if_out)
{
	int num_ads = numberOfLSUAds(sr);
	uint8_t* temp = malloc(sizeof(struct ospfv2_lsu_pkt) + num_ads*sizeof(struct ospfv2_lsu));
	struct sr_ethernet_hdr *ether = (struct sr_ethernet_hdr *)temp;	
	struct ip *ip_hdr = (struct ip *)(temp + sizeof(struct sr_ethernet_hdr));	
    struct ospfv2_hdr *hdr = (struct ospfv2_hdr *)(temp + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    struct ospfv2_lsu_hdr *lsu_hdr = (struct ospfv2_lsu_hdr *)(temp + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));
    
	/* LSU */
	/* Append All Advertisements */
	setAds(sr, temp);

    /* LSU Header */
	lsu_hdr->seq = htons(if_out->seq);
	lsu_hdr->ttl = OSPF_MAX_LSU_TTL;
   	lsu_hdr->num_adv = htonl(num_ads);

    /* Header */
    hdr->version = OSPF_V2;
    hdr->type = OSPF_TYPE_LSU;
    hdr->len = htons(sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) + num_ads*sizeof(struct ospfv2_lsu));
   
    /*struct sr_if* rid_if = sr_get_interface(sr, "eth0");*/
    /*hdr->rid = rid_if->ip;*/
    hdr->rid = if_out->ip;
    hdr->aid = htonl(if_out->ip & 0xff);

    hdr->autype = OSPF_DEFAULT_AUTHKEY;
    hdr->audata = 0x0;

    hdr->csum = 0;
	/* AHHH! checksum may need htons() */
    hdr->csum = calcChecksum(hdr, htons(hdr->len));

	/* IP Header */
	ip_hdr->ip_hl  = htons(sizeof(struct ip));
	ip_hdr->ip_v   = htons(4);
	ip_hdr->ip_tos = 0; /* Not Supported */
	ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) + num_ads*sizeof(struct ospfv2_lsu));
	ip_hdr->ip_id  = 0; /* Not Supported */
	ip_hdr->ip_off = 0; /* Not Supported */

	ip_hdr->ip_ttl = IP_MAX_TTL;
	ip_hdr->ip_p   = IPPROTO_PWOSPF;

	ip_hdr->ip_src.s_addr = if_out->ip;
	ip_hdr->ip_dst.s_addr = if_out->n_ip;

	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = calcChecksum(ip_hdr, sizeof(struct ip));

	/* Ethernet Header */
	uint8_t* mac = getARPEntry(if_out->n_ip);
	if (mac != NULL) {
		memcpy(ether->ether_dhost, mac, ETHER_ADDR_LEN);
		memcpy(ether->ether_shost, if_out->addr, ETHER_ADDR_LEN);
		ether->ether_type = htons(ETHERTYPE_IP);
		/*printf("Sending LSU through interface: %s\n", if_out->name);*/
		sr_send_packet(sr, temp, sizeof(struct ospfv2_lsu_pkt) + num_ads*sizeof(struct ospfv2_lsu), if_out->name);
		if_out->seq = if_out->seq + 1;
	} else {
		/* Put in Queue */
		printf("ARP ENTRY NOT FOUND\n");
	}
}

void sendLSUs(struct sr_instance* sr)
{
	struct sr_if* interface = sr->if_list;
    while (interface != NULL){
		if (interface->n_ip != 0x00) {
			sendLSU(sr, interface);
			sr->ospf_subsys->lsu_timer = time(NULL);
		}
		interface = interface->next;
	}
}

int numberOfLSUAds(struct sr_instance* sr)
{
	int count = 0;

	struct sr_if* interface = sr->if_list;
    while (interface != NULL){
		/* increment count if interface exists */
		count += 1;
		if (interface->n_ip != 0x00) {
			/* increment count if interface has a neighbour */
			count += 1;
		}
		interface = interface->next;
	}
	return count;
}

void setAds(struct sr_instance* sr, uint8_t* packet)
{
	int count = 0;

	struct ospfv2_lsu *lsu;

	struct sr_if* interface = sr->if_list;

	char* gateway = getGatewayInterface(sr);

    while (interface != NULL){
		/* create ad for interface */
		lsu = (struct ospfv2_lsu *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr)
										   + sizeof(struct ospfv2_lsu_hdr) + count*sizeof(struct ospfv2_lsu) );
		
		
		if (gateway != NULL && (strcmp(gateway, interface->name) == 0)) {
	
			lsu->subnet = interface->ip & interface->mask;
		    lsu->mask = interface->mask;
		    lsu->rid = htons(0);
	
		} else {

			lsu->subnet = interface->ip & interface->n_mask;
		    lsu->mask = interface->n_mask;
		    lsu->rid = htons(0);
			/*lsu->rid = interface->ip;*/
		}

		count += 1;

		if (interface->n_ip != 0x00) {
			lsu = (struct ospfv2_lsu *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr)
										       + sizeof(struct ospfv2_lsu_hdr) + count*sizeof(struct ospfv2_lsu) );
			/* create ad for neighbour */
			lsu->subnet = interface->n_ip & interface->n_mask;
	    	lsu->mask = interface->n_mask;
	    	lsu->rid = interface->n_id;
			count += 1;
		}

		interface = interface->next;
	}
}

void cleanDB(struct sr_instance* sr)
{
	int bool = 0;
	struct pwospf_entry* cp = pwospf_db;
	struct pwospf_entry* pp = pwospf_db;
	while( cp != NULL ) {
		if ((cp->ttl + OSPF_TOPO_ENTRY_TIMEOUT) < time(NULL)) {
			if( cp == pwospf_db )
			{
	            /* if first element */
	            pwospf_db = cp->next;
                pp = pwospf_db;
                free(cp);
                cp = pwospf_db;
			}
			else
            {
                /* not first element */
                pp->next = cp->next;
                free(cp);
                cp = pp->next;
            }
			bool |= 1;
		} else {
			pp = cp;
			cp = cp->next;
		}
	}

	struct sr_if* interface= sr->if_list;
	char* gateway = getGatewayInterface(sr);
	while( interface != NULL ) {
		if (interface->n_ip == 0x00) {
			if (gateway != NULL && strcmp(gateway, interface->name) == 0)
			{
				bool |= addPWOSPFEntry(interface->ip & interface->mask, interface->mask, htons(0), OSPF_MAX_LSU_TTL, time(NULL), interface);
			} else {
				bool |= addPWOSPFEntry(interface->ip & interface->n_mask, interface->n_mask, htons(0), OSPF_MAX_LSU_TTL, time(NULL), interface);
			}
		}
		interface= interface->next;
	}

	if (bool) {
		computePWOSPFTable(sr);
	}
}
