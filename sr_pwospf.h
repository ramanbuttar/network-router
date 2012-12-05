/*-----------------------------------------------------------------------------
 * file:  sr_pwospf.h
 * date:  Tue Nov 23 23:21:22 PST 2004 
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_PWOSPF_H
#define SR_PWOSPF_H

#include <pthread.h>
#include "sr_protocol.h"

/* forward declare */
struct sr_instance;

struct pwospf_subsys
{
    /* -- pwospf subsystem state variables here -- */


    /* -- thread and single lock for pwospf subsystem -- */
    pthread_t thread;
    pthread_mutex_t lock;
    pthread_t iface_thread;			/* Thread for Interface List */
    pthread_mutex_t iface_lock;		/* Lock for Interface List */
    pthread_t lsu_thread;			/* Thread for sending LSUs */
	time_t lsu_timer;				/* Last sent LSU update */
    pthread_mutex_t db_lock;		/* Lock for PWOSPSF DB */
    pthread_t db_thread;			/* Thread for taking out stale DB entries */
    pthread_mutex_t rt_lock;		/* Lock for PWOSPSF Routing Table */

#ifdef ROUTER_DEBUG
    pthread_t debug_thread;			/* Thread for taking out stale DB entries */
#endif

};



int pwospf_init(struct sr_instance* sr);

/* Threading */
void pwospf_iface_lock(struct pwospf_subsys* subsys);
void pwospf_iface_unlock(struct pwospf_subsys* subsys);

void pwospf_db_lock(struct pwospf_subsys* subsys);
void pwospf_db_unlock(struct pwospf_subsys* subsys);

void pwospf_rt_lock(struct pwospf_subsys* subsys);
void pwospf_rt_unlock(struct pwospf_subsys* subsys);

int checkInterfaceTTL(struct sr_instance* sr);
int numberOfLSUAds(struct sr_instance* sr);
void cleanDB(struct sr_instance* sr);

#endif /* SR_PWOSPF_H */
