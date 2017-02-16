/*
 * Copyright (c) 2003, Amgad Zeitoun.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Amgad Zeitoun at the University of Michigan, Ann Arbor. The
 * name of the University may not be used to endorse or promote
 * products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Author: 
 *           Amgad Zeitoun (azeitoun@eecs.umich.edu)
 */

/*
 * Event queue
 */

#include "queue.h"
#include <assert.h>


queue_entry *create_qentry(int type, struct timeval time, unsigned int id)
{
   queue_entry *qe = (queue_entry *) calloc(1, sizeof(queue_entry));
   assert(qe);

   qe->type = type;
   qe->time = time;
   qe->id = id;

   
   return qe;
}

int queue_insert(queue *q, queue_entry *qe)
{
   queue_entry *p;

   assert(q);
   assert(qe);

   if(!q->head) {
      q->head = qe;
      q->tail = qe;
   }
   else {
      for(p = q->head; p && compare_time(p->time, qe->time) <= 0; p = p->next);
      
      if(p) {
	 qe->next = p;
	 qe->prev = p->prev;
	 p->prev = qe;
	 if(qe->prev)
	    qe->prev->next = qe;
	 else
	    q->head = qe;
      }
      else {
	 assert(q->tail);
	 qe->prev = q->tail;
	 q->tail = qe;
	 qe->prev->next = qe;
      }
   }
   
   q->size++;
   return OK;
}

queue_entry *get_first_entry(queue *q)
{
   return(q->head);
}

int queue_remove(queue *q, int type, unsigned int id)
{
   queue_entry *qe;
   assert(q);

   qe = q->head;

   for( ; qe && ((qe->type != type) || (qe->id != id)); qe = qe->next);

  
   if(qe == q->head || qe == q->tail) {
      if(qe == q->head) {
	 q->head = qe->next;
	 if(q->head)
	    q->head->prev = NULL;
      }
      
      if(qe == q->tail) {
	 q->tail = qe->prev;
	 if(q->tail)
	    q->tail->next = NULL;
      }
   }
   else if(qe) {
      qe->prev->next = qe->next;
      qe->next->prev = qe->prev;
   }
   else
      return ERR;

   q->size--;
   free(qe);
   return OK;
}
struct timeval time_to_next_event(queue *q)
{
   struct timeval now;

   timevalclear(&now);
   
   if(q->head) {
      gettimeofday(&now, NULL);

      timevalsub(&now, &(q->head->time)); 
   }

   return now;
}

int compare_time(const struct timeval t1, const struct timeval t2)
{
   if(t1.tv_sec < t2.tv_sec)    return -1;
   if(t1.tv_sec > t2.tv_sec)    return 1;
   if(t1.tv_usec < t2.tv_usec)  return -1;
   if(t1.tv_usec > t2.tv_usec)  return 1;
   return 0;
}
