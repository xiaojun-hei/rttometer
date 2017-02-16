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

#ifndef __QUEUE_H__
#define __QUEUE_H__

#include <sys/time.h>
#include <stdlib.h>

#ifndef OK
#define OK 1
#endif

#ifndef ERR
#define ERR 0
#endif

#define timevalsub(vvp, uvp)                                           \
        do {                                                            \
                (vvp)->tv_sec -= (uvp)->tv_sec;                         \
                (vvp)->tv_usec -= (uvp)->tv_usec;                       \
                if ((vvp)->tv_usec < 0) {                               \
                        (vvp)->tv_sec--;                                \
                        (vvp)->tv_usec += 1000000;                      \
                }                                                       \
        } while (0)


#ifndef timevalclear
#define timevalclear(tvp)   (tvp)->tv_sec = (tvp)->tv_usec = 0
#endif

typedef struct queue_entry{
   int type;
   unsigned int id;
   struct timeval time;
   struct queue_entry *next, *prev;
} queue_entry;


typedef struct queue {
   queue_entry *head, *tail;
   unsigned long size;
} queue;

queue_entry *create_qentry(int type, struct timeval time, unsigned int id);
int queue_insert(queue *q, queue_entry *qe);
queue_entry *get_first_entry(queue *q);
int queue_remove(queue *q, int type, unsigned int id);
struct timeval time_to_next_event(queue *q);
int compare_time(const struct timeval t1, const struct timeval t2);


#endif
