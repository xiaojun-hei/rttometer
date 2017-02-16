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
 * Hash table implementation
 */

#ifndef __HASHTABLE_H__
#define __HASHTABLE_H__

#include <stdio.h>
#include <assert.h>

#ifndef OK
#define OK 1
#endif

#ifndef ERR
#define ERR 0
#endif

typedef struct hashentry {
   unsigned int key;
   const void *data;
   struct hashentry *next;
} hashentry;


typedef struct hashtable {
   hashentry **table;
   unsigned int size;
   unsigned int inserted;
   unsigned int (*h)(const void *key);      /* hash function for remove, insert..ect. */
   unsigned int (*hl)(const void *key);     /* hash function for lookup only */
   int (*match)(const void *key1, const void *key2);
   int (*matchl)(const void *key1, const void *key2);
   void (*destroy)(const void *record);
} hashtable;

hashtable *hashtable_new(unsigned int size, unsigned int (*h)(const void *key), int (*match)(const void *key1, const void *key2), void (*destroy)(const void *record));
int hashtable_insert(hashtable *ht, const void *data);
int hashtable_remove(hashtable *ht, const void *data);
void *hashtable_lookup(hashtable *ht, unsigned int key);
void hashtable_destroy(hashtable *ht);
   

#endif
