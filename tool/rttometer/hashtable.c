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

#include <stdlib.h>
#include <string.h>
#include "hashtable.h"

/*
 * Create a new hashtable
 */

hashtable *hashtable_new(unsigned int size, unsigned int (*h)(const void *key), int (*match)(const void *key1, const void *key2), void (*destroy)(const void *record))
{
   hashtable *ht;
   
   assert(size > 0);
   ht = (hashtable *) calloc(1, sizeof(hashtable));
   assert(ht);

   ht->table = (hashentry **) calloc(size, sizeof(hashentry *));
   assert(ht->table);
   
   ht->size = size;
   ht->h = h;
   ht->match = match;
   ht->destroy = destroy;
   return ht;
}

/*
 * Insert an element into the hash table
 */

int hashtable_insert(hashtable *ht, const void *data)
{
   hashentry *he = (hashentry *) calloc(1, sizeof(hashentry));

   assert(he);
   assert(ht);

   /* Fill the hash entry */
   he->key = ht->h(data);
   he->data = data;

   /* Insert into the table */
   he->next = ht->table[he->key % ht->size];
   ht->table[he->key % ht->size] = he;

   ht->inserted++;
   return OK;
}

/*
 * Remove an entry from the hash table
 */
int hashtable_remove(hashtable *ht, const void *data)
{
   unsigned int index, key;
   hashentry *he, *p;
   
   assert(ht);

   /* Get the index into the hash table */
   key = ht->h(data);
   index = key % ht->size;

   /* No entry at that bucket */
   if(!ht->table[index])
      return ERR;

   he = ht->table[index];
  
   /* Node at the head? */
   if(ht->match(he->data, data)) {
      ht->table[index] = he->next;
      he->next = NULL;
      free(he);
      ht->inserted--;
      return OK;
   }
   
   while(he->next && !ht->match(he->next->data, data))
      he = he->next;

   if(!he->next)
      return ERR;

   p = he->next;
   he->next = p->next;

   p->next = NULL;
   free(p);
   ht->inserted--;
   return OK;
}

/*
 *  Lookup for an entry in the table
 */ 
void *hashtable_lookup(hashtable *ht, unsigned int key)
{
   unsigned int index;
   hashentry *he;
   
   assert(ht);

   /* Get the index into the hash table */
   index = key % ht->size;

   /* No entry at that bucket */
   if(!ht->table[index])
      return NULL;

   he = ht->table[index];
  
   /* Node at the head? */
   if(he->key == key) {
      return ((void *) he->data);
   }
   
   while(he->next && (he->next->key != key))
      he = he->next;

   if(!he->next)
      return NULL;

  
   return ((void *)he->next->data);
}

/*
 * Destroy the hashtable
 */
void hashtable_destroy(hashtable *ht)
{
   hashentry *he, *p;
   unsigned int i;

   assert(ht);
   
   for(i = 0; i < ht->size; i++){
      if(ht->table[i]) {
	 he = ht->table[i];
	 do {
	    p = he->next;
	    if(ht->destroy)
	       ht->destroy(he->data);
	    free(he);
	    he = p;
	 } while(he);
      }
   }

   free(ht->table);
   memset(ht, 0, sizeof(hashtable));
}
 
   
