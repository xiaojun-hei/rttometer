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
 * Set of functions to calculate the statistical mode
 */

#include <stdlib.h>
#include <assert.h>
#include "hashtable.h"

#define CEIL(x) ( ((unsigned int) ((x) + 0.5)) > (unsigned int) (x)? (unsigned int) ((x) + 0.5):(unsigned int)(x))

typedef struct mode_node {
   unsigned int key;
   unsigned int cnt;
} mode_node;

unsigned int get_node_key(const void *node)
{
   mode_node *n = (mode_node *) node;
   return(n->key);
}

int match_node(const void *node1, const void *node2)
{
   mode_node *n1, *n2;

   n1 = (mode_node *) node1;
   n2 = (mode_node *) node2;

   if(n1->key < n2->key) return -1;
   if(n1->key > n2->key) return 1;

   return 0;
}

void destroy(const void *record)
{
   mode_node *n = (mode_node *) record;

   free(n);
}

/* Calaculate the mode of an array of values with length len */

float mode(double *array, int len)
{
	int i;
	float mode = -1.0;
	unsigned int max_cnt = 0;
	unsigned int val;
	char dbl_precision;
	
	hashtable *vh;
	mode_node *p;
	unsigned int key;
	
	assert(array);
	if (len <= 0)
	   return mode;

	vh = hashtable_new(len, get_node_key, match_node, destroy);

	/* If the RTTs are very small (i.e., less than 1 ms), make double digitis mode
	   precision, otherwise make it a single digit precision */
	/* NOTE: I assume that array is sorted. Which is true, because I call mode()
	   after I qsort the array
	*/
	dbl_precision = (array[0] < 1.0)? 1:0;
	
	for(i=0; i < len; i++) {
	   
	   /* I am using a single digit precision by default, except when the values
	    of RTTs are really small (<1.0ms) */
	   key = dbl_precision? CEIL(array[i] * 100):CEIL(array[i] * 10);
	   
	   p = hashtable_lookup(vh, key);
	   if (!p) {
	      p = (mode_node *) calloc(1, sizeof(mode_node));
	      assert(p);
	      p->key = key;
	      hashtable_insert(vh, (const void *) p);
	   }

	   p->cnt++;

	   if(p->cnt > max_cnt) {
	      /* we have a mode here */
	      max_cnt = p->cnt;
	      val = key;
	   }
	   /* TODO: detect multiple modes */
	}


	/* The mode should be repeated more than once! */
	/* Just in case we don't have any mode at all */
	if ( max_cnt > 1 ) 
	   mode = dbl_precision? (float) val/100:(float) val/10;

	hashtable_destroy(vh);
		
	return mode;
}
