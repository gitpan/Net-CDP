/*
 * $Id: cdp_llist.c,v 1.1.1.1 2004/06/04 06:01:29 mchapman Exp $
 */

#include "cdp.h"

#include <stdlib.h>

cdp_llist_t *
cdp_llist_new(cdp_dup_fn_t dup_fn, cdp_free_fn_t free_fn) {
	cdp_llist_t *llist;

	llist = (cdp_llist_t *)calloc(1, sizeof(cdp_llist_t));
	llist->dup_fn = dup_fn;
	llist->free_fn = free_fn;
	llist->count = 0;
	llist->head = llist->tail = NULL;

	return llist;
}

cdp_llist_t *
cdp_llist_dup(const cdp_llist_t *llist) {
	cdp_llist_t *result;
	cdp_llist_item_t *item;

	result = (cdp_llist_t *)calloc(1, sizeof(cdp_llist_t));
	result->dup_fn = llist->dup_fn;
	result->free_fn = llist->free_fn;
	for (item = llist->head; item; item = item->next)
		cdp_llist_append(result, item->x);
	
	return result;
}

void
cdp_llist_append(cdp_llist_t *llist, const void *x) {
	cdp_llist_item_t *item;
	
	item = (cdp_llist_item_t *)calloc(1, sizeof(cdp_llist_item_t));
	item->x = (*llist->dup_fn)(x);
	if (llist->tail)
		llist->tail->next = item;
	else
		llist->head = item;
	llist->tail = item;
	llist->count++;
}

void
cdp_llist_free(cdp_llist_t *llist) {
	cdp_llist_item_t *item, *next;
	
	for (item = llist->head; item; item = next) {
		next = item->next;
		(*llist->free_fn)(item->x);
		free(item);
	}
	free(llist);
}
