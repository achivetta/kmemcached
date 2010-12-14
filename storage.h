/* -*- Mode: C; tab-width: 2; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#ifndef STORAGE_H
#define STORAGE_H

typedef struct item {
  uint64_t cas;
  char* key;
  size_t nkey;
  char* data;
  size_t size;
  uint32_t flags;
  time_t exp;
  struct item* h_next;
} item_t;

bool initialize_storage(void);
void shutdown_storage(void);

item_t* create_item(const char* key, size_t nkey, const char* data,
                         size_t size, uint32_t flags, time_t exp);

void put_item(item_t* item);
item_t* get_item(const char* key, size_t nkey);
bool delete_item(const char* key, size_t nkey);
void flush(uint32_t when);
void free_item(item_t* item);
void release_item(item_t* item); // For use when ref counting/locking

#endif
