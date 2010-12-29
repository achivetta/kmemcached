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
  atomic_t refcount;
  struct rcu_head rcu_head;
  struct item* h_next;
} item_t;

bool initialize_storage(void);
void shutdown_storage(void);

item_t* create_item(const char* key, size_t nkey, const char* data,
                    size_t size, uint32_t flags, time_t exp);
item_t* clone_item(item_t *item);
item_t* get_item(const char* key, size_t nkey); 
int delete_item(const char* key, size_t nkey, uint64_t cas);
bool add_item(item_t* it);
int replace_item(item_t* item, uint64_t cas);
void set_item(item_t* item);
void flush(uint32_t when);
void release_item(item_t* item);

#endif
