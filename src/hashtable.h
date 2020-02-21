typedef struct _HTBL_ENTRY {
    struct _HTBL_ENTRY *next;
    void *data;
    char key[0];
} HTBL_ENTRY, *PHTBL_ENTRY;

typedef struct {
    unsigned int count;
    unsigned int key_size;
    PHTBL_ENTRY table[0];
} HTBL, *PHTBL;

PHTBL htbl_create(unsigned int count, unsigned int key_size);
void htbl_insert(PHTBL t, void *key, void *data);
void* htbl_search(PHTBL t, void *key);
int htbl_remove(PHTBL t, void *key);
void htbl_destroy(PHTBL t);
