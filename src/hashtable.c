uintptr_t htbl_hash_data(uintptr_t seed, void* data, size_t len)
{
	unsigned char *ptr = data;
	for(size_t i = 0; i < len; i++) {
		seed = seed * 0xdead1337 - ptr[i] * 0x13579bdf + 0xf33d1ee7;
		// seed = seed ^ (seed >> 7) ^ (ptr[i] << 19);
	}
    return seed;
}

PHTBL htbl_create(unsigned int count, unsigned int key_size)
{
    PHTBL t = malloc(sizeof(HTBL) + sizeof(PHTBL_ENTRY) * count);
    t->count = count;
    t->key_size = key_size;

    for (int i = 0; i < count; i++)
        t->table[i] = NULL;

    return t;
}

void htbl_insert(PHTBL t, void *key, void *data)
{
    PHTBL_ENTRY node = malloc(sizeof(HTBL_ENTRY) + t->key_size);
    memcpy(node->key, key, t->key_size);
    node->data = data;

    uintptr_t index = htbl_hash_data(0, key, t->key_size) % t->count;
    node->next = t->table[index];
    t->table[index] = node;
}

void* htbl_search(PHTBL t, void *key)
{
    uintptr_t index = htbl_hash_data(0, key, t->key_size) % t->count;
    for (PHTBL_ENTRY node = t->table[index];
         node != NULL;
         node = node->next)
    {
        if (memcmp(node->data, key, t->key_size) == 0)
            return node->data;
    }

    return NULL;
}

int htbl_remove(PHTBL t, void *key)
{
    uintptr_t index = htbl_hash_data(0, key, t->key_size) % t->count;
    PHTBL_ENTRY prev = NULL;

    for (PHTBL_ENTRY node = t->table[index];
         node != NULL;
         node = node->next)
    {
        if (memcmp(node->key, key, t->key_size) == 0) {
            if(prev == NULL) {
                t->table[index] = node->next;
            } else {
                prev->next = node->next;
            }

            free(node);

            return 1;
        }
        prev = node;
    }

    return 0;
}

void htbl_destroy(PHTBL t)
{
    for (int i = 0; i < t->count; i++)
    {
        PHTBL_ENTRY node = t->table[i], next;
        while (node)
        {
            next = node->next;
            free(node);
            node = next;
        }
    }
    free(t);
}
