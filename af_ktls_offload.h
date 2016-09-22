#ifndef AF_KTLS_OFFLOAD_H_
#define AF_KTLS_OFFLOAD_H_

#include <linux/types.h>

#include "af_ktls.h"

struct tls_record_info {
	struct list_head list;
	u32 start_seq;
	int len;
	int num_frags;
	skb_frag_t	frags[MAX_SKB_FRAGS];
};

struct ktls_key {
	char key[KTLS_AES_GCM_128_KEY_SIZE];
	char salt[KTLS_AES_GCM_128_SALT_SIZE];
	char iv[KTLS_AES_GCM_128_IV_SIZE];
};

struct ktls_keys {
	struct ktls_key tx;
	struct ktls_key rx;
};

extern struct tcp_offload_ops tls_offload_ops;

struct ktls_offload_context {
	struct list_head records_list;
	u32 expectedSN;
	spinlock_t lock; /* protects records list */
};

void tls_destroy_record(struct tls_record_info *record);
int tls_send_record(struct sock *sk, struct tls_record_info *record);

struct tls_record_info *ktls_get_record(
			struct ktls_offload_context *context,
			u32 seq);

#endif /* AF_KTLS_OFFLOAD_H_ */
