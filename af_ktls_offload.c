#include <net/tcp.h>
#include "af_ktls_offload.h"

void tls_destroy_record(struct tls_record_info *record)
{
	skb_frag_t *frag;

	while (record->num_frags > 0) {
		record->num_frags--;
		frag = &record->frags[record->num_frags];
		__skb_frag_unref(frag);
	}
	kfree(record);
}
EXPORT_SYMBOL(tls_destroy_record);

void clean_offloaded_data(struct sock *sk, int closing_sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tls_record_info *info, *temp;
	u32 end_seq;

	list_for_each_entry_safe(info, temp, &tp->offload_list, list) {
		end_seq = info->start_seq + info->len;
		if (before(tp->snd_una, end_seq) && !closing_sk)
			break;
		list_del(&info->list);

		pr_info("releasing record seq=%u\n", info->start_seq);

		tls_destroy_record(info);
	}
}

struct tcp_offload_ops tls_offload_ops = {
	clean_offloaded_data,
};
EXPORT_SYMBOL(tls_offload_ops);
