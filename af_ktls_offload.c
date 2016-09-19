#include <net/tcp.h>
#include "af_ktls_offload.h"

void tls_destroy_record(struct tls_record_info *record)
{
	skb_frag_t *frag;
	pr_info("releasing record seq=%u\n", record->end_seq);

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
	struct ktls_offload_context *context = sk->sk_tls_offload;
	struct tcp_sock *tp = tcp_sk(sk);
	struct tls_record_info *info, *temp;
	unsigned long flags;

	spin_lock_irqsave(&context->lock, flags);
	info = context->retransmit_hint;
	if (info &&
	    !before(tp->snd_una, info->end_seq)) {
		context->retransmit_hint = NULL;
		list_del(&info->list);
		tls_destroy_record(info);
	}

	list_for_each_entry_safe(info, temp, &context->records_list, list) {
		if (before(tp->snd_una, info->end_seq) && !closing_sk)
			break;
		list_del(&info->list);

		tls_destroy_record(info);
	}

	spin_unlock_irqrestore(&context->lock, flags);
}

struct tls_record_info *ktls_get_record(
			struct ktls_offload_context *context,
			u32 seq) {
	struct tls_record_info *info;

	info = context->retransmit_hint;
	if (!info ||
	    before(seq, info->end_seq - info->len))
		info = list_first_entry(&context->records_list,
					struct tls_record_info, list);

	list_for_each_entry_from(info, &context->records_list, list) {
		if (before(seq, info->end_seq)) {
			context->retransmit_hint = info;
			return info;
		}
	}

	return NULL;
}
EXPORT_SYMBOL(ktls_get_record);

int tls_send_record(struct sock *sk, struct tls_record_info *record)
{
	struct ktls_offload_context *context = sk->sk_tls_offload;
	struct tcp_sock *tp = tcp_sk(sk);
	int i = 0;
	skb_frag_t *frag;
	int flags = MSG_SENDPAGE_NOTLAST;
	int ret = 0;

	lock_sock(sk);
	record->end_seq = tp->write_seq + record->len;

	spin_lock_irq(&context->lock);
	list_add_tail(&record->list, &context->records_list);
	spin_unlock_irq(&context->lock);

	while (flags == MSG_SENDPAGE_NOTLAST) {
		frag = &record->frags[i];

		i++;
		if (i == record->num_frags)
			flags = 0;
		ret = do_tcp_sendpages(sk, skb_frag_page(frag),
				       frag->page_offset, skb_frag_size(frag),
				       flags);

		if (ret != skb_frag_size(frag)) {
			pr_err("do_tcp_sendpages sent only part of the frag ret=%d",
			       ret);
		}
	}
	release_sock(sk);

	pr_info("new record added %u\n", record->end_seq);
	return ret;
}
EXPORT_SYMBOL(tls_send_record);

struct tcp_offload_ops tls_offload_ops = {
	clean_offloaded_data,
	NULL
};
EXPORT_SYMBOL(tls_offload_ops);
