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
	struct ktls_offload_context *context = sk->sk_tls_offload;
	struct tcp_sock *tp = tcp_sk(sk);
	struct tls_record_info *info, *temp;
	u32 end_seq;
	unsigned long flags;

	spin_lock_irqsave(&context->lock, flags);
	list_for_each_entry_safe(info, temp, &context->records_list, list) {
		end_seq = info->start_seq + info->len;
		if (before(tp->snd_una, end_seq) && !closing_sk)
			break;
		list_del(&info->list);

		pr_info("releasing record seq=%u\n", info->start_seq);

		tls_destroy_record(info);
	}
	spin_unlock_irqrestore(&context->lock, flags);
}

struct tls_record_info *ktls_get_record(
			struct ktls_offload_context *context,
			u32 seq) {
	struct tls_record_info *info;

	list_for_each_entry(info, &context->records_list, list) {
		u32 end_seq = info->start_seq + info->len;

		if (before(seq, end_seq))
			return info;
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
	record->start_seq = tp->write_seq;

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

	pr_info("new record added %u\n", record->start_seq);
	return ret;
}
EXPORT_SYMBOL(tls_send_record);

struct tcp_offload_ops tls_offload_ops = {
	clean_offloaded_data,
	NULL
};
EXPORT_SYMBOL(tls_offload_ops);
