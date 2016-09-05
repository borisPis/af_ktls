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

static void send_sync_skb(struct sock *sk,
			  struct tls_record_info *info,
			  struct sk_buff *skb, u32 seq)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_sock *inet = inet_sk(sk);
	int headln = skb_transport_offset(skb) + tcp_hdrlen(skb);
	int max_header = sk->sk_prot->max_header;
	struct sk_buff *nskb = alloc_skb(max_header, GFP_ATOMIC);
	int sync_size = 0;
	int mss;

	if (!nskb)
		return;

	nskb->sk = skb->sk;
	skb_reserve(nskb, max_header);

	memcpy(skb_push(nskb, headln), skb->data, headln);
	skb_reset_transport_header(nskb);

	skb_shinfo(nskb)->gso_size = 0;
	skb_shinfo(nskb)->gso_type = skb_shinfo(skb)->gso_type;

	sync_size = seq - info->start_seq;
	if (sync_size) {
		int i;

		if (sync_size >= 1 << 16) {
			pr_err("bad packet %u %u\n", seq, info->start_seq);
			return;
		}

		tcp_hdr(nskb)->seq = htonl(info->start_seq);

		mss = tcp_current_mss(skb->sk);
		if (sync_size > mss) {
			skb_shinfo(nskb)->gso_size = mss;
			skb_shinfo(nskb)->gso_segs = DIV_ROUND_UP(sync_size,
								  mss);
		}

		nskb->len += sync_size;
		nskb->data_len += sync_size;
		i = 0;
		while (sync_size > 0) {
			skb_shinfo(nskb)->frags[i] = info->frags[i];
			skb_frag_ref(nskb, i);
			sync_size -= skb_frag_size(
					&skb_shinfo(nskb)->frags[i]);

			if (sync_size < 0) {
				skb_frag_size_add(
					&skb_shinfo(nskb)->frags[i],
					sync_size);
			}

			i++;
		}
		skb_shinfo(nskb)->nr_frags = i;
	}

	nskb->ooo_okay = skb->ooo_okay;
	skb->ooo_okay = 0;

	nskb->ip_summed = skb->ip_summed;
	icsk->icsk_af_ops->send_check(sk, nskb);

	nskb->sync_skb = 1;
	pr_info("sending sync skb seq [%u-%u)\n",
		info->start_seq, info->start_seq + nskb->data_len);
	icsk->icsk_af_ops->queue_xmit(sk, nskb, &inet->cork.fl);
}

static void tcp_check_sync(struct sock *sk, struct sk_buff *skb,
			   u32 seq, u32 end_seq) {
	struct tls_record_info *info;
	struct tcp_sock *tp = tcp_sk(sk);

	pr_info("tcp_check_sync %u %u\n", tp->expected_seq, seq);

	if (tp->expected_seq == seq || list_empty(&tp->offload_list))
		goto update_expected;

	list_for_each_entry(info, &tp->offload_list, list) {
		u32 end_seq = info->start_seq + info->len;

		if (before(seq, end_seq))
			break;
	}

	send_sync_skb(sk, info, skb, seq);
update_expected:
	tp->expected_seq = end_seq;
}

int tls_send_record(struct sock *sk, struct tls_record_info *record)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int i = 0;
	skb_frag_t *frag;
	int flags = MSG_SENDPAGE_NOTLAST;
	int ret = 0;

	lock_sock(sk);
	record->start_seq = tp->write_seq;
	list_add_tail(&record->list, &tp->offload_list);

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
	tcp_check_sync
};
EXPORT_SYMBOL(tls_offload_ops);
