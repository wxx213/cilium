/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/ctx.h>
#include <linux/bpf.h>

#include "common.h"
#include "time.h"
#include "edt.h"
#include "bw_stats.h"

/* For now the map is not thread safe, may add spin lock in the future */

#if defined(ENABLE_BANDWIDTH_MANAGER) && __ctx_is == __ctx_skb
static __always_inline int accept(struct __ctx_buff *ctx, __u32 ep_id)
{
	__u64 tokens, now, t_last, elapsed_time, bps;
	struct edt_id aggregate = {};
	struct edt_info *info;
	__u32 ret = CTX_ACT_OK;

	aggregate.id = ep_id;
	if (!aggregate.id)
		return CTX_ACT_OK;

	aggregate.direction = DIRECTION_INGRESS;

	info = map_lookup_elem(&cilium_throttle, &aggregate);
	if (!info)
		return CTX_ACT_OK;
	if (!info->bps)
		return CTX_ACT_OK;

	now = ktime_get_ns();

	bps = READ_ONCE(info->bps);
	t_last = READ_ONCE(info->t_last);
	tokens = READ_ONCE(info->tokens);
	elapsed_time = now - t_last;
	if (elapsed_time > 0) {
		tokens += (bps * elapsed_time / NSEC_PER_SEC);
		if (tokens > bps)
			tokens = bps;
	}
	if (tokens >= ctx_wire_len(ctx))
		tokens -= ctx_wire_len(ctx);
	else
		ret = CTX_ACT_DROP;
	WRITE_ONCE(info->t_last, now);
	WRITE_ONCE(info->tokens, tokens);
	return ret;
}

/* accept_v2 - 按流量组入流量限速
 * @ctx: 数据包上下文
 * @ep_id: endpoint ID
 * @group_id: 流量组 ID (从源 IP 查询获得)
 *
 * 使用 Token Bucket 算法进行入流量限速
 * 同时更新带宽统计
 */
static __always_inline int accept_v2(struct __ctx_buff *ctx, __u32 ep_id, __u16 group_id)
{
	__u64 tokens, now, t_last, elapsed_time, bps;
	struct edt_id_v2 aggregate = {};
	struct edt_info *info;
	__u32 ret = CTX_ACT_OK;

	if (!ep_id || !group_id)
		return CTX_ACT_OK;

	aggregate.endpoint_id = ep_id;
	aggregate.group_id = group_id;
	aggregate.direction = DIRECTION_INGRESS;

	info = map_lookup_elem(&cilium_throttle_v2, &aggregate);
	if (!info)
		return CTX_ACT_OK;
	if (!info->bps)
		return CTX_ACT_OK;

	now = ktime_get_ns();

	bps = READ_ONCE(info->bps);
	t_last = READ_ONCE(info->t_last);
	tokens = READ_ONCE(info->tokens);
	elapsed_time = now - t_last;
	if (elapsed_time > 0) {
		tokens += (bps * elapsed_time / NSEC_PER_SEC);
		if (tokens > bps)
			tokens = bps;
	}
	if (tokens >= ctx_wire_len(ctx)) {
		tokens -= ctx_wire_len(ctx);
		/* 更新带宽统计 */
		update_bw_stats(ep_id, group_id, DIRECTION_INGRESS, ctx_wire_len(ctx));
	} else {
		ret = CTX_ACT_DROP;
	}
	WRITE_ONCE(info->t_last, now);
	WRITE_ONCE(info->tokens, tokens);
	return ret;
}
#else
static __always_inline int
accept(struct __ctx_buff *ctx __maybe_unused, __u32 ep_id __maybe_unused)
{
	return CTX_ACT_OK;
}

static __always_inline int
accept_v2(struct __ctx_buff *ctx __maybe_unused, __u32 ep_id __maybe_unused,
	  __u16 group_id __maybe_unused)
{
	return CTX_ACT_OK;
}
#endif /* ENABLE_BANDWIDTH_MANAGER */

