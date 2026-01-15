/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* 带宽统计功能
 * 
 * 该文件定义了带宽统计 Map 及相关更新函数，用于按流量组统计
 * 每个 Endpoint 的流量字节数和包数。
 */

#pragma once

#include "common.h"

/* 带宽统计 Map 最大条目数 */
#define BW_STATS_MAP_SIZE 65536

/* 带宽统计 Key 结构 */
struct bw_stats_key {
	__u32 endpoint_id;  /* Endpoint ID */
	__u16 group_id;     /* 流量组 ID */
	__u8  direction;    /* 0: Egress, 1: Ingress */
	__u8  pad;
};

/* 带宽统计 Value 结构 (PerCPU) */
struct bw_stats_value {
	__u64 bytes;        /* 累计字节数 */
	__u64 packets;      /* 累计包数 */
};

/* 带宽统计 Map (PerCPU Hash)
 * 
 * 使用 PerCPU 类型避免多 CPU 并发更新时的锁竞争
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct bw_stats_key);
	__type(value, struct bw_stats_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, BW_STATS_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_bw_stats __section_maps_btf;

/* 更新带宽统计
 * 
 * @param endpoint_id: Endpoint ID
 * @param group_id: 流量组 ID
 * @param direction: 方向 (0: Egress, 1: Ingress)
 * @param bytes: 本次传输的字节数
 */
static __always_inline void
update_bw_stats(__u32 endpoint_id, __u16 group_id, __u8 direction, __u64 bytes)
{
	struct bw_stats_key key = {
		.endpoint_id = endpoint_id,
		.group_id = group_id,
		.direction = direction,
	};
	struct bw_stats_value *val;

	val = map_lookup_elem(&cilium_bw_stats, &key);
	if (val) {
		/* 条目已存在，直接更新 */
		val->bytes += bytes;
		val->packets += 1;
	} else {
		/* 条目不存在，创建新条目 */
		struct bw_stats_value new_val = {
			.bytes = bytes,
			.packets = 1,
		};
		map_update_elem(&cilium_bw_stats, &key, &new_val, BPF_ANY);
	}
}
