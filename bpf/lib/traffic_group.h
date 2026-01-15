/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* 基于 CIDR 的流量分组功能
 * 
 * 该文件定义了流量组 LPM Map 及相关查询函数，用于将目标 IP 地址
 * 映射到对应的流量组 ID，支持按 CIDR 进行流量分类和限速。
 */

#pragma once

#include "common.h"
#include "ipv6.h"

/* 流量组 Map 最大条目数 */
#define TRAFFIC_GROUP_MAP_SIZE 4096

/* 流量组 Key 结构 (用于 LPM Trie 查询)
 * 内存布局必须与 subnet_key 保持一致
 */
struct traffic_group_key {
	struct bpf_lpm_trie_key lpm_key;
	__u16 pad0;
	__u8  pad1;
	__u8  family;      /* ENDPOINT_KEY_IPV4 / ENDPOINT_KEY_IPV6 */
	union {
		struct {
			__be32 ip4;
			__u32  pad2;
			__u32  pad3;
			__u32  pad4;
		};
		union v6addr ip6;
	};
} __packed;

/* 流量组 Value 结构 */
struct traffic_group_value {
	__u16 group_id;    /* 流量组 ID (0 = 默认/未匹配) */
	__u16 pad;
};

/* CIDR -> 流量组 ID Map (LPM Trie) */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct traffic_group_key);
	__type(value, struct traffic_group_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, TRAFFIC_GROUP_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_traffic_group __section_maps_btf;

/* 计算 LPM Key 的静态前缀长度 (非 IP 部分) */
#define TRAFFIC_GROUP_STATIC_PREFIX						\
	(8 * (sizeof(struct traffic_group_key) - sizeof(struct bpf_lpm_trie_key)	\
	      - sizeof(union v6addr)))
#define TRAFFIC_GROUP_PREFIX_LEN(PREFIX) (TRAFFIC_GROUP_STATIC_PREFIX + (PREFIX))

#define V4_TRAFFIC_GROUP_KEY_LEN (sizeof(__be32) * 8)
#define V6_TRAFFIC_GROUP_KEY_LEN (sizeof(union v6addr) * 8)

/* 根据 IPv4 目标地址查询流量组 ID
 * 
 * @param dest_ip: 目标 IPv4 地址 (网络字节序)
 * @return: 流量组 ID，0 表示未匹配任何流量组
 */
static __always_inline __maybe_unused __u16
lookup_traffic_group4(__be32 dest_ip)
{
	__u32 prefix = V4_TRAFFIC_GROUP_KEY_LEN;
	struct traffic_group_value *val;
	struct traffic_group_key key = {
		.lpm_key.prefixlen = TRAFFIC_GROUP_PREFIX_LEN(prefix),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = dest_ip,
	};

	val = map_lookup_elem(&cilium_traffic_group, &key);
	if (val)
		return val->group_id;

	return 0;  /* 默认组 */
}

/* 根据 IPv6 目标地址查询流量组 ID
 * 
 * @param dest_ip: 目标 IPv6 地址
 * @return: 流量组 ID，0 表示未匹配任何流量组
 */
static __always_inline __maybe_unused __u16
lookup_traffic_group6(const union v6addr *dest_ip)
{
	__u32 prefix = V6_TRAFFIC_GROUP_KEY_LEN;
	struct traffic_group_value *val;
	struct traffic_group_key key = {
		.lpm_key.prefixlen = TRAFFIC_GROUP_PREFIX_LEN(prefix),
		.family = ENDPOINT_KEY_IPV6,
		.ip6 = *dest_ip,
	};

	val = map_lookup_elem(&cilium_traffic_group, &key);
	if (val)
		return val->group_id;

	return 0;  /* 默认组 */
}
