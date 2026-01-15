// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

// Package bwstatsmap 提供带宽统计 BPF Map 的 Go 操作接口
// 用于收集每个流量组的带宽使用统计
package bwstatsmap

import (
	"fmt"
	"log/slog"
	"unsafe"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
)

const (
	// MapName 是 BPF Map 的名称
	MapName = "cilium_bw_stats"
	// MapSize 是 Map 的最大条目数
	MapSize = 65536
)

// 方向常量
const (
	DirectionEgress  uint8 = 0
	DirectionIngress uint8 = 1
)

// Key 表示统计 Map 的键
type Key struct {
	EndpointID uint32 `align:"endpoint_id"`
	GroupID    uint16 `align:"group_id"`
	Direction  uint8  `align:"direction"`
	Pad        uint8  `align:"pad"`
}

// String 返回键的字符串表示
func (k *Key) String() string {
	dir := "egress"
	if k.Direction == DirectionIngress {
		dir = "ingress"
	}
	return fmt.Sprintf("ep=%d group=%d dir=%s", k.EndpointID, k.GroupID, dir)
}

// Value 表示统计 Map 的值 (单个 CPU 的值)
type Value struct {
	Bytes   uint64 `align:"bytes"`
	Packets uint64 `align:"packets"`
}

// String 返回值的字符串表示
func (v *Value) String() string {
	return fmt.Sprintf("bytes=%d packets=%d", v.Bytes, v.Packets)
}

// Values 是 Value 的切片，用于 PerCPU Map
type Values []Value

// Bytes 返回所有 CPU 的字节总和
func (vs Values) Bytes() uint64 {
	var total uint64
	for _, v := range vs {
		total += v.Bytes
	}
	return total
}

// Packets 返回所有 CPU 的包数总和
func (vs Values) Packets() uint64 {
	var total uint64
	for _, v := range vs {
		total += v.Packets
	}
	return total
}

// IterateCallback 是迭代回调函数签名
type IterateCallback func(*Key, *Values)

// BwStatsMap 接口定义带宽统计 Map 的操作
type BwStatsMap interface {
	IterateWithCallback(IterateCallback) error
}

type bwStatsMap struct {
	bpfMap *ebpf.Map
}

func newMap(logger *slog.Logger) *bwStatsMap {
	return &bwStatsMap{
		bpfMap: ebpf.NewMap(logger, &ebpf.MapSpec{
			Name:       MapName,
			Type:       ebpf.PerCPUHash,
			KeySize:    uint32(unsafe.Sizeof(Key{})),
			ValueSize:  uint32(unsafe.Sizeof(Value{})),
			MaxEntries: MapSize,
			Pinning:    ebpf.PinByName,
		}),
	}
}

// NewMap 创建一个新的 Map 实例
func NewMap(lc cell.Lifecycle, logger *slog.Logger) bpf.MapOut[BwStatsMap] {
	m := newMap(logger)
	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			return m.bpfMap.OpenOrCreate()
		},
		OnStop: func(cell.HookContext) error {
			return m.bpfMap.Close()
		},
	})
	return bpf.NewMapOut(BwStatsMap(m))
}

// IterateWithCallback 迭代 Map 中所有键值对
func (m *bwStatsMap) IterateWithCallback(cb IterateCallback) error {
	return m.bpfMap.IterateWithCallback(&Key{}, &Values{}, func(k, v any) {
		key := k.(*Key)
		values := v.(*Values)
		cb(key, values)
	})
}

// Stats 表示聚合后的统计数据
type Stats struct {
	EndpointID uint32
	GroupID    uint16
	Direction  uint8
	Bytes      uint64
	Packets    uint64
}

// CollectStats 收集所有统计数据并聚合 PerCPU 值
func (m *bwStatsMap) CollectStats() ([]Stats, error) {
	var allStats []Stats

	err := m.IterateWithCallback(func(key *Key, values *Values) {
		allStats = append(allStats, Stats{
			EndpointID: key.EndpointID,
			GroupID:    key.GroupID,
			Direction:  key.Direction,
			Bytes:      values.Bytes(),
			Packets:    values.Packets(),
		})
	})

	if err != nil {
		return nil, fmt.Errorf("收集统计失败: %w", err)
	}

	return allStats, nil
}
