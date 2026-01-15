// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

// Package trafficgroupmap 提供流量组 BPF Map 的 Go 操作接口
// 用于将 CIDR 映射到流量组 ID
package trafficgroupmap

import (
	"fmt"
	"log/slog"
	"net"
	"unsafe"

	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
)

const (
	// MapName 是 BPF Map 的名称
	MapName = "cilium_traffic_group"
	// MapSize 是 Map 的最大条目数
	MapSize = 4096
)

// 地址族常量
const (
	FamilyIPv4 uint8 = unix.AF_INET
	FamilyIPv6 uint8 = unix.AF_INET6
)

// Key 表示流量组 Map 的键
// 内存布局必须与 BPF 侧 traffic_group_key 保持一致
type Key struct {
	Prefixlen uint32   `align:"lpm_key"`
	Pad0      uint16   `align:"pad0"`
	Pad1      uint8    `align:"pad1"`
	Family    uint8    `align:"family"`
	IP        [16]byte `align:"ip6"` // 16 bytes for both IPv4 and IPv6
}

// String 返回键的字符串表示
func (k *Key) String() string {
	if k.Family == FamilyIPv4 {
		return fmt.Sprintf("%s/%d", net.IP(k.IP[:4]).String(), k.Prefixlen-64)
	}
	return fmt.Sprintf("%s/%d", net.IP(k.IP[:]).String(), k.Prefixlen-64)
}

// Value 表示流量组 Map 的值
type Value struct {
	GroupID uint16   `align:"group_id"`
	Pad     [2]uint8 `align:"pad"`
}

// String 返回值的字符串表示
func (v *Value) String() string {
	return fmt.Sprintf("group=%d", v.GroupID)
}

// TrafficGroupMap 接口定义流量组 Map 的操作
type TrafficGroupMap interface {
	InsertCIDR(cidr *net.IPNet, groupID uint16) error
	DeleteCIDR(cidr *net.IPNet) error
	LookupCIDR(cidr *net.IPNet) (uint16, error)
}

type trafficGroupMap struct {
	bpfMap *ebpf.Map
}

func newMap(logger *slog.Logger) *trafficGroupMap {
	return &trafficGroupMap{
		bpfMap: ebpf.NewMap(logger, &ebpf.MapSpec{
			Name:       MapName,
			Type:       ebpf.LPMTrie,
			KeySize:    uint32(unsafe.Sizeof(Key{})),
			ValueSize:  uint32(unsafe.Sizeof(Value{})),
			MaxEntries: MapSize,
			Flags:      unix.BPF_F_NO_PREALLOC,
			Pinning:    ebpf.PinByName,
		}),
	}
}

// NewMap 创建一个新的 Map 实例
func NewMap(lc cell.Lifecycle, logger *slog.Logger) bpf.MapOut[TrafficGroupMap] {
	m := newMap(logger)
	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			return m.bpfMap.OpenOrCreate()
		},
		OnStop: func(cell.HookContext) error {
			return m.bpfMap.Close()
		},
	})
	return bpf.NewMapOut(TrafficGroupMap(m))
}

// InsertCIDR 插入一个 CIDR 到流量组的映射
func (m *trafficGroupMap) InsertCIDR(cidr *net.IPNet, groupID uint16) error {
	key := cidrToKey(cidr)
	value := &Value{GroupID: groupID}
	return m.bpfMap.Update(key, value, 0)
}

// DeleteCIDR 删除一个 CIDR 映射
func (m *trafficGroupMap) DeleteCIDR(cidr *net.IPNet) error {
	key := cidrToKey(cidr)
	return m.bpfMap.Delete(key)
}

// cidrToKey 将 CIDR 转换为 Map Key
func cidrToKey(cidr *net.IPNet) *Key {
	key := &Key{}
	ones, _ := cidr.Mask.Size()

	if ip4 := cidr.IP.To4(); ip4 != nil {
		// IPv4
		key.Family = FamilyIPv4
		// prefixlen = static_prefix (64 bits) + actual_prefix
		key.Prefixlen = 64 + uint32(ones)
		copy(key.IP[:4], ip4)
	} else {
		// IPv6
		key.Family = FamilyIPv6
		key.Prefixlen = 64 + uint32(ones)
		copy(key.IP[:], cidr.IP.To16())
	}

	return key
}

// LookupCIDR 查询 CIDR 对应的流量组
func (m *trafficGroupMap) LookupCIDR(cidr *net.IPNet) (uint16, error) {
	key := cidrToKey(cidr)
	var value Value
	err := m.bpfMap.Lookup(key, &value)
	if err != nil {
		return 0, err
	}
	return value.GroupID, nil
}
