// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bandwidth

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/maps/bwstatsmap"
	"github.com/cilium/cilium/pkg/trafficgroup"
)

// TrafficGroupStats 表示流量组统计接口
type TrafficGroupStats interface {
	// CollectStats 收集所有流量组的带宽统计
	CollectStats() ([]GroupBandwidthStats, error)
}

// GroupBandwidthStats 表示单个流量组的带宽统计
type GroupBandwidthStats struct {
	EndpointID uint32
	GroupID    uint16
	GroupName  string
	Direction  string // "egress" or "ingress"
	Bytes      uint64
	Packets    uint64
}

// statsCollector 实现统计收集
type statsCollector struct {
	bwStatsMap bwstatsmap.BwStatsMap
	tgManager  *trafficgroup.Manager
}

// NewStatsCollector 创建统计收集器
func NewStatsCollector(bwStatsMap bwstatsmap.BwStatsMap, tgManager *trafficgroup.Manager) TrafficGroupStats {
	return &statsCollector{
		bwStatsMap: bwStatsMap,
		tgManager:  tgManager,
	}
}

// CollectStats 收集所有统计数据
func (c *statsCollector) CollectStats() ([]GroupBandwidthStats, error) {
	if c.bwStatsMap == nil {
		return nil, nil
	}

	var result []GroupBandwidthStats

	err := c.bwStatsMap.IterateWithCallback(func(key *bwstatsmap.Key, values *bwstatsmap.Values) {
		// 获取流量组名称
		groupName := ""
		if c.tgManager != nil {
			if name, ok := c.tgManager.GetGroupName(key.GroupID); ok {
				groupName = name
			}
		}

		// 转换方向
		direction := "egress"
		if key.Direction == bwstatsmap.DirectionIngress {
			direction = "ingress"
		}

		result = append(result, GroupBandwidthStats{
			EndpointID: key.EndpointID,
			GroupID:    key.GroupID,
			GroupName:  groupName,
			Direction:  direction,
			Bytes:      values.Bytes(),
			Packets:    values.Packets(),
		})
	})

	if err != nil {
		return nil, fmt.Errorf("收集 BPF 统计失败: %w", err)
	}

	return result, nil
}

// Metrics 定义 Prometheus 指标
var (
	bandwidthBytesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "cilium",
			Subsystem: "bw",
			Name:      "bytes_total",
			Help:      "Total bytes by endpoint, group, direction",
		},
		[]string{"endpoint", "group", "direction"},
	)
)

// RegisterMetrics 注册 Prometheus 指标
func RegisterMetrics() {
	prometheus.MustRegister(bandwidthBytesTotal)
}

// ExportMetrics 导出统计到 Prometheus
func ExportMetrics(stats []GroupBandwidthStats) {
	for _, s := range stats {
		groupLabel := s.GroupName
		if groupLabel == "" {
			groupLabel = fmt.Sprintf("%d", s.GroupID)
		}

		bandwidthBytesTotal.WithLabelValues(
			fmt.Sprintf("%d", s.EndpointID),
			groupLabel,
			s.Direction,
		).Add(float64(s.Bytes))
	}
}
