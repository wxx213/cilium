// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package annotation 提供 Pod 注解解析功能
package annotation

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"
)

const (
	// GroupEgressPrefix 是出口带宽限制注解的前缀（按流量组）
	// 格式: bandwidth.cilium.io/egress-<group_name>: "<limit>"
	GroupEgressPrefix = "bandwidth.cilium.io/egress-"

	// GroupIngressPrefix 是入口带宽限制注解的前缀（按流量组）
	// 格式: bandwidth.cilium.io/ingress-<group_name>: "<limit>"
	GroupIngressPrefix = "bandwidth.cilium.io/ingress-"
)

// Direction 表示流量方向
type Direction string

const (
	DirectionEgress  Direction = "egress"
	DirectionIngress Direction = "ingress"
)

// BandwidthRule 表示一条带宽限制规则
type BandwidthRule struct {
	// GroupName 是流量组名称 (如 "internal", "public")
	GroupName string

	// Direction 是流量方向 ("egress" 或 "ingress")
	Direction Direction

	// Limit 是带宽限制 (bytes/sec)
	Limit uint64
}

// ParseBandwidthAnnotations 解析 Pod 的带宽注解
// 返回解析出的带宽规则列表
//
// 支持的注解格式:
//   - bandwidth.cilium.io/egress-<group>: "<limit>"
//   - bandwidth.cilium.io/ingress-<group>: "<limit>"
//
// limit 支持 K/M/G 单位，如 "100M" = 100 Mbps
func ParseBandwidthAnnotations(annotations map[string]string) ([]BandwidthRule, error) {
	if annotations == nil {
		return nil, nil
	}

	var rules []BandwidthRule

	for key, value := range annotations {
		var direction Direction
		var groupName string

		if strings.HasPrefix(key, GroupEgressPrefix) {
			direction = DirectionEgress
			groupName = strings.TrimPrefix(key, GroupEgressPrefix)
		} else if strings.HasPrefix(key, GroupIngressPrefix) {
			direction = DirectionIngress
			groupName = strings.TrimPrefix(key, GroupIngressPrefix)
		} else {
			continue
		}

		// 跳过空组名
		if groupName == "" {
			continue
		}

		// 解析带宽值
		limit, err := ParseBandwidthValue(value)
		if err != nil {
			return nil, fmt.Errorf("无法解析带宽注解 %s=%s: %w", key, value, err)
		}

		rules = append(rules, BandwidthRule{
			GroupName: groupName,
			Direction: direction,
			Limit:     limit,
		})
	}

	return rules, nil
}

// ParseBandwidthValue 解析带宽值字符串
// 使用 Kubernetes resource.Quantity 格式，返回 bytes/sec
//
// 示例:
//   - "100M" -> 100 * 1000 * 1000 = 100,000,000 bytes/sec (约 800 Mbps)
//   - "1G"   -> 1 * 1000 * 1000 * 1000 = 1,000,000,000 bytes/sec (约 8 Gbps)
//   - "10Mi" -> 10 * 1024 * 1024 = 10,485,760 bytes/sec (约 84 Mbps)
//
// 注意: 这里使用的是字节/秒 (bytes/sec)，不是比特/秒 (bits/sec)
func ParseBandwidthValue(value string) (uint64, error) {
	// 使用 Kubernetes 的 resource.Quantity 解析
	quantity, err := resource.ParseQuantity(value)
	if err != nil {
		return 0, fmt.Errorf("无效的带宽值: %s", value)
	}

	// resource.Quantity 直接返回字节数
	bytesPerSec := uint64(quantity.Value())

	return bytesPerSec, nil
}

// HasBandwidthAnnotations 检查注解中是否包含带宽限制配置
func HasBandwidthAnnotations(annotations map[string]string) bool {
	for key := range annotations {
		if strings.HasPrefix(key, GroupEgressPrefix) || strings.HasPrefix(key, GroupIngressPrefix) {
			return true
		}
	}
	return false
}
