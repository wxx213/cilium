// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

// Package trafficgroup 实现了基于 CIDR 的流量分组功能
// 用于将 Pod 流量按目标地址分类并应用不同的带宽限制
package trafficgroup

import (
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/trafficgroupmap"
)

var log = logging.DefaultSlogLogger.With(logfields.LogSubsys, "trafficgroup")

// Manager 管理流量组的生命周期
// 监听 CiliumTrafficGroup CRD 变化，同步到 BPF Map
type Manager struct {
	mu sync.RWMutex

	// groups 存储所有流量组，key 为 name
	groups map[string]*v2alpha1.CiliumTrafficGroup

	// idToName 存储 ID 到 Name 的映射，用于校验冲突和反查
	idToName map[uint16]string

	// tgMap 是流量组 BPF Map
	tgMap trafficgroupmap.TrafficGroupMap

	// logger
	logger *slog.Logger
}

// NewManager 创建新的流量组管理器
func NewManager(tgMap trafficgroupmap.TrafficGroupMap) *Manager {
	return &Manager{
		groups:   make(map[string]*v2alpha1.CiliumTrafficGroup),
		idToName: make(map[uint16]string),
		tgMap:    tgMap,
		logger:   log,
	}
}

// OnAdd 处理流量组的添加事件
func (m *Manager) OnAdd(tg *v2alpha1.CiliumTrafficGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 校验 ID 冲突
	if existingName, exists := m.idToName[tg.Spec.ID]; exists && existingName != tg.Name {
		return fmt.Errorf("流量组 ID %d 已被 %s 使用，无法分配给 %s", tg.Spec.ID, existingName, tg.Name)
	}

	// 使用 DeepCopy 存储流量组
	m.groups[tg.Name] = tg.DeepCopy()
	m.idToName[tg.Spec.ID] = tg.Name

	m.logger.Info("添加流量组",
		"name", tg.Name,
		"id", tg.Spec.ID,
		"cidrs", len(tg.Spec.CIDRs))

	// 同步到 BPF Map
	return m.syncToBPF(tg)
}

// OnUpdate 处理流量组的更新事件
func (m *Manager) OnUpdate(oldTG, newTG *v2alpha1.CiliumTrafficGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 如果 ID 发生变化，需要检查新 ID 是否冲突
	if oldTG.Spec.ID != newTG.Spec.ID {
		// 检查新 ID 是否被其他组使用
		if existingName, exists := m.idToName[newTG.Spec.ID]; exists && existingName != newTG.Name {
			return fmt.Errorf("流量组 ID %d 已被 %s 使用", newTG.Spec.ID, existingName)
		}
		// 删除旧 ID 映射
		delete(m.idToName, oldTG.Spec.ID)
	}

	// 先删除旧的 CIDRs
	if err := m.deleteFromBPFLocked(oldTG); err != nil {
		m.logger.Warn("删除旧 CIDRs 失败", "error", err)
	}

	// 使用 DeepCopy 更新存储
	m.groups[newTG.Name] = newTG.DeepCopy()
	m.idToName[newTG.Spec.ID] = newTG.Name

	m.logger.Info("更新流量组",
		"name", newTG.Name,
		"id", newTG.Spec.ID,
		"cidrs", len(newTG.Spec.CIDRs))

	// 同步新的 CIDRs 到 BPF Map
	return m.syncToBPF(newTG)
}

// OnDelete 处理流量组的删除事件
func (m *Manager) OnDelete(tg *v2alpha1.CiliumTrafficGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.groups, tg.Name)
	delete(m.idToName, tg.Spec.ID)

	m.logger.Info("删除流量组",
		"name", tg.Name,
		"id", tg.Spec.ID)

	// 从 BPF Map 删除
	return m.deleteFromBPFLocked(tg)
}

// GetGroupID 根据流量组名称获取 ID
func (m *Manager) GetGroupID(name string) (uint16, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tg, exists := m.groups[name]
	if !exists {
		return 0, false
	}
	return tg.Spec.ID, true
}

// GetGroupName 根据流量组 ID 获取名称 (用于 Metrics)
func (m *Manager) GetGroupName(id uint16) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	name, exists := m.idToName[id]
	return name, exists
}

// syncToBPF 将流量组同步到 BPF Map
func (m *Manager) syncToBPF(tg *v2alpha1.CiliumTrafficGroup) error {
	if m.tgMap == nil {
		m.logger.Debug("BPF Map 未初始化，跳过同步",
			"name", tg.Name)
		return nil
	}

	var errs []error
	for _, cidrStr := range tg.Spec.CIDRs {
		_, cidr, err := net.ParseCIDR(string(cidrStr))
		if err != nil {
			m.logger.Warn("无效的 CIDR",
				"cidr", cidrStr,
				"error", err)
			errs = append(errs, err)
			continue
		}

		if err := m.tgMap.InsertCIDR(cidr, tg.Spec.ID); err != nil {
			m.logger.Error("写入 BPF Map 失败",
				"cidr", cidrStr,
				"group_id", tg.Spec.ID,
				"error", err)
			errs = append(errs, err)
			continue
		}

		m.logger.Debug("CIDR 已同步到 BPF Map",
			"cidr", cidrStr,
			"group_id", tg.Spec.ID)
	}

	if len(errs) > 0 {
		return fmt.Errorf("同步部分 CIDR 失败: %d 个错误", len(errs))
	}

	return nil
}

// deleteFromBPFLocked 从 BPF Map 删除流量组 (必须持有锁)
func (m *Manager) deleteFromBPFLocked(tg *v2alpha1.CiliumTrafficGroup) error {
	if m.tgMap == nil {
		return nil
	}

	var errs []error
	for _, cidrStr := range tg.Spec.CIDRs {
		_, cidr, err := net.ParseCIDR(string(cidrStr))
		if err != nil {
			continue
		}

		if err := m.tgMap.DeleteCIDR(cidr); err != nil {
			m.logger.Warn("从 BPF Map 删除 CIDR 失败",
				"cidr", cidrStr,
				"error", err)
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("删除部分 CIDR 失败: %d 个错误", len(errs))
	}

	return nil
}
