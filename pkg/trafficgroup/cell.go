// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

// Package trafficgroup 实现基于 CIDR 的流量分组的 Informer 集成
package trafficgroup

import (
	"github.com/cilium/hive/cell"
	"k8s.io/client-go/util/workqueue"

	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

// Cell 提供 TrafficGroup 的 Hive 集成
var Cell = cell.Module(
	"trafficgroup",
	"Traffic Group Manager for CIDR-based bandwidth limiting",

	cell.Provide(newTrafficGroupResource),
	cell.Provide(NewManager), // 提供 Manager 实例
	cell.Invoke(registerInformer),
)

// TrafficGroupResource 是 CiliumTrafficGroup 的 Resource 类型
type TrafficGroupResource resource.Resource[*v2alpha1.CiliumTrafficGroup]

func newTrafficGroupResource(lc cell.Lifecycle, cs client.Clientset, mp workqueue.MetricsProvider) TrafficGroupResource {
	if !cs.IsEnabled() {
		return nil
	}

	lw := utils.ListerWatcherFromTyped[*v2alpha1.CiliumTrafficGroupList](
		cs.CiliumV2alpha1().CiliumTrafficGroups(),
	)

	return resource.New[*v2alpha1.CiliumTrafficGroup](
		lc,
		lw,
		mp,
		resource.WithMetric("CiliumTrafficGroup"),
	)
}

type informerParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Manager   *Manager             `optional:"true"`
	Resource  TrafficGroupResource `optional:"true"`
}

func registerInformer(p informerParams) {
	if p.Resource == nil || p.Manager == nil {
		return
	}

	p.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			go runInformer(ctx, p.Manager, p.Resource)
			return nil
		},
	})
}

func runInformer(ctx cell.HookContext, m *Manager, res TrafficGroupResource) {
	for event := range res.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			if err := m.OnAdd(event.Object); err != nil {
				event.Done(err)
				continue
			}
		case resource.Delete:
			if err := m.OnDelete(event.Object); err != nil {
				event.Done(err)
				continue
			}
		}
		event.Done(nil)
	}
}
