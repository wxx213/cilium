// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/policy/api"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumtrafficgroup",path="ciliumtrafficgroups",scope="Cluster",shortName={ctg}
// +kubebuilder:object:root=true
// +deepequal-gen=false

// CiliumTrafficGroup 定义了基于 CIDR 的流量分组，用于按目标地址进行流量分类和限速。
// 每个流量组包含一个唯一的 ID 和一组 CIDR 列表，当 Pod 流量的目标地址匹配某个 CIDR 时，
// 该流量将被归类到对应的流量组，并应用该组的带宽限制。
type CiliumTrafficGroup struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec CiliumTrafficGroupSpec `json:"spec"`
}

// CiliumTrafficGroupSpec 定义了流量组的规格
type CiliumTrafficGroupSpec struct {
	// ID 是流量组的唯一标识符，用于 BPF Map 中的快速查找。
	// 必须是 1-65535 之间的正整数，0 保留给未匹配任何规则的默认流量。
	// 同一集群中的所有 CiliumTrafficGroup 必须有唯一的 ID。
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	ID uint16 `json:"id"`

	// CIDRs 是属于此流量组的 CIDR 列表。
	// 当目标 IP 匹配多个流量组的 CIDR 时，使用最长前缀匹配 (LPM) 规则。
	// 例如：10.1.2.0/24 优先于 10.0.0.0/8。
	// 使用 0.0.0.0/0 可以作为兜底规则匹配所有未被其他规则匹配的流量。
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	CIDRs []api.CIDR `json:"cidrs"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// CiliumTrafficGroupList 是 CiliumTrafficGroup 资源的列表
type CiliumTrafficGroupList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CiliumTrafficGroup `json:"items"`
}
