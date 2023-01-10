// Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tiers

import (
	"strings"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	ClusterDNSPolicyName               = networkpolicy.TigeraComponentPolicyPrefix + "cluster-dns"
	localDNSCacheAccessPolicyName      = networkpolicy.TigeraComponentPolicyPrefix + "local-dns-access"
	clusterFromLocalDNAcessSPolicyName = networkpolicy.TigeraComponentPolicyPrefix + "cluster-from-local-dns-access"
)

var DNSIngressNamespaceSelector = createDNSIngressNamespaceSelector(
	render.GuardianNamespace,
	render.ComplianceNamespace,
	render.DexNamespace,
	render.ElasticsearchNamespace,
	render.LogCollectorNamespace,
	render.IntrusionDetectionNamespace,
	render.KibanaNamespace,
	render.ManagerNamespace,
	common.TigeraPrometheusNamespace,
	"tigera-skraper",
	rmeta.APIServerNamespace(operatorv1.TigeraSecureEnterprise),
)

var defaultTierOrder = 100.0

func Tiers(cfg *Config) render.Component {
	return tiersComponent{cfg: cfg}
}

type Config struct {
	Openshift          bool
	DNSLocalCacheState *dns.DNSNodeLocalCacheState
}

type tiersComponent struct {
	cfg *Config
}

func (t tiersComponent) ResolveImages(is *operatorv1.ImageSet) error {
	return nil
}

func (t tiersComponent) Objects() ([]client.Object, []client.Object) {
	objsToCreate := []client.Object{
		t.allowTigeraTier(),
	}

	objsToDelete := []client.Object{}

	if t.cfg.DNSLocalCacheState != nil {
		objsToCreate = append(objsToCreate, networkpolicy.ToRuntimeObjects(t.allowTigeraClusterDNSNodeLocalCachePolicy()...)...)
		objsToDelete = append(objsToDelete, t.allowTigeraClusterDNSPolicy())
	} else {
		objsToCreate = append(objsToDelete, t.allowTigeraClusterDNSPolicy())
		objsToDelete = append(objsToCreate, networkpolicy.ToRuntimeObjects(t.allowTigeraClusterDNSNodeLocalCachePolicy()...)...)
	}

	return objsToCreate, objsToDelete
}

func (t tiersComponent) Ready() bool {
	return true
}

func (t tiersComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeAny
}

func (t tiersComponent) allowTigeraTier() *v3.Tier {
	return &v3.Tier{
		TypeMeta: metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: networkpolicy.TigeraComponentTierName,
			Labels: map[string]string{
				"projectcalico.org/system-tier": "true",
			},
		},
		Spec: v3.TierSpec{
			Order: &defaultTierOrder,
		},
	}
}

func (t tiersComponent) allowTigeraClusterDNSPolicy() *v3.NetworkPolicy {
	dnsPolicyNamespace, dnsPolicySelector := t.getPolicyNamespaceAndSelector()
	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ClusterDNSPolicyName,
			Namespace: dnsPolicyNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: dnsPolicySelector,
			Ingress: []v3.Rule{
				{
					Action: v3.Allow,
					Source: v3.EntityRule{
						NamespaceSelector: "all()",
						Selector:          DNSIngressNamespaceSelector,
					},
				},
				{
					Action: v3.Pass,
				},
			},
			Egress: []v3.Rule{
				{
					Action: v3.Allow,
				},
			},
			Types: []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
		},
	}
}

func (t tiersComponent) allowTigeraClusterDNSNodeLocalCachePolicy() []*v3.NetworkPolicy {
	dnsPolicyNamespace, dnsPolicySelector := t.getPolicyNamespaceAndSelector()

	localDNSCacheAccess := &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      localDNSCacheAccessPolicyName,
			Namespace: dnsPolicyNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: dnsPolicySelector,
		},
	}

	kubeDNSAcceptRequestAccess := &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterFromLocalDNAcessSPolicyName,
			Namespace: dnsPolicyNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: dnsPolicySelector,
		},
	}

	return []*v3.NetworkPolicy{localDNSCacheAccess, kubeDNSAcceptRequestAccess}
}

func (t tiersComponent) getPolicyNamespaceAndSelector() (string, string) {
	if t.cfg.Openshift {
		return "dns.operator.openshift.io/daemonset-dns == 'default'", "openshift-dns"
	} else {
		return "k8s-app == 'kube-dns'", "kube-system"
	}
}

func createDNSIngressNamespaceSelector(namespaces ...string) string {
	var builder strings.Builder
	builder.WriteString("projectcalico.org/namespace in {")
	for idx, namespace := range namespaces {
		builder.WriteByte('\'')
		builder.WriteString(namespace)
		builder.WriteByte('\'')
		if idx != len(namespaces)-1 {
			builder.WriteByte(',')
		}
	}
	builder.WriteByte('}')
	return builder.String()
}
