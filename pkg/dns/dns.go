// Copyright (c) 2020, 2023 Tigera, Inc. All rights reserved.

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

package dns

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Default location for the resolv.conf file.
	DefaultResolveConfPath = "/etc/resolv.conf"

	// Default cluster domain value for k8s clusters.
	DefaultClusterDomain = "cluster.local"
)

// GetClusterDomain parses the path to resolv.conf to find the cluster domain.
func GetClusterDomain(resolvConfPath string) (string, error) {
	var clusterDomain string
	file, err := os.Open(resolvConfPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	reg := regexp.MustCompile(`^search.*?\ssvc\.([^\s]*)`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		match := reg.FindStringSubmatch(scanner.Text())
		if len(match) > 0 {
			clusterDomain = match[1]
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	if clusterDomain == "" {
		return "", fmt.Errorf("failed to find cluster domain in resolv.conf")
	}

	return clusterDomain, nil
}

// GetServiceDNSNames returns a list of a service's DNS names.
// We return:
// - <svc_name>
// - <svc_name>.<ns>
// - <svc_name>.<ns>.svc
// - <svc_name>.<ns>.svc.<cluster-domain>
func GetServiceDNSNames(name, namespace, clusterDomain string) []string {
	return []string{
		name,
		fmt.Sprintf("%s.%s", name, namespace),
		fmt.Sprintf("%s.%s.svc", name, namespace),
		fmt.Sprintf("%s.%s.svc.%s", name, namespace, clusterDomain),
	}
}

func GetClusterDNSService(ctx context.Context, k8sClient client.Client, isOpenShift bool) (*corev1.Service, error) {

	clusterDNSServiceName := "kube-dns"
	if isOpenShift {
		clusterDNSServiceName = "openshift-dns"
	}

	clusterDNSService := &corev1.Service{}
	err := k8sClient.Get(ctx, client.ObjectKey{Name: clusterDNSServiceName}, clusterDNSService)

	if err != nil {
		return nil, err
	}

	return clusterDNSService, err
}

type DNSNodeLocalCacheState struct {
	Enabled             bool
	ClusterDNSServiceIP string
}
