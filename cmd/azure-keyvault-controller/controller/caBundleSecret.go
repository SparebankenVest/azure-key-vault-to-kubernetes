/*
Copyright Sparebanken Vest

Based on the Kubernetes controller example at
https://github.com/kubernetes/sample-controller

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (c *Controller) syncCABundleSecret(key string) error {
	labelledNamespaces, err := c.getAllAkvsLabelledNamespaces()
	if err != nil {
		return err
	}

	log.Debugf("looping all labelled namespaces looking for ca bundle configmap '%s' to update", c.caBundleConfigMapName)

	for _, ns := range labelledNamespaces {
		if err := c.syncCABundleInNamespace(ns.Name); err != nil {
			return err
		}
	}
	return nil
}

func getCABundleFromSecret(secret *corev1.Secret) (string, error) {
	dataByte, found := secret.Data["ca.crt"]
	if !found {
		return "", fmt.Errorf("did not find key ca.crt in secret %s", secret.Name)
	}

	caBundle := string(dataByte)
	if caBundle == "" {
		return "", fmt.Errorf("did find key ca.crt in secret %s, but no data was found", secret.Name)
	}

	return caBundle, nil
}

func getCABundleFromConfigMap(cm *corev1.ConfigMap) string {
	return cm.Data["caCert"]
}

func newConfigMap(name string, ns string, secret *corev1.Secret) (*corev1.ConfigMap, error) {
	caCert, err := getCABundleFromSecret(secret)
	if err != nil {
		return nil, err
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(secret, schema.GroupVersionKind{
					Group:   corev1.SchemeGroupVersion.Group,
					Version: corev1.SchemeGroupVersion.Version,
					Kind:    "Secret",
				}),
			},
		},
		Data: map[string]string{
			"caCert": caCert,
		},
	}, nil
}
