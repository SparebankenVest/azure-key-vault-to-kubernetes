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
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
)

func (c *Controller) syncCABundleSecret(key string) error {
	/*
		1. Get Secret
		2. Get all akv2k8s-injector enabled namespaces
		3. Create ConfigMaps containing CA cert in namespaces
	*/

	// Convert the namespace/name string into a distinct namespace and name
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	log.Debugf("pulling secret '%s' from namespace '%s'", name, namespace)

	// Get the Secret resource with this namespace/name
	secret, err := c.secretsLister.Secrets(namespace).Get(name)
	if err != nil {
		// The Secret resource may no longer exist, in which case we stop
		// processing.
		if errors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("secret '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	labelledNamespaces, err := c.getAllAkvsLabelledNamespaces()

	log.Debugf("looping all labelled namespaces looking for config map '%s' to update", c.caBundleConfigMapName)

	for _, ns := range labelledNamespaces {
		configMap, err := c.configMapLister.ConfigMaps(ns.Name).Get(c.caBundleConfigMapName)

		// If the resource doesn't exist, we'll create it
		if errors.IsNotFound(err) {
			log.Infof("configmap '%s' not found in labelled namespace '%s' - creating configmap now", c.caBundleConfigMapName, ns.Name)
			newConfigMap, err := newConfigMap(c.caBundleConfigMapName, ns.Name, secret)
			if err != nil {
				log.Errorf("failed to create new configmap, error: %+v", err)
			}

			configMap, err = c.kubeclientset.CoreV1().ConfigMaps(ns.Name).Create(newConfigMap)
			if err != nil {
				msg := fmt.Sprintf("failed to create configmap %s in namespace %s", newConfigMap.Name, ns.Name)
				c.recorder.Event(newConfigMap, corev1.EventTypeWarning, ErrConfigMap, msg)
				log.Errorf("%s, error: %+v", msg, err)
				return err
			}
			return nil
		}

		// If an error occurs during Get/Create, we'll requeue the item so we can
		// attempt processing again later. This could have been caused by a
		// temporary network failure, or any other transient reason.
		if err != nil {
			return err
		}

		// If the ConfigMap is not controlled by this Secret resource, we should log
		// a warning to the event recorder and return error msg.
		if !metav1.IsControlledBy(configMap, secret) {
			msg := fmt.Sprintf(MessageResourceExists, configMap.Name)
			c.recorder.Event(secret, corev1.EventTypeWarning, ErrResourceExists, msg)
			return fmt.Errorf(msg)
		}

		// If CA cert in ConfigMap resource is not the same as in Secret resource, we
		// should update the ConfigMap resource.
		if configMap.Data["caCert"] != secret.StringData["caCert"] {
			log.Infof("secret %s updated: updating config map: %s", secret.Name, configMap.Name)
			newConfigMap, err := newConfigMap(c.caBundleConfigMapName, ns.Name, secret)
			if err != nil {
				log.Errorf("failed to create new configmap, error: %+v", err)
			}

			configMap, err = c.kubeclientset.CoreV1().ConfigMaps(ns.Name).Update(newConfigMap)

			if err != nil {
				msg := fmt.Sprintf("failed to update configmap %s in namespace %s", newConfigMap.Name, ns.Name)
				c.recorder.Event(newConfigMap, corev1.EventTypeWarning, ErrConfigMap, msg)
				log.Errorf("%s, error: %+v", msg, err)
				return err
			}
		}

		// If an error occurs during Update, we'll requeue the item so we can
		// attempt processing again later. This could have been caused by a
		// temporary network failure, or any other transient reason.
		if err != nil {
			return err
		}
	}

	c.recorder.Event(secret, corev1.EventTypeNormal, SuccessSynced, "CA Bundle successfully synced to to ConfigMap")
	return nil
}

func newConfigMap(name string, ns string, secret *corev1.Secret) (*corev1.ConfigMap, error) {
	dataByte, found := secret.Data["ca.crt"]
	if !found {
		return nil, fmt.Errorf("key ca.crt not found in secret %s/%s", secret.Namespace, secret.Name)
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
			"caCert": string(dataByte),
		},
	}, nil
}
