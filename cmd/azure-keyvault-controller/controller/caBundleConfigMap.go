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
	"k8s.io/client-go/tools/cache"
	"kmodules.xyz/client-go/tools/queue"
)

func (c *Controller) initConfigMap() {
	c.kubeInformerFactory.Core().V1().ConfigMaps().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			cm, err := convertToConfigMap(obj)
			if err != nil {
				log.Errorf("failed to convert to configmap: %v", err)
			}

			if c.isCABundleConfigMap(cm) {
				queue.Enqueue(c.caBundleConigMapQueue.GetQueue(), cm)
				return
			}
		},
	})
}

func (c *Controller) syncCABundleConfigMap(key string) error {
	cm, err := c.getConfigMap(key)
	if err != nil {
		return err
	}

	if ownerRef := metav1.GetControllerOf(cm); ownerRef != nil {
		secret, err := c.getSecretFromConfigMap(cm, ownerRef)
		if err != nil {
			return err
		}

		queue.Enqueue(c.caBundleSecretQueue.GetQueue(), secret)
	}
	return nil
}

func (c *Controller) getSecretFromConfigMap(cm *corev1.ConfigMap, owner *metav1.OwnerReference) (*corev1.Secret, error) {
	return c.secretsLister.Secrets(c.caBundleSecretNamespaceName).Get(owner.Name)
}

func (c *Controller) isCABundleConfigMap(cm *corev1.ConfigMap) bool {
	return cm.Name == c.caBundleConfigMapName
}

func (c *Controller) getConfigMap(key string) (*corev1.ConfigMap, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, fmt.Errorf("invalid resource key: %s", key)
	}

	log.Debugf("getting configmap %s from namespace %s", name, namespace)
	cm, err := c.configMapLister.ConfigMaps(namespace).Get(name)

	if err != nil {
		return nil, err
	}
	return cm, err
}

func convertToConfigMap(obj interface{}) (*corev1.ConfigMap, error) {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return nil, fmt.Errorf("couldn't get object from tombstone %#v", obj)
		}
		cm, ok = tombstone.Obj.(*corev1.ConfigMap)
		if !ok {
			return nil, fmt.Errorf("tombstone contained object that is not a configmap %#v", obj)
		}
	}
	return cm, nil
}
