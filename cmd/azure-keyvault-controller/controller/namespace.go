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
	"k8s.io/client-go/tools/cache"
	"kmodules.xyz/client-go/tools/queue"
)

func (c *Controller) initNamespace() {
	c.kubeInformerFactory.Core().V1().Namespaces().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) { // When a new namespace gets added, that we should add ConfigMap to
			ns, err := convertToNamespace(obj)
			if err != nil {
				log.Errorf("failed to convert to namespace: %v", err)
			}

			if c.isInjectorEnabledForNamespace(ns) {
				queue.Enqueue(c.namespaceQueue.GetQueue(), ns)
			}
		},
		UpdateFunc: func(old, new interface{}) { // When an existing namespace gets updated, that potentually have akv2k8s label on it
			newNs, err := convertToNamespace(new)
			if err != nil {
				log.Errorf("failed to convert to namespace: %v", err)
			}

			oldNs, err := convertToNamespace(old)
			if err != nil {
				log.Errorf("failed to convert to namespace: %v", err)
			}

			if newNs.ResourceVersion == oldNs.ResourceVersion {
				// Periodic resync will send update events for all known Secrets.
				// Two different versions of the same Secret will always have different RVs.
				return
			}

			if c.isInjectorEnabledForNamespace(newNs) || c.isInjectorEnabledForNamespace(oldNs) {
				if c.hasNamespaceLabelChanged(oldNs, newNs) {
					queue.Enqueue(c.namespaceQueue.GetQueue(), newNs)
				}
			}
		},
	})
}

func (c *Controller) syncNamespace(key string) error {
	ns, err := c.namespaceLister.Get(key)
	if err != nil {
		return err
	}

	log.Debugf("Looking for configmap '%s' in labelled namespace '%s'", c.caBundleConfigMapName, ns.Name)
	cm, err := c.configMapLister.ConfigMaps(ns.Name).Get(c.caBundleConfigMapName)

	//If this is a non-labelled namespace, we delete ca bundle config map
	if !c.isInjectorEnabledForNamespace(ns) && cm != nil {
		log.Infof("configmap '%s' exists in namespace '%s' which is no longer labelled to keep CA Bundle - deleting now", c.caBundleConfigMapName, key)
		err = c.kubeclientset.CoreV1().ConfigMaps(key).Delete(c.caBundleConfigMapName, &metav1.DeleteOptions{})
		if err != nil {
			return err
		}
		msg := fmt.Sprintf("CA Bundle successfully deleted ConfigMap %s in namespace %s", c.caBundleConfigMapName, key)
		c.recorder.Event(cm, corev1.EventTypeNormal, SuccessSynced, msg)
		return nil
	}

	if err != nil {
		if errors.IsNotFound(err) { // if configmap does not exist, create it
			log.Infof("configmap '%s' not found in labelled namespace '%s' - creating now", c.caBundleConfigMapName, key)

			log.Debugf("getting secret %s with ca bundle in namespace %s", c.caBundleSecretName, c.caBundleSecretNamespaceName)
			secret, err := c.kubeclientset.CoreV1().Secrets(c.caBundleSecretNamespaceName).Get(c.caBundleSecretName, metav1.GetOptions{})
			if err != nil {
				return err
			}

			log.Debugf("creating new configmap %s with ca bundle in namespace %s", c.caBundleConfigMapName, c.caBundleSecretNamespaceName)
			newConfigMap := newConfigMap(c.caBundleConfigMapName, ns.Name, secret)
			_, err = c.kubeclientset.CoreV1().ConfigMaps(ns.Name).Create(newConfigMap)
			if err != nil {
				return err
			}
			msg := fmt.Sprintf("CA Bundle successfully synced to ConfigMap %s in namespace %s", c.caBundleConfigMapName, key)
			c.recorder.Event(cm, corev1.EventTypeNormal, SuccessSynced, msg)
			return nil
		}

		return err
	}

	//Get ca bundle from Secret
	secret, err := c.kubeclientset.CoreV1().Secrets(c.caBundleSecretNamespaceName).Get(c.caBundleSecretName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	dataByte := secret.Data["ca.crt"]
	secretCaBundle := string(dataByte)
	cmCaBundle, found := cm.Data["ca.crt"]

	if found && secretCaBundle != cmCaBundle {
		log.Infof("configmap '%s' exists in namespace '%s' with old ca bundle - updating now", c.caBundleConfigMapName, key)

		newConfigMap := newConfigMap(c.caBundleConfigMapName, ns.Name, secret)
		_, err = c.kubeclientset.CoreV1().ConfigMaps(ns.Name).Update(newConfigMap)
		if err != nil {
			return err
		}
		msg := fmt.Sprintf("CA Bundle successfully synced to ConfigMap %s in namespace %s", c.caBundleConfigMapName, key)
		c.recorder.Event(cm, corev1.EventTypeNormal, SuccessSynced, msg)
	}

	return nil
}

func (c *Controller) getAllAkvsLabelledNamespaces() ([]*corev1.Namespace, error) {
	labelSelector := &metav1.LabelSelector{
		MatchLabels: map[string]string{
			c.caBundleSecretNamespaceName: "enabled",
		},
	}

	selector, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		return nil, err
	}

	return c.namespaceLister.List(selector)
}

func convertToNamespace(obj interface{}) (*corev1.Namespace, error) {
	ns, ok := obj.(*corev1.Namespace)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return nil, fmt.Errorf("couldn't get object from tombstone %#v", obj)
		}
		ns, ok = tombstone.Obj.(*corev1.Namespace)
		if !ok {
			return nil, fmt.Errorf("tombstone contained object that is not a Secret %#v", obj)
		}
	}
	return ns, nil
}

func (c *Controller) isInjectorEnabledForNamespace(ns *corev1.Namespace) bool {
	lbl := ns.Labels[c.namespaceAkvsLabel]
	if lbl == "enabled" {
		return true
	}

	return false
}

func (c *Controller) hasNamespaceLabelChanged(oldNs, newNs *corev1.Namespace) bool {
	newLbl, newLblExist := newNs.Labels[c.namespaceAkvsLabel]
	oldLbl, oldLblExist := oldNs.Labels[c.namespaceAkvsLabel]

	if newLblExist == oldLblExist && newLbl == oldLbl {
		return false
	}
	return true
}
