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
	"time"

	"github.com/appscode/go/runtime"
	"github.com/appscode/go/wait"
	log "github.com/sirupsen/logrus"

	"k8s.io/client-go/util/workqueue"
)

type FastSlowWorker struct {
	name        string
	queue       workqueue.RateLimitingInterface
	maxRetries  int
	threadiness int
	reconcile   func(key string) error
}

func NewFastSlowWorker(name string, normalFreq time.Duration, slowFreq time.Duration, maxFailSlow int, maxRetries, threadiness int, fn func(key string) error) *FastSlowWorker {
	rl := workqueue.NewItemFastSlowRateLimiter(normalFreq, slowFreq, maxFailSlow)
	q := workqueue.NewNamedRateLimitingQueue(rl, name)
	return &FastSlowWorker{name, q, maxRetries, threadiness, fn}
}

func (w *FastSlowWorker) GetQueue() workqueue.RateLimitingInterface {
	return w.queue
}

func (w *FastSlowWorker) processQueue() {
	for w.processNextEntry() {
	}
}

// ProcessMessage tries to process the next message in the Queue, and requeues on an error
func (w *FastSlowWorker) processNextEntry() bool {
	// Wait until there is a new item in the working queue
	key, quit := w.queue.Get()
	if quit {
		return false
	}
	// Tell the queue that we are done with processing this key. This unblocks the key for other workers
	// This allows safe parallel processing because two deployments with the same key are never processed in
	// parallel.
	defer w.queue.Done(key)

	// Invoke the method containing the business logic
	err := w.reconcile(key.(string))
	if err == nil {
		// Forget about the #AddRateLimited history of the key on every successful synchronization.
		// This ensures that future processing of updates for this key is not delayed because of
		// an outdated error history.
		w.queue.Forget(key)
		return true
	}
	log.Errorf("Failed to process key %v. Reason: %s", key, err)

	// This controller retries 5 times if something goes wrong. After that, it stops trying.
	if w.queue.NumRequeues(key) < w.maxRetries {
		log.Infof("Error syncing key %v: %v", key, err)

		// Re-enqueue the key rate limited. Based on the rate limiter on the
		// queue and the re-enqueue history, the key will be processed later again.
		w.queue.AddRateLimited(key)
		return true
	}

	w.queue.Forget(key)
	// Report to an external entity that, even after several retries, we could not successfully process this key
	runtime.HandleError(err)
	log.Infof("Dropping key %q out of the queue: %v", key, err)
	return true
}

func (w *FastSlowWorker) Run(shutdown <-chan struct{}) {
	defer runtime.HandleCrash()

	// Every second, process all messages in the Queue until it is time to shutdown
	for i := 0; i < w.threadiness; i++ {
		go wait.Until(w.processQueue, time.Second, shutdown)
	}

	go func() {
		<-shutdown

		// Stop accepting messages into the Queue
		log.Infof("Shutting down %s Queue\n", w.name)
		w.queue.ShutDown()
	}()
}
