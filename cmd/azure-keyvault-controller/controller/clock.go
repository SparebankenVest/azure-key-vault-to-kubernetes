/*
Copyright Sparebanken Vest

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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Timer is a simple interface for time handling
type Timer interface {
	Now() metav1.Time
}

// Clock is a simple Time impl
type Clock struct {
}

// Now returns current time
func (t *Clock) Now() metav1.Time {
	now := time.Now()
	return metav1.Time{Time: now}
}
