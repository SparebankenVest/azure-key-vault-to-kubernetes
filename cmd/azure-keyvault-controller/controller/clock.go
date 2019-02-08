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
