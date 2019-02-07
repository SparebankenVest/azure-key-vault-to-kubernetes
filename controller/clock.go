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

// FakeClock is a timer used for unit testing
type FakeClock struct {
}

// Now returns a fake time
func (t *FakeClock) Now() metav1.Time {
	now := time.Date(2019, time.February, 4, 12, 0, 0, 0, time.Local)
	return metav1.Time{Time: now}
}
