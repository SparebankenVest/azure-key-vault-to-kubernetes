package akv2k8s

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestVersion(t *testing.T) {
	BuildDate = time.Now().UTC().Format(time.RFC3339)
	GitCommit = "20462a2"
	Version = "1.1.7"
	Component = "env-injector"
	expectedUserAgentStr := fmt.Sprintf("akv2k8s/%s/%s/%s/%s", Component, Version, GitCommit, BuildDate)
	gotUserAgentStr := GetUserAgent()

	if !strings.EqualFold(expectedUserAgentStr, gotUserAgentStr) {
		t.Fatalf("got unexpected user agent string: %s. Expected: %s.", gotUserAgentStr, expectedUserAgentStr)
	}
}
