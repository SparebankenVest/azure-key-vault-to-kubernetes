package akv2k8s

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

// Version is the version of the component
var Version string

// BuildDate is the date when the binary was built
var BuildDate string

// GitCommit is the commit hash when the binary was built
var GitCommit string

// Component is the versioned component
var Component string

// GetUserAgent is used to get the user agent string which is then provided to adal
// to use as the extended user agent header.
// The format is: akv2k8s/<version>/<component>/<Git commit>/<Build date>
func GetUserAgent() string {
	return fmt.Sprintf("akv2k8s/%s/%s/%s/%s", Component, Version, GitCommit, BuildDate)
}

// LogVersion prints the version and exits
// The format is: <component> - commit: <Git commit>  - date: <build date>
func LogVersion() {
	contextLogger := log.WithFields(log.Fields{
		"commit":    GitCommit,
		"buildDate": BuildDate,
		"component": Component,
	})
	contextLogger.Infof("version %s", Version)
}
