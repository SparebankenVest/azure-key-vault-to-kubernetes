package main

import (
	"fmt"
	"regexp"
	"strings"

	"k8s.io/klog/v2"
)

const (
	envLookupRegex = `^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)@azurekeyvault(\?([a-zA-Z_][a-zA-Z0-9_\.]*)?)?$`
)

type EnvSecret struct {
	akvsName string
	query    string
	index    int
}

func parseEnvVars(envVars []string) (map[string]EnvSecret, error) {
	re := regexp.MustCompile(envLookupRegex)

	result := make(map[string]EnvSecret)
	for index, envVar := range envVars {
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) != 2 {
			klog.ErrorS(fmt.Errorf("error splitting env var"), "env variable not properly formatted", "env", envVar)
			continue
		}

		name := parts[0]
		value := parts[1]
		match := re.FindStringSubmatch(value)
		if len(match) == 0 {
			klog.V(4).InfoS("env variable not an azure key vault reference", "env", envVar)
			continue
		}

		klog.V(4).InfoS("found env var to get azure key vault secret for", "env", name)

		akvsName := match[1]
		klog.V(4).InfoS("azure key vault secret name found", "akvsName", akvsName)

		if akvsName == "" {
			err := fmt.Errorf("error extracting secret name")
			klog.ErrorS(err, "env variable not properly formatted", "env", name, "value", value)
			return nil, err
		}

		var query string
		if len(match) == 5 {
			klog.V(4).InfoS("found query in env var", "env", name, "value", value, "query", query)
			query = match[4]
		} else {
			query = ""
		}

		result[name] = EnvSecret{
			akvsName: akvsName,
			query:    query,
			index:    index,
		}
	}

	return result, nil
}
