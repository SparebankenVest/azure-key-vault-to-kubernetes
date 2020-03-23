package main

import (
	"fmt"
	"github.com/containers/image/v5/types"
	"github.com/ghodss/yaml"
	log "github.com/sirupsen/logrus"
	"testing"
)

func TestDockerPull(t *testing.T) {
	config.dockerPullTimeout = 120

	opts := imageOptions{
		image:        "openjdk:slim",
		credentials:  types.DockerAuthConfig{},
		architecture: "amd64",
		osChoice:     "linux",
	}

	manifest, err := opts.getConfigFromManifest()

	if err != nil {
		t.Errorf("failed somewhere in get manifest %+v", err)
		return
	}

	var cmd []string
	cmd = append(cmd, manifest.Config.Entrypoint...)
	cmd = append(cmd, manifest.Config.Cmd...)

	if len(cmd) == 0 {
		t.Errorf("no entrypoint nor cmd found there is something wrong.")
		fmt.Print(yaml.Marshal(manifest.Config))
	}

	log.Infof("cmd found: %v", cmd)
}
