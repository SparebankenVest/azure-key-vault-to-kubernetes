package main

// func TestDockerPull(t *testing.T) {
// 	config.dockerImageInspectionTimeout = 20

// 	opts := imageOptions{
// 		image:        "openjdk:slim",
// 		credentials:  dockerTypes.AuthConfig{},
// 		architecture: "amd64",
// 		osChoice:     "linux",
// 	}

// 	manifest, err := opts.getConfigFromManifest()

// 	if err != nil {
// 		t.Errorf("failed somewhere in get manifest %+v", err)
// 		return
// 	}

// 	var cmd []string
// 	cmd = append(cmd, manifest.Config.Entrypoint...)
// 	cmd = append(cmd, manifest.Config.Cmd...)

// 	if len(cmd) == 0 {
// 		t.Errorf("no entrypoint nor cmd found there is something wrong.")
// 		t.Log(yaml.Marshal(manifest.Config))
// 	}

// 	t.Logf("cmd found: %v", cmd)
// }

// func TestDockerPullWithShaImageNotation(t *testing.T) {
// 	config.dockerImageInspectionTimeout = 20

// 	opts := imageOptions{
// 		image:        "spvest/azure-keyvault-webhook@sha256:38a78fde88bd3bf023606ac3a2219b0803457734cb2e7bb80b55d36450cc71f1",
// 		credentials:  dockerTypes.AuthConfig{},
// 		architecture: "amd64",
// 		osChoice:     "linux",
// 	}

// 	manifest, err := opts.getConfigFromManifest()

// 	if err != nil {
// 		t.Errorf("failed somewhere in get manifest %+v", err)
// 		return
// 	}

// 	var cmd []string
// 	cmd = append(cmd, manifest.Config.Entrypoint...)
// 	cmd = append(cmd, manifest.Config.Cmd...)

// 	if len(cmd) == 0 {
// 		t.Errorf("no entrypoint nor cmd found there is something wrong.")
// 		t.Log(yaml.Marshal(manifest.Config))
// 	}

// 	t.Logf("cmd found: %v", cmd)
// }
