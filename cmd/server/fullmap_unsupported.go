//go:build !linux && !windows

package main

import "errors"

func fullMappingSupported() bool { return false }

func cleanupStaleFullMappings() {}

func startFullMapping(fullMappingSpec, *mappingManager) (fullMapper, error) {
	return nil, errors.New("full mapping is supported only by Linux and Windows server packages; macOS supports TCP/UDP port mappings")
}
