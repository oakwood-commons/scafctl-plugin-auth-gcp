// Package main is the entry point for the scafctl-plugin-auth-gcp plugin.
package main

import (
	"github.com/oakwood-commons/scafctl-plugin-auth-gcp/internal/gcp"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

func main() {
	sdkplugin.ServeAuthHandler(&gcp.Plugin{})
}
