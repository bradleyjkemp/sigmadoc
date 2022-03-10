//go:build tools
// +build tools

// This is the standard way to use Go modules to pin version of CLI tools (in this case sigma-test)
// See: https://github.com/golang/go/issues/25922#issuecomment-1038394599

package sigmadoc

import (
	_ "github.com/bradleyjkemp/sigmadoc"
)
