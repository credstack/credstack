package version

import (
	"fmt"
	"runtime"
)

var (
	// SemVer The semantic version of this build
	SemVer = "undefined"

	// CommitSHA The git commit SHA that this was built against
	CommitSHA = "undefined"

	// BuildDate A timestamp of when the build was completed
	BuildDate = "undefined"
)

// String Returns the version string of this build
func String() string {
	return fmt.Sprintf("credstack %s (commit %s, built at %s, runtime %s)",
		SemVer, CommitSHA, BuildDate, runtime.Version())
}
