// Package buildinfo exposes immutable release metadata set by the linker.
package buildinfo

type Info struct {
	Version   string `json:"version"`
	Revision  string `json:"revision"`
	BuildDate string `json:"build_date"`
}

// These values are populated by release builds with -ldflags. Development builds remain explicit.
var Version = "dev"
var Revision = "unknown"
var BuildDate = "unknown"

func Current() Info { return Info{Version: Version, Revision: Revision, BuildDate: BuildDate} }
