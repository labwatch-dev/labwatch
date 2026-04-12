// Package collector defines the interface for metric collectors.
package collector

import "context"

// Collector gathers metrics from a specific source.
type Collector interface {
	// Name returns the collector's identifier (e.g., "system", "docker").
	Name() string

	// Collect gathers metrics and returns them as a map.
	Collect(ctx context.Context) (interface{}, error)
}
