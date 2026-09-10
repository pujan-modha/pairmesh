// Package health defines the loopback-only daemon snapshot.
// Nothing here ever listens publicly; the admin mux serves /healthz.
package health

// Status is the daemon snapshot.
type Status struct {
	Role       string `json:"role"` // pms | pmc
	Healthy    bool   `json:"healthy"`
	Detail     string `json:"detail,omitempty"`
	Revision   uint64 `json:"directory_revision,omitempty"`
	Devices    int    `json:"devices,omitempty"`
	DirectConn bool   `json:"direct,omitempty"`
	Via        string `json:"via,omitempty"`
}
