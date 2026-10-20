// Package model defines the wire types exchanged between the scan-data client
// and the fingerprinting server. The JSON field names are part of the public
// API contract and must stay stable.
package model

// ScanRecord is one raw observation produced by a network scanner.
type ScanRecord struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// Fingerprint is the identification result for one ScanRecord.
//
// Protocol is always populated. Unrecognised input yields "unknown" with a
// zero confidence; product/version/os_hint are best-effort and may be empty.
type Fingerprint struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// UnknownProtocol is the protocol value guaranteed for unrecognised banners.
const UnknownProtocol = "unknown"

// NewUnknown returns an unknown result that still echoes the input identity.
func NewUnknown(rec ScanRecord) Fingerprint {
	return Fingerprint{
		IP:         rec.IP,
		Port:       rec.Port,
		Protocol:   UnknownProtocol,
		Product:    "",
		Version:    "",
		OSHint:     "",
		Confidence: 0,
	}
}
