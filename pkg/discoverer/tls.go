package discoverer

// TLS holds the tls information for authenticating with the Server.
type TLS struct {
	TLSCa         string
	TLSCert       string
	TLSKey        string
	TLSMaxVersion string
	TLSMinVersion string
	TLSVersion    string
}
