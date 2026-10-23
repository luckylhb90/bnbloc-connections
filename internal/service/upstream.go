package service

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// Guarded is the client of the connected systems: HTTPS calls that never
// follow a redirect, never decompress for the caller (the answer goes back
// as the system sent it), and never reach loopback, link-local (cloud
// metadata included) or unspecified addresses, whatever a name resolves to.
// Private addresses are allowed: an organization's own systems live there.
func Guarded() *http.Client {
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	return &http.Client{
		Timeout: 90 * time.Second,
		Transport: &http.Transport{
			DisableCompression:  true,
			TLSHandshakeTimeout: 15 * time.Second,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     90 * time.Second,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
				if err != nil || len(ips) == 0 {
					return nil, fmt.Errorf("%s does not resolve", host)
				}
				for _, ip := range ips {
					if forbidden(ip) {
						return nil, fmt.Errorf("%s resolves to %s, which connections never reach", host, ip)
					}
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].Unmap().String(), port))
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// forbidden: loopback, link-local (169.254.0.0/16, fe80::/10: cloud
// metadata), unspecified, multicast.
func forbidden(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip == netip.MustParseAddr("fd00:ec2::254")
}

func (s *Service) upstream() *http.Client {
	if s.Upstream != nil {
		return s.Upstream
	}
	return Guarded()
}
