// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package ipn

import (
	"testing"

	"tailscale.com/tailcfg"
)

func TestCheckFunnelAccess(t *testing.T) {
	const portAttr tailcfg.NodeCapability = "https://tailscale.com/cap/funnel-ports?ports=443,8080-8090,8443,"
	tests := []struct {
		port    uint16
		caps    []tailcfg.NodeCapability
		wantErr bool
	}{
		{443, []tailcfg.NodeCapability{portAttr}, true}, // No "funnel" attribute
		{443, []tailcfg.NodeCapability{portAttr, tailcfg.NodeAttrFunnel}, true},
		{443, []tailcfg.NodeCapability{portAttr, tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel}, false},
		{8443, []tailcfg.NodeCapability{portAttr, tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel}, false},
		{8321, []tailcfg.NodeCapability{portAttr, tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel}, true},
		{8083, []tailcfg.NodeCapability{portAttr, tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel}, false},
		{8091, []tailcfg.NodeCapability{portAttr, tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel}, true},
		{3000, []tailcfg.NodeCapability{portAttr, tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel}, true},
	}
	for _, tt := range tests {
		err := CheckFunnelAccess(tt.port, tt.caps)
		switch {
		case err != nil && tt.wantErr,
			err == nil && !tt.wantErr:
			continue
		case tt.wantErr:
			t.Fatalf("got no error, want error")
		case !tt.wantErr:
			t.Fatalf("got error %v, want no error", err)
		}
	}
}
