// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/util/mak"
	"tailscale.com/version"
)

type execFunc func(ctx context.Context, args []string) error

type commandInfo struct {
	Name      string
	ShortHelp string
	LongHelp  string
}

var serveHelpCommon = strings.TrimSpace(`
<target> can be a port number (e.g., 3000), a partial URL (e.g., localhost:3000), or a
full URL including a path (e.g., http://localhost:3000/foo, https+insecure://localhost:3000/foo).

EXAMPLES
  - Mount a local web server at 127.0.0.1:3000 in the foreground:
    $ tailscale %s localhost:3000

  - Mount a local web server at 127.0.0.1:3000 in the background:
    $ tailscale %s -d localhost:3000
`)

type serveMode int

const (
	serve serveMode = iota
	funnel
)

var infoMap = map[serveMode]commandInfo{
	serve: {
		Name:      "serve",
		ShortHelp: "Serve content and local servers on your tailnet",
		LongHelp: strings.Join([]string{
			"Serve enables you to share a local server securely within your tailnet.\n",
			"To share a local server on the internet, use `tailscale funnel`\n\n",
		}, "\n"),
	},
	funnel: {
		Name:      "funnel",
		ShortHelp: "Serve content and local servers on the internet",
		LongHelp: strings.Join([]string{
			"Funnel enables you to share a local server on the internet using Tailscale.\n",
			"To share only within your tailnet, use `tailscale serve`\n\n",
		}, "\n"),
	},
}

func buildShortUsage(subcmd string) string {
	return strings.Join([]string{
		subcmd + " <target>",
		subcmd + " set [flags] <source> [off]",
		subcmd + " status [--json]",
		subcmd + " reset",
	}, "\n  ")
}

// newServeDevCommand returns a new "serve" subcommand using e as its environment.
func newServeDevCommand(e *serveEnv, subcmd serveMode) *ffcli.Command {
	if subcmd != serve && subcmd != funnel {
		log.Fatalf("newServeDevCommand called with unknown subcmd %q", subcmd)
	}

	info := infoMap[subcmd]

	return &ffcli.Command{
		Name:      info.Name,
		ShortHelp: info.ShortHelp,
		ShortUsage: strings.Join([]string{
			fmt.Sprintf("%s <target>", info.Name),
			fmt.Sprintf("%s status [--json]", info.Name),
			fmt.Sprintf("%s reset", info.Name),
		}, "\n  "),
		LongHelp: info.LongHelp + fmt.Sprintf(strings.TrimSpace(serveHelpCommon), subcmd, subcmd),
		Exec:     e.runServeCombined(subcmd),

		FlagSet: e.newFlags("serve-set", func(fs *flag.FlagSet) {
			fs.BoolVar(&e.bg, "bg", false, "run the command in the background")
			fs.StringVar(&e.setPath, "set-path", "", "set a path for a specific target")
			fs.StringVar(&e.https, "https", "", "default; HTTPS listener")
			fs.StringVar(&e.http, "http", "", "HTTP listener")
			fs.StringVar(&e.tcp, "tcp", "", "TCP listener")
			fs.StringVar(&e.tlsTerminatedTcp, "tls-terminated-tcp", "", "TLS terminated TCP listener")

		}),
		UsageFunc: usageFunc,
		Subcommands: []*ffcli.Command{
			{
				Name:      "status",
				Exec:      e.runServeStatus,
				ShortHelp: "view current proxy configuration",
				FlagSet: e.newFlags("serve-status", func(fs *flag.FlagSet) {
					fs.BoolVar(&e.json, "json", false, "output JSON")
				}),
				UsageFunc: usageFunc,
			},
			{
				Name:      "reset",
				ShortHelp: "reset current serve/funnel config",
				Exec:      e.runServeReset,
				FlagSet:   e.newFlags("serve-reset", nil),
				UsageFunc: usageFunc,
			},
		},
	}
}

// runServeCombined is the entry point for the "tailscale {serve,funnel}" commands.
func (e *serveEnv) runServeCombined(subcmd serveMode) execFunc {
	e.subcmd = subcmd

	return func(ctx context.Context, args []string) error {
		funnel := subcmd == funnel

		err := checkLegacyInvocation(subcmd, args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: the CLI for serve and funnel has changed.\n")
			fmt.Fprintf(os.Stderr, "Please see https://tailscale.com/kb/1242/tailscale-serve for more information.\n\n")

			return errHelp
		}

		if len(args) > 2 {
			fmt.Fprintf(os.Stderr, "error: invalid number of arguments (%d)\n\n", len(args))
			return errHelp
		}

		// always run in the background when using --set-path
		if e.setPath != "" {
			e.bg = true
		}

		turnOff := "off" == args[len(args)-1]

		// support passing in a port number as the target
		target := args[0]
		port, err := strconv.Atoi(args[0])
		if err == nil {
			target = fmt.Sprintf("http://127.0.0.1:%d", port)
		}

		ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
		defer cancel()

		st, err := e.getLocalClientStatusWithoutPeers(ctx)
		if err != nil {
			return fmt.Errorf("getting client status: %w", err)
		}

		if funnel {
			// verify node has funnel capabilities
			if err := e.verifyFunnelEnabled(ctx, st, 443); err != nil {
				return err
			}
		}

		// default mount point to "/"
		mount := e.setPath
		if mount == "" {
			mount = "/"
		}

		if e.bg || turnOff {
			srvType, srvPort, err := srvTypeAndPortFromFlags(e)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
				return errHelp
			}

			if turnOff {
				err := e.unsetServe(ctx, srvType, srvPort, mount)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
					return errHelp
				}
				return nil
			}

			err = e.setServe(ctx, srvType, srvPort, mount, target, funnel)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
				return errHelp
			}

			return nil
		}

		dnsName := strings.TrimSuffix(st.Self.DNSName, ".")
		hp := ipn.HostPort(dnsName + ":443") // TODO(marwan-at-work): support the 2 other ports

		// In the streaming case, the process stays running in the
		// foreground and prints out connections to the HostPort.
		//
		// The local backend handles updating the ServeConfig as
		// necessary, then restores it to its original state once
		// the process's context is closed or the client turns off
		// Tailscale.
		return e.streamServe(ctx, ipn.ServeStreamRequest{
			Funnel:     funnel,
			HostPort:   hp,
			Source:     target,
			MountPoint: mount,
		})
	}
}

func (e *serveEnv) streamServe(ctx context.Context, req ipn.ServeStreamRequest) error {
	stream, err := e.lc.StreamServe(ctx, req)
	if err != nil {
		return err
	}
	defer stream.Close()

	fmt.Fprintf(os.Stderr, "Serve started on \"https://%s\".\n", strings.TrimSuffix(string(req.HostPort), ":443"))
	fmt.Fprintf(os.Stderr, "Press Ctrl-C to stop.\n\n")
	_, err = io.Copy(os.Stdout, stream)
	return err
}

func (e *serveEnv) setServe(ctx context.Context, srvType string, srvPort uint16, mount string, target string, allowFunnel bool) error {
	if srvType == "https" {
		// Running serve with https requires that the tailnet has enabled
		// https cert provisioning. Send users through an interactive flow
		// to enable this if not already done.
		//
		// TODO(sonia,tailscale/corp#10577): The interactive feature flow
		// is behind a control flag. If the tailnet doesn't have the flag
		// on, enableFeatureInteractive will error. For now, we hide that
		// error and maintain the previous behavior (prior to 2023-08-15)
		// of letting them edit the serve config before enabling certs.
		e.enableFeatureInteractive(ctx, "serve", func(caps []string) bool {
			return slices.Contains(caps, tailcfg.CapabilityHTTPS)
		})
	}

	// get serve config
	sc, err := e.lc.GetServeConfig(ctx)
	if err != nil {
		return err
	}

	// nil if no config
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}

	dnsName, err := e.getSelfDNSName(ctx)
	if err != nil {
		return err
	}

	// update serve config based on the type
	switch srvType {
	case "https", "http":
		mount, err := cleanMountPoint(mount)
		if err != nil {
			return fmt.Errorf("failed to clean the mount point: %w", err)
		}
		useTLS := srvType == "https"
		sc, err = e.applyWebServe(sc, dnsName, srvPort, useTLS, mount, target)
		if err != nil {
			return fmt.Errorf("failed apply web serve: %w", err)
		}
	case "tcp", "tls-terminated-tcp":
		sc, err = e.applyTCPServe(sc, dnsName, srvType, srvPort, target)
		if err != nil {
			return fmt.Errorf("failed to apply TCP serve: %w", err)
		}
	default:
		return fmt.Errorf("invalid type %q", srvType)
	}

	// update the serve config based on if funnel is enabled
	sc, err = e.setFunnel(sc, dnsName, srvPort, allowFunnel)
	if err != nil {
		return err
	}

	// persist the serve config changes
	if err := e.lc.SetServeConfig(ctx, sc); err != nil {
		return err
	}

	// notify the user of the change
	m, err := e.messageForPort(ctx, sc, dnsName, srvPort)
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, m)

	return nil
}

func (e *serveEnv) messageForPort(ctx context.Context, sc *ipn.ServeConfig, dnsName string, srvPort uint16) (string, error) {
	var output strings.Builder

	hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(srvPort))))

	if sc.AllowFunnel[hp] == true {
		output.WriteString("Available on the internet:\n")
	} else {
		output.WriteString("Available within your tailnet:\n")
	}

	scheme := "https"
	if sc.IsServingHTTP(srvPort) {
		scheme = "http"
	}

	portPart := ":" + fmt.Sprint(srvPort)
	if scheme == "http" && srvPort == 80 ||
		scheme == "https" && srvPort == 443 {
		portPart = ""
	}

	output.WriteString(fmt.Sprintf("%s://%s%s\n\n", scheme, dnsName, portPart))

	srvTypeAndDesc := func(h *ipn.HTTPHandler) (string, string) {
		switch {
		case h.Path != "":
			return "path", h.Path
		case h.Proxy != "":
			return "proxy", h.Proxy
		case h.Text != "":
			return "text", "\"" + elipticallyTruncate(h.Text, 20) + "\""
		}
		return "", ""
	}

	if sc.Web[hp] != nil {
		var mounts []string

		for k := range sc.Web[hp].Handlers {
			mounts = append(mounts, k)
		}
		sort.Slice(mounts, func(i, j int) bool {
			return len(mounts[i]) < len(mounts[j])
		})
		maxLen := len(mounts[len(mounts)-1])

		for _, m := range mounts {
			h := sc.Web[hp].Handlers[m]
			t, d := srvTypeAndDesc(h)
			output.WriteString(fmt.Sprintf("%s %s%s %-5s %s\n", "|--", m, strings.Repeat(" ", maxLen-len(m)), t, d))
		}
	} else if sc.TCP[srvPort] != nil {
		h := sc.TCP[srvPort]
		st, err := e.getLocalClientStatusWithoutPeers(ctx)
		if err != nil {
			return "", fmt.Errorf("getting client status: %w", err)
		}

		tlsStatus := "TLS over TCP"
		if h.TerminateTLS != "" {
			tlsStatus = "TLS terminated"
		}

		output.WriteString(fmt.Sprintf("|-- tcp://%s (%s)\n", hp, tlsStatus))
		for _, a := range st.TailscaleIPs {
			ipp := net.JoinHostPort(a.String(), strconv.Itoa(int(srvPort)))
			output.WriteString(fmt.Sprintf("|-- tcp://%s\n", ipp))
		}
		output.WriteString(fmt.Sprintf("|--> tcp://%s\n", h.TCPForward))
	}

	output.WriteString("\nServe started and running in the background.\n")
	output.WriteString(fmt.Sprintf("To disable the proxy, run: tailscale %s off\n", infoMap[e.subcmd].Name))

	return output.String(), nil
}

func (e *serveEnv) applyWebServe(sc *ipn.ServeConfig, dnsName string, srvPort uint16, useTLS bool, mount, source string) (*ipn.ServeConfig, error) {
	h := new(ipn.HTTPHandler)

	ts, _, _ := strings.Cut(source, ":")
	switch {
	case ts == "text":
		text := strings.TrimPrefix(source, "text:")
		if text == "" {
			return nil, errors.New("unable to serve; text cannot be an empty string")
		}
		h.Text = text
	case isProxyTarget(source):
		t, err := expandProxyTarget(source)
		if err != nil {
			return nil, err
		}
		h.Proxy = t
	default: // assume path
		if version.IsSandboxedMacOS() {
			// don't allow path serving for now on macOS (2022-11-15)
			return nil, fmt.Errorf("path serving is not supported if sandboxed on macOS")
		}
		if !filepath.IsAbs(source) {
			return nil, fmt.Errorf("path must be absolute\n\n")
		}
		source = filepath.Clean(source)
		fi, err := os.Stat(source)
		if err != nil {
			return nil, fmt.Errorf("invalid path\n\n")
		}
		if fi.IsDir() && !strings.HasSuffix(mount, "/") {
			// dir mount points must end in /
			// for relative file links to work
			mount += "/"
		}
		h.Path = source
	}

	if sc.IsTCPForwardingOnPort(srvPort) {
		return nil, fmt.Errorf("cannot serve web; already serving TCP")
	}

	hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(srvPort))))

	mak.Set(&sc.TCP, srvPort, &ipn.TCPPortHandler{HTTPS: useTLS, HTTP: !useTLS})

	if _, ok := sc.Web[hp]; !ok {
		mak.Set(&sc.Web, hp, new(ipn.WebServerConfig))
	}
	mak.Set(&sc.Web[hp].Handlers, mount, h)

	for k, v := range sc.Web[hp].Handlers {
		if v == h {
			continue
		}
		// If the new mount point ends in / and another mount point
		// shares the same prefix, remove the other handler.
		// (e.g. /foo/ overwrites /foo)
		// The opposite example is also handled.
		m1 := strings.TrimSuffix(mount, "/")
		m2 := strings.TrimSuffix(k, "/")
		if m1 == m2 {
			delete(sc.Web[hp].Handlers, k)
			continue
		}
	}

	return sc, nil
}

func (e *serveEnv) applyTCPServe(sc *ipn.ServeConfig, dnsName string, srcType string, srcPort uint16, dest string) (*ipn.ServeConfig, error) {
	var terminateTLS bool
	switch srcType {
	case "tcp":
		terminateTLS = false
	case "tls-terminated-tcp":
		terminateTLS = true
	default:
		return nil, fmt.Errorf("invalid TCP source %q", dest)
	}

	dstURL, err := url.Parse(dest)
	if err != nil {
		return nil, fmt.Errorf("invalid TCP source %q: %v", dest, err)
	}
	host, dstPortStr, err := net.SplitHostPort(dstURL.Host)
	if err != nil {
		return nil, fmt.Errorf("invalid TCP source %q: %v", dest, err)
	}

	switch host {
	case "localhost", "127.0.0.1":
		// ok
	default:
		return nil, fmt.Errorf("invalid TCP source %q, must be one of localhost or 127.0.0.1", dest)
	}

	if p, err := strconv.ParseUint(dstPortStr, 10, 16); p == 0 || err != nil {
		return nil, fmt.Errorf("invalid port %q", dstPortStr)
	}

	fwdAddr := "127.0.0.1:" + dstPortStr

	if sc.IsServingWeb(srcPort) {
		return nil, fmt.Errorf("cannot serve TCP; already serving web on %d", srcPort)
	}

	mak.Set(&sc.TCP, srcPort, &ipn.TCPPortHandler{TCPForward: fwdAddr})

	if terminateTLS {
		sc.TCP[srcPort].TerminateTLS = dnsName
	}

	return sc, nil
}

func (e *serveEnv) setFunnel(sc *ipn.ServeConfig, dnsName string, srvPort uint16, allowFunnel bool) (*ipn.ServeConfig, error) {
	hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(srvPort))))

	// nil if no config
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}

	// Setting funnel here removes another roundtrip for get/set ServeConfig
	// when we also need funnel enabled for the handler. However, verifyFunnelEnabled
	// will still need to be checked as that is not handled here currently.
	if allowFunnel {
		mak.Set(&sc.AllowFunnel, hp, true)
	} else {
		delete(sc.AllowFunnel, hp)
	}

	return sc, nil
}

func (e *serveEnv) unsetServe(ctx context.Context, srvType string, srvPort uint16, mount string) error {
	switch srvType {
	case "https", "http":
		mount, err := cleanMountPoint(mount)
		if err != nil {
			return fmt.Errorf("failed to clean the mount point: %w", err)
		}
		return e.handleWebServeRemove(ctx, srvPort, mount)
	case "tcp", "tls-terminated-tcp":
		return e.handleTCPServeRemove(ctx, srvPort)
	default:
		return fmt.Errorf("invalid type %q", srvType)
	}
}

func srvTypeAndPortFromFlags(e *serveEnv) (srvType string, srvPort uint16, err error) {
	sourceMap := map[string]string{
		"http":               e.http,
		"https":              e.https,
		"tcp":                e.tcp,
		"tls-terminated-tcp": e.tlsTerminatedTcp,
	}

	var srcTypeCount int
	var srcValue string

	for k, v := range sourceMap {
		if v != "" {
			srcTypeCount++
			srvType = k
			srcValue = v
		}
	}

	if srcTypeCount > 1 {
		return "", 0, fmt.Errorf("cannot serve multiple types for a single mount point")
	} else if srcTypeCount == 0 {
		srvType = "https"
		srcValue = "443"
	}

	srvPort, err = parseServePort(srcValue)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q: %w", srcValue, err)
	}

	return srvType, srvPort, nil
}

func checkLegacyInvocation(subcmd serveMode, args []string) error {
	if subcmd == serve && len(args) == 2 {
		prefixes := []string{"http:", "https:", "tls:", "tls-terminated-tcp:"}

		for _, prefix := range prefixes {
			if strings.HasPrefix(args[0], prefix) {
				return errors.New("invalid invocation")
			}
		}
	}

	if subcmd == funnel && len(args) == 2 {
		onOff := args[len(args)-1]
		if onOff == "on" || onOff == "off" {
			return errors.New("invalid invocation")
		}
	}

	return nil
}
