package pkg

import (
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	log "github.com/sirupsen/logrus"
)

func (peer WireguardPeer) Validate() error {
	if peer.Endpoint == "" {
		return nil
	}
	_, _, err := net.SplitHostPort(peer.Endpoint)
	return err
}

func (peer WireguardPeer) WriteTo(sb io.StringWriter) {
	sb.WriteString(fmt.Sprintf("public_key=%s\n", hex.EncodeToString(peer.PublicKey)))
	if peer.Endpoint != "" {
		sb.WriteString(fmt.Sprintf("endpoint=%s\n", peer.resolvedEndpoint))
	}
	sb.WriteString(fmt.Sprintf("allowed_ip=%s\n", peer.AllowedIps))
	if !peer.DisablePersistentKeepalive {
		sb.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.PersistentKeepaliveInterval))
	}
}

func (base WireguardBase) String() string {
	sb := strings.Builder{}

	sb.WriteString(fmt.Sprintf("private_key=%s\n", hex.EncodeToString(base.PrivateKey)))
	sb.WriteString(fmt.Sprintf("listen_port=%d\n", base.ListenPort))

	for i := range base.Peers {
		base.Peers[i].WriteTo(&sb)
	}

	return sb.String()
}

func (base *WireguardBase) ResolvePeerEndpoints() error {
	for i := range base.Peers {
		if base.Peers[i].Endpoint == "" {
			continue
		}

		host, port, _ := net.SplitHostPort(base.Peers[i].Endpoint)
		addr := net.ParseIP(host)
		if addr != nil {
			base.Peers[i].resolvedEndpoint = base.Peers[i].Endpoint
			continue
		}

		addrs, err := net.LookupHost(host)
		if err != nil {
			return fmt.Errorf("lookup failed for %v: %v", host, err)
		}
		addr = net.ParseIP(addrs[rand.Intn(len(addrs))])

		base.Peers[i].resolvedEndpoint = fmt.Sprintf("%v:%v", addr, port)
	}
	return nil
}

func SetupWireguard(base *WireguardBase) (*device.Device, *netstack.Net, error) {
	if err := base.ResolvePeerEndpoints(); err != nil {
		return nil, nil, fmt.Errorf("failed to resolve peer endpoint: %v", err)
	}

	localAddress := netip.MustParseAddr(base.LocalAddress)

	var dnsAddresses = make([]netip.Addr, len(base.Dns))
	for i := range base.Dns {
		dnsAddresses[i] = netip.MustParseAddr(base.Dns[i])
	}

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{localAddress},
		dnsAddresses,
		base.Mtu,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create tun: %v", err)
	}

	level := device.LogLevelError
	if base.Verbose {
		level = device.LogLevelVerbose
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(level, ""))

	if err := dev.IpcSet(base.String()); err != nil {
		return nil, nil, err
	}

	return dev, tnet, nil
}

func (config *WireguardBase) PrintInfo() {
	log.Info("Wireguard interface is UP:")
	log.Infof("  Local Address: %v", config.LocalAddress)
	log.Infof("  DNS: %v", config.Dns)
	for i := range config.Peers {
		log.Infof("  Peer: %+v", config.Peers[i])
	}
}
