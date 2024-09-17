package pkg

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gopkg.in/dealancer/validate.v2"
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

func (base WireguardBase) Validate() error {
	privateKeyCount := len(base.PrivateKey) / device.NoisePrivateKeySize

	if base.BrokerIndex >= privateKeyCount {
		return errors.New("broker index beyond private key count")
	}

	return nil
}

func (base WireguardBase) GenerateConfig() string {
	sb := strings.Builder{}

	indexedPrivateKey := base.PrivateKey[device.NoisePrivateKeySize*base.BrokerIndex : device.NoisePrivateKeySize*(base.BrokerIndex+1)]

	sb.WriteString(fmt.Sprintf("private_key=%s\n", hex.EncodeToString(indexedPrivateKey)))
	sb.WriteString(fmt.Sprintf("listen_port=%d\n", base.ListenPort))

	for i := range base.Peers {
		base.Peers[i].WriteTo(&sb)
	}

	return sb.String()
}

func (base *WireguardBase) ResolveConfig() error {
	resolvedLocalAddress, err := netip.ParseAddr(base.LocalAddress)
	if err != nil {
		return fmt.Errorf("LocalAddress parse failed: %v", err)
	}
	for i := 0; i < base.BrokerIndex; i++ {
		resolvedLocalAddress = resolvedLocalAddress.Next()
	}
	base.resolvedLocalAddress = resolvedLocalAddress

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

func (config *WireguardBase) Start() (*netstack.Net, func() error, error) {
	// ensure config is valid
	if err := validate.Validate(config); err != nil {
		return nil, nil, fmt.Errorf("invalid wireguard config: %v", err)
	}

	// resolve local address and peer endpoints (if not IP address already)
	if err := config.ResolveConfig(); err != nil {
		return nil, nil, fmt.Errorf("failed to resolve peer endpoint: %v", err)
	}

	var dnsAddresses = make([]netip.Addr, len(config.Dns))
	for i := range config.Dns {
		dnsAddresses[i] = netip.MustParseAddr(config.Dns[i])
	}

	// create the wireguard interface
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{config.resolvedLocalAddress},
		dnsAddresses,
		config.Mtu,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create wireguard tun: %v", err)
	}

	level := device.LogLevelError
	if config.Verbose {
		level = device.LogLevelVerbose
	}

	// create wireguard device
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(level, ""))

	// apply wireguard configs
	if err := dev.IpcSet(config.GenerateConfig()); err != nil {
		return nil, nil, fmt.Errorf("failed to apply wireguard configs: %v", err)
	}

	// finally, bring up the device
	if err := dev.Up(); err != nil {
		return nil, nil, fmt.Errorf("failed to bring up wireguard device: %v", err)
	}

	return tnet, dev.Down, nil
}
