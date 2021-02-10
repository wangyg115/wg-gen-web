package wgapi

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var once sync.Once
var server *Server

type Server struct {
	wg         *wgctrl.Client
	deviceName string
}

// NewServer initializes a Server with a WireGuard
func NewServer(wg *wgctrl.Client, deviceName string) (*Server, error) {
	if server == nil {
		return &Server{wg: wg, deviceName: deviceName}, nil
	}
	return server, nil
}

func New() (*Server, error) {
	if server == nil {
		client, err := wgctrl.New()
		if err != nil {
			return nil, err
		}
		deviceName := os.Getenv("WG_DEVICE_NAME")
		if deviceName == "" {
			return nil, Error{Message: "env var WG_DEVICE_NAME not set."}
		}
		device, err := client.Device(deviceName)
		if err != nil {
			return nil, err
		}
		return &Server{wg: client, deviceName: device.Name}, nil
	}
	return server, nil
}

// GetDeviceInfo returns information such as the public key and type of
// interface for the currently configured device.
func (s *Server) GetDeviceInfo() (*GetDeviceInfoResponse, error) {
	dev, err := s.wg.Device(s.deviceName)
	if err != nil {
		return nil, fmt.Errorf("could not get WireGuard device: %w", err)
	}

	return &GetDeviceInfoResponse{
		Device: &Device{
			Name:         dev.Name,
			Type:         dev.Type.String(),
			PublicKey:    dev.PublicKey.String(),
			ListenPort:   dev.ListenPort,
			FirewallMark: dev.FirewallMark,
			NumPeers:     len(dev.Peers),
		},
	}, nil
}

func validateListPeersRequest(req *ListPeersRequest) error {
	if req == nil {
		return InvalidParams("request body required", nil)
	}

	if req.Limit < 0 {
		return InvalidParams("limit must be positive integer", nil)
	} else if req.Offset < 0 {
		return InvalidParams("offset must be positive integer", nil)
	}

	return nil
}

// ListPeers retrieves information about all Peers known to the current
// WireGuard interface, including allowed IP addresses and usage stats,
// optionally with pagination.
func (s *Server) ListPeers() (*ListPeersResponse, error) {

	dev, err := s.wg.Device(s.deviceName)
	if err != nil {
		return nil, fmt.Errorf("could not get WireGuard device: %w", err)
	}

	var peers []*Peer

	for _, peer := range dev.Peers {
		peers = append(peers, peer2rpc(peer))
	}

	// TODO(jc): pagination

	return &ListPeersResponse{
		Peers: peers,
	}, nil
}

func peer2rpc(peer wgtypes.Peer) *Peer {
	var keepAlive string
	if peer.PersistentKeepaliveInterval > 0 {
		keepAlive = peer.PersistentKeepaliveInterval.String()
	}

	var allowedIPs []string
	for _, allowedIP := range peer.AllowedIPs {
		allowedIPs = append(allowedIPs, allowedIP.String())
	}

	return &Peer{
		PublicKey:           peer.PublicKey.String(),
		HasPresharedKey:     peer.PresharedKey != wgtypes.Key{},
		Endpoint:            peer.Endpoint.String(),
		PersistentKeepAlive: keepAlive,
		LastHandshake:       peer.LastHandshakeTime,
		ReceiveBytes:        peer.ReceiveBytes,
		TransmitBytes:       peer.TransmitBytes,
		AllowedIPs:          allowedIPs,
		ProtocolVersion:     peer.ProtocolVersion,
	}
}

func validateGetPeerRequest(req *GetPeerRequest) error {
	if req == nil {
		return InvalidParams("request body required", nil)
	}

	if req.PublicKey == "" {
		return InvalidParams("public key is required", nil)
	} else if len(req.PublicKey) != 44 {
		return InvalidParams("malformed public key", nil)
	}

	_, err := wgtypes.ParseKey(req.PublicKey)
	if err != nil {
		return InvalidParams("invalid public key: "+err.Error(), nil)
	}

	return nil
}

// GetPeer retrieves a specific Peer by their public key.
func (s *Server) GetPeer(req *GetPeerRequest) (*GetPeerResponse, error) {
	if err := validateGetPeerRequest(req); err != nil {
		return nil, err
	}

	dev, err := s.wg.Device(s.deviceName)
	if err != nil {
		return nil, fmt.Errorf("could not get WireGuard device: %w", err)
	}

	publicKey, err := wgtypes.ParseKey(req.PublicKey)
	if err != nil {
		return nil, InvalidParams("invalid public key: "+err.Error(), nil)
	}

	for _, peer := range dev.Peers {
		if peer.PublicKey == publicKey {
			return &GetPeerResponse{
				Peer: peer2rpc(peer),
			}, nil
		}
	}

	return &GetPeerResponse{}, nil
}

func validateAddPeerRequest(req *AddPeerRequest) error {
	if req == nil {
		return InvalidParams("request body required", nil)
	}

	if req.PublicKey == "" {
		return InvalidParams("public key is required", nil)
	} else if len(req.PublicKey) != 44 {
		return InvalidParams("malformed public key", nil)
	}

	_, err := wgtypes.ParseKey(req.PublicKey)
	if err != nil {
		return InvalidParams("invalid public key: "+err.Error(), nil)
	}

	if req.PresharedKey != "" {
		if len(req.PresharedKey) != 44 {
			return InvalidParams("malformed preshared key", nil)
		}

		_, err := wgtypes.ParseKey(req.PresharedKey)
		if err != nil {
			return InvalidParams("invalid preshared key: "+err.Error(), nil)
		}
	}

	if req.Endpoint != "" {
		_, err := net.ResolveUDPAddr("udp", req.Endpoint)
		if err != nil {
			return InvalidParams("invalid endpoint: "+err.Error(), nil)
		}
	}

	if req.PersistentKeepAlive != "" {
		_, err := time.ParseDuration(req.PersistentKeepAlive)
		if err != nil {
			return InvalidParams("invalid keepalive: "+err.Error(), nil)
		}
	}

	for _, allowedIP := range req.AllowedIPs {
		_, _, err := net.ParseCIDR(allowedIP)
		if err != nil {
			return InvalidParams(fmt.Sprintf("range %q is not valid: %s", allowedIP, err), nil)
		}
	}

	return nil
}

// AddPeer inserts a new Peer into the WireGuard interfaces table, multiple
// calls to AddPeer can be used to update details of the Peer.
func (s *Server) AddPeer(req *AddPeerRequest) (*CfgPeerResponse, error) {
	if err := validateAddPeerRequest(req); err != nil {
		return nil, err
	} else if req.ValidateOnly {
		return &CfgPeerResponse{}, nil
	}

	publicKey, err := wgtypes.ParseKey(req.PublicKey)
	if err != nil {
		return nil, InvalidParams("invalid public key: "+err.Error(), nil)
	}

	peer := wgtypes.PeerConfig{PublicKey: publicKey}

	if req.PresharedKey != "" {
		pk, err := wgtypes.ParseKey(req.PresharedKey)
		if err != nil {
			return nil, InvalidParams("invalid preshared key: "+err.Error(), nil)
		}

		peer.PresharedKey = &pk
	}

	if req.Endpoint != "" {
		addr, err := net.ResolveUDPAddr("udp", req.Endpoint)
		if err != nil {
			return nil, InvalidParams("invalid endpoint: "+err.Error(), nil)
		}

		peer.Endpoint = addr
	}

	if req.PersistentKeepAlive != "" {
		d, err := time.ParseDuration(req.PersistentKeepAlive)
		if err != nil {
			return nil, InvalidParams("invalid keepalive: "+err.Error(), nil)
		}

		peer.PersistentKeepaliveInterval = &d
	}

	for _, allowedIP := range req.AllowedIPs {
		_, aip, err := net.ParseCIDR(allowedIP)
		if err != nil {
			return nil, InvalidParams(fmt.Sprintf("range %q is not valid: %s", allowedIP, err), nil)
		}

		peer.AllowedIPs = append(peer.AllowedIPs, *aip)
	}

	err = s.wg.ConfigureDevice(s.deviceName, wgtypes.Config{Peers: []wgtypes.PeerConfig{peer}})
	if err != nil {
		return nil, fmt.Errorf("could not configure WireGuard device: %w", err)
	}

	return &CfgPeerResponse{OK: true}, nil
}

func validateRemovePeerRequest(req *RemovePeerRequest) error {
	if req == nil {
		return InvalidParams("request body required", nil)
	}

	if req.PublicKey == "" {
		return InvalidParams("public key is required", nil)
	} else if len(req.PublicKey) != 44 {
		return InvalidParams("malformed public key", nil)
	}

	_, err := wgtypes.ParseKey(req.PublicKey)
	if err != nil {
		return InvalidParams("invalid public key: "+err.Error(), nil)
	}

	return nil
}

// RemovePeer deletes a Peer from the WireGuard interfaces table by their
// public key,
func (s *Server) RemovePeer(req *RemovePeerRequest) (*CfgPeerResponse, error) {
	if err := validateRemovePeerRequest(req); err != nil {
		return nil, err
	} else if req.ValidateOnly {
		return &CfgPeerResponse{}, nil
	}

	publicKey, err := wgtypes.ParseKey(req.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	peer := wgtypes.PeerConfig{
		PublicKey: publicKey,
		Remove:    true,
	}

	err = s.wg.ConfigureDevice(s.deviceName, wgtypes.Config{Peers: []wgtypes.PeerConfig{peer}})
	if err != nil {
		return nil, fmt.Errorf("could not configure WireGuard device: %w", err)
	}

	return &CfgPeerResponse{OK: true}, nil
}
