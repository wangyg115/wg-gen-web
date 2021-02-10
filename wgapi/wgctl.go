package wgapi

import (
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"gitlab.127-0-0-1.fr/vx3r/wg-gen-web/core"
	"gitlab.127-0-0-1.fr/vx3r/wg-gen-web/model"
)

//var s, _ = New()

// ApplyRoutes applies router to gin Router
func ApplyRoutes(r *gin.RouterGroup) {
	g := r.Group("/status")
	{
		g.GET("/enabled", readEnabled)
		g.GET("/interface", readInterfaceStatus)
		g.GET("/clients", readClientStatus)
	}
}

func readEnabled(c *gin.Context) {
	c.JSON(http.StatusOK, Enabeled())
}

func Enabeled() bool {
	return os.Getenv("WG_DEVICE_NAME") != ""
}

func readInterfaceStatus(c *gin.Context) {
	interfaceStatus := &model.InterfaceStatus{
		Name:          "unknown",
		DeviceType:    "unknown",
		ListenPort:    0,
		NumberOfPeers: 0,
		PublicKey:     "",
	}
	var s, _ = New()
	st, err := s.GetDeviceInfo()
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Error("failed to read interface status")
		c.AbortWithStatusJSON(http.StatusInternalServerError, err.Error())
		return
	}
	interfaceStatus.Name = st.Device.Name
	interfaceStatus.DeviceType = st.Device.Type
	interfaceStatus.ListenPort = st.Device.ListenPort
	interfaceStatus.NumberOfPeers = st.Device.NumPeers
	interfaceStatus.PublicKey = st.Device.PublicKey

	c.JSON(http.StatusOK, interfaceStatus)
}

func readClientStatus(c *gin.Context) {
	status, err := clientStatus()
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Error("failed to read client status")
		c.AbortWithStatusJSON(http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, status)
}

func clientStatus() ([]*model.ClientStatus, error) {
	var clientStatus []*model.ClientStatus

	var s, err = New()
	if err != nil {
		return clientStatus, err
	}
	st, err := s.ListPeers()
	if err != nil {
		return clientStatus, err
	}
	clients, err := core.ReadClients()
	withClientDetails := true
	if err != nil {
		withClientDetails = false
	}
	for _, peer := range st.Peers {
		peerHandshake := peer.LastHandshake
		peerHandshakeRelative := time.Since(peerHandshake)
		peerActive := peerHandshakeRelative.Minutes() < 3 // TODO: we need a better detection... ping for example?
		newClientStatus := &model.ClientStatus{
			PublicKey:             peer.PublicKey,
			HasPresharedKey:       peer.HasPresharedKey,
			ProtocolVersion:       peer.ProtocolVersion,
			Name:                  "UNKNOWN",
			Email:                 "UNKNOWN",
			Connected:             peerActive,
			AllowedIPs:            peer.AllowedIPs,
			Endpoint:              peer.Endpoint,
			LastHandshake:         peerHandshake,
			LastHandshakeRelative: peerHandshakeRelative,
			ReceivedBytes:         int(peer.ReceiveBytes),
			TransmittedBytes:      int(peer.TransmitBytes),
		}

		if withClientDetails {
			for _, client := range clients {
				if client.PublicKey != newClientStatus.PublicKey {
					continue
				}

				newClientStatus.Name = client.Name
				newClientStatus.Email = client.Email
				break
			}
		}

		clientStatus = append(clientStatus, newClientStatus)
	}

	sort.Slice(clientStatus, func(i, j int) bool {
		return clientStatus[i].LastHandshakeRelative < clientStatus[j].LastHandshakeRelative
	})

	return clientStatus, nil
}

func updatePeerCall(peer model.Peer, enable bool) (*model.Resp, error) {
	var s, err = New()
	if err != nil {
		return nil, err
	}
	if enable {
		rq := AddPeerRequest{
			AllowedIPs:   peer.AllowedIPs,
			PublicKey:    peer.PublicKey,
			PresharedKey: peer.PresharedKey,
		}
		rsp, err := s.AddPeer(&rq)
		if err != nil {
			return nil, err
		}
		return &model.Resp{OK: rsp.OK}, nil
	}
	rq := RemovePeerRequest{
		PublicKey: peer.PublicKey,
	}
	rsp, err := s.RemovePeer(&rq)
	if err != nil {
		return nil, err
	}
	return &model.Resp{OK: rsp.OK}, nil
}

func UpdatePeer(peer model.Peer, enable bool) (*model.Resp, error) {
	if Enabeled() {
		return updatePeerCall(peer, enable)
	}
	return core.UpdatePeer(peer, enable)
}
