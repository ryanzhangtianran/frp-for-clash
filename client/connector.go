// Copyright 2023 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"cmp"
	"context"
	"crypto/tls"
	"math"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	libnet "github.com/fatedier/golib/net"
	fmux "github.com/fatedier/yamux"
	quic "github.com/quic-go/quic-go"
	"github.com/samber/lo"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/proto/wire"
	"github.com/fatedier/frp/pkg/transport"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/xlog"
)

// Connector is an interface for establishing connections to the server.
type Connector interface {
	Open() error
	Connect() (net.Conn, error)
	Close() error
}

type MessageConnector interface {
	Connect() (*msg.Conn, error)
	Close() error
}

type messageConnector struct {
	connector    Connector
	wireProtocol string
}

func newMessageConnector(connector Connector, wireProtocol string) *messageConnector {
	return &messageConnector{
		connector:    connector,
		wireProtocol: wireProtocol,
	}
}

func (c *messageConnector) Connect() (*msg.Conn, error) {
	conn, err := c.connector.Connect()
	if err != nil {
		return nil, err
	}
	if err = wire.WriteMagicIfV2(conn, c.wireProtocol); err != nil {
		conn.Close()
		return nil, err
	}
	return msg.NewConn(conn, msg.NewReadWriter(conn, c.wireProtocol)), nil
}

func (c *messageConnector) Close() error {
	return c.connector.Close()
}

// defaultConnectorImpl is the default implementation of Connector for normal frpc.
// DialFunc dials the frps server address over a caller-controlled transport.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type defaultConnectorImpl struct {
	ctx    context.Context
	cfg    *v1.ClientCommonConfig
	dialer DialFunc

	muxSession *fmux.Session
	quicConn   *quic.Conn
	closeOnce  sync.Once
}

func NewConnector(ctx context.Context, cfg *v1.ClientCommonConfig) Connector {
	return NewConnectorWithDialer(ctx, cfg, nil)
}

// NewConnectorWithDialer is NewConnector with a custom dialer for tcp/websocket/wss transports.
// The dialer replaces transport.proxyURL and transport.connectServerLocalIP; quic and kcp ignore it.
func NewConnectorWithDialer(ctx context.Context, cfg *v1.ClientCommonConfig, dialer DialFunc) Connector {
	return &defaultConnectorImpl{
		ctx:    ctx,
		cfg:    cfg,
		dialer: dialer,
	}
}

// Open opens an underlying connection to the server.
// The underlying connection is either a TCP connection or a QUIC connection.
// After the underlying connection is established, you can call Connect() to get a stream.
// If TCPMux isn't enabled, the underlying connection is nil, you will get a new real TCP connection every time you call Connect().
func (c *defaultConnectorImpl) Open() error {
	xl := xlog.FromContextSafe(c.ctx)

	// special for quic
	if strings.EqualFold(c.cfg.Transport.Protocol, "quic") {
		var tlsConfig *tls.Config
		var err error
		sn := c.cfg.Transport.TLS.ServerName
		if sn == "" {
			sn = c.cfg.ServerAddr
		}
		if lo.FromPtr(c.cfg.Transport.TLS.Enable) {
			tlsConfig, err = transport.NewClientTLSConfig(
				c.cfg.Transport.TLS.CertFile,
				c.cfg.Transport.TLS.KeyFile,
				c.cfg.Transport.TLS.TrustedCaFile,
				sn)
		} else {
			tlsConfig, err = transport.NewClientTLSConfig("", "", "", sn)
		}
		if err != nil {
			xl.Warnf("fail to build tls configuration, err: %v", err)
			return err
		}
		tlsConfig.NextProtos = []string{"frp"}

		conn, err := quic.DialAddr(
			c.ctx,
			net.JoinHostPort(c.cfg.ServerAddr, strconv.Itoa(c.cfg.ServerPort)),
			tlsConfig, &quic.Config{
				MaxIdleTimeout:     time.Duration(c.cfg.Transport.QUIC.MaxIdleTimeout) * time.Second,
				MaxIncomingStreams: int64(c.cfg.Transport.QUIC.MaxIncomingStreams),
				KeepAlivePeriod:    time.Duration(c.cfg.Transport.QUIC.KeepalivePeriod) * time.Second,
			})
		if err != nil {
			return err
		}
		c.quicConn = conn
		return nil
	}

	if !lo.FromPtr(c.cfg.Transport.TCPMux) {
		return nil
	}

	conn, err := c.realConnect()
	if err != nil {
		return err
	}

	fmuxCfg := fmux.DefaultConfig()
	fmuxCfg.KeepAliveInterval = time.Duration(c.cfg.Transport.TCPMuxKeepaliveInterval) * time.Second
	// Use trace level for yamux logs
	fmuxCfg.LogOutput = xlog.NewTraceWriter(xl)
	fmuxCfg.MaxStreamWindowSize = 6 * 1024 * 1024
	session, err := fmux.Client(conn, fmuxCfg)
	if err != nil {
		conn.Close()
		return err
	}
	c.muxSession = session
	return nil
}

// Connect returns a stream from the underlying connection, or a new TCP connection if TCPMux isn't enabled.
func (c *defaultConnectorImpl) Connect() (net.Conn, error) {
	if c.quicConn != nil {
		stream, err := c.quicConn.OpenStreamSync(context.Background())
		if err != nil {
			return nil, err
		}
		return netpkg.QuicStreamToNetConn(stream, c.quicConn), nil
	} else if c.muxSession != nil {
		stream, err := c.muxSession.OpenStream()
		if err != nil {
			return nil, err
		}
		return stream, nil
	}

	return c.realConnect()
}

func (c *defaultConnectorImpl) realConnect() (net.Conn, error) {
	xl := xlog.FromContextSafe(c.ctx)
	var tlsConfig *tls.Config
	var err error
	tlsEnable := lo.FromPtr(c.cfg.Transport.TLS.Enable)
	if c.cfg.Transport.Protocol == "wss" {
		tlsEnable = true
	}
	if tlsEnable {
		sn := c.cfg.Transport.TLS.ServerName
		if sn == "" {
			sn = c.cfg.ServerAddr
		}

		tlsConfig, err = transport.NewClientTLSConfig(
			c.cfg.Transport.TLS.CertFile,
			c.cfg.Transport.TLS.KeyFile,
			c.cfg.Transport.TLS.TrustedCaFile,
			sn)
		if err != nil {
			xl.Warnf("fail to build tls configuration, err: %v", err)
			return nil, err
		}
	}

	addr := net.JoinHostPort(c.cfg.ServerAddr, strconv.Itoa(c.cfg.ServerPort))
	hooks := []libnet.AfterHook{}
	addTLSHook := func(priority uint64) {
		if tlsConfig != nil {
			hooks = append(hooks, libnet.AfterHook{Priority: priority, Hook: func(ctx context.Context, conn net.Conn, _ string) (context.Context, net.Conn, error) {
				return ctx, tls.Client(conn, tlsConfig), nil
			}})
		}
	}
	tlsHeadByteHook := libnet.AfterHook{
		Priority: libnet.DefaultAfterHookPriority,
		Hook:     netpkg.DialHookCustomTLSHeadByte(tlsConfig != nil, lo.FromPtr(c.cfg.Transport.TLS.DisableCustomTLSFirstByte)),
	}
	protocol := c.cfg.Transport.Protocol
	switch protocol {
	case "websocket":
		protocol = "tcp"
		hooks = append(hooks, libnet.AfterHook{Priority: libnet.DefaultAfterHookPriority, Hook: netpkg.DialHookWebsocket(protocol, "")}, tlsHeadByteHook)
		addTLSHook(math.MaxUint64)
	case "wss":
		protocol = "tcp"
		addTLSHook(100)
		// Make sure that if it is wss, the websocket hook is executed after the tls hook.
		hooks = append(hooks, libnet.AfterHook{Hook: netpkg.DialHookWebsocket(protocol, tlsConfig.ServerName), Priority: 110})
	default:
		hooks = append(hooks, tlsHeadByteHook)
		addTLSHook(math.MaxUint64)
	}

	if c.dialer != nil && protocol == "tcp" {
		return dialWithHooks(c.ctx, c.dialer, addr, hooks)
	}

	proxyType, proxyAddr, auth, err := libnet.ParseProxyURL(c.cfg.Transport.ProxyURL)
	if err != nil {
		xl.Errorf("fail to parse proxy url")
		return nil, err
	}
	dialOptions := []libnet.DialOption{}
	for _, h := range hooks {
		dialOptions = append(dialOptions, libnet.WithAfterHook(h))
	}
	if c.cfg.Transport.ConnectServerLocalIP != "" {
		dialOptions = append(dialOptions, libnet.WithLocalAddr(c.cfg.Transport.ConnectServerLocalIP))
	}
	dialOptions = append(dialOptions,
		libnet.WithProtocol(protocol),
		libnet.WithTimeout(time.Duration(c.cfg.Transport.DialServerTimeout)*time.Second),
		libnet.WithKeepAlive(time.Duration(c.cfg.Transport.DialServerKeepAlive)*time.Second),
		libnet.WithProxy(proxyType, proxyAddr),
		libnet.WithProxyAuth(auth),
	)
	return libnet.DialContext(c.ctx, addr, dialOptions...)
}

// dialWithHooks mirrors libnet.DialContext's after-hook handling for a caller-supplied dialer.
func dialWithHooks(ctx context.Context, dial DialFunc, addr string, hooks []libnet.AfterHook) (net.Conn, error) {
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(hooks, func(a, b libnet.AfterHook) int { return cmp.Compare(a.Priority, b.Priority) })
	for _, h := range hooks {
		var next net.Conn
		if ctx, next, err = h.Hook(ctx, conn, addr); err != nil {
			conn.Close()
			return nil, err
		}
		conn = next
	}
	return conn, nil
}

func (c *defaultConnectorImpl) Close() error {
	c.closeOnce.Do(func() {
		if c.quicConn != nil {
			_ = c.quicConn.CloseWithError(0, "")
		}
		if c.muxSession != nil {
			_ = c.muxSession.Close()
		}
	})
	return nil
}
