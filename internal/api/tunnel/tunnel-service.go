package tunnel

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"

	netPrivate "github.com/gradusp/crispy-tunnel/internal/pkg/net"
	"github.com/gradusp/crispy-tunnel/pkg/tunnel"
	"github.com/gradusp/go-platform/logger"
	"github.com/gradusp/go-platform/pkg/slice"
	"github.com/gradusp/go-platform/server"
	grpcRt "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type tunnelService struct {
	tunnel.UnimplementedTunnelServiceServer

	appCtx context.Context
	sema   chan struct{}
}

var (
	_ tunnel.TunnelServiceServer = (*tunnelService)(nil)
	_ server.APIService          = (*tunnelService)(nil)
	_ server.APIGatewayProxy     = (*tunnelService)(nil)

	//go:embed tunnel.swagger.json
	rawSwagger []byte
)

const (
	mask32 = "/32"
)

var (
	reDetectRule = regexp.MustCompile(`(?i)tun\d*\b`)
)

type listLinksConsumer = func(netlink.Link) error

//NewTunnelService creates tunnel service
func NewTunnelService(ctx context.Context) server.APIService {
	ret := &tunnelService{
		appCtx: ctx,
		sema:   make(chan struct{}, 1),
	}
	runtime.SetFinalizer(ret, func(o *tunnelService) {
		close(o.sema)
	})
	return ret
}

//GetSwaggerDocs get swagger spec docs
func GetSwaggerDocs() (*server.SwaggerSpec, error) {
	const api = "tunnel/GetSwaggerDocs"
	ret := new(server.SwaggerSpec)
	err := json.Unmarshal(rawSwagger, ret)
	return ret, errors.Wrap(err, api)
}

//Description impl server.APIService
func (srv *tunnelService) Description() grpc.ServiceDesc {
	return tunnel.TunnelService_ServiceDesc
}

//RegisterGRPC impl server.APIService
func (srv *tunnelService) RegisterGRPC(_ context.Context, s *grpc.Server) error {
	tunnel.RegisterTunnelServiceServer(s, srv)
	return nil
}

//RegisterProxyGW impl server.APIGatewayProxy
func (srv *tunnelService) RegisterProxyGW(ctx context.Context, mux *grpcRt.ServeMux, c *grpc.ClientConn) error {
	return tunnel.RegisterTunnelServiceHandler(ctx, mux, c)
}

//AddTunnel impl tunnel service
func (srv *tunnelService) AddTunnel(ctx context.Context, req *tunnel.AddTunnelRequest) (resp *emptypb.Empty, err error) {
	dbgLvl := logger.IsLevelEnabled(ctx, zap.DebugLevel)
	defer func() {
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				err = status.FromContextError(err).Err()
			}
			if status.Code(errors.Cause(err)) == codes.Unknown {
				err = status.Errorf(codes.Internal, "%v", err)
			}
		}
	}()

	tunnelIP := req.GetTunDestIP()

	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.String("req-tunnel-IP", tunnelIP))

	var hcTunDestNetIP net.IP
	if hcTunDestNetIP, _, err = net.ParseCIDR(tunnelIP + mask32); err != nil {
		return nil, err
	}
	span.SetAttributes(attribute.String("hcTunDestNetIP", hcTunDestNetIP.String()))
	tunnelName := fmt.Sprintf("tun%v", netPrivate.IPType(hcTunDestNetIP).Int())
	span.SetAttributes(attribute.String("tunnel-name", tunnelName))

	var leave func()
	if leave, err = srv.enter(ctx); err != nil {
		return nil, err
	}
	defer leave()

	if dbgLvl {
		span.AddEvent("netlink.LinkByName",
			trace.WithAttributes(attribute.String("tunnel-name", tunnelName)))
	}
	if _, e := netlink.LinkByName(tunnelName); e == nil {
		return nil, status.Errorf(codes.AlreadyExists, "tunnel '%v'", tunnelName)
	} else if !errors.As(e, new(netlink.LinkNotFoundError)) {
		return nil, errors.Errorf("netlink.LinkByName('%s') -> %v", tunnelName, e)
	}
	linkNew := &netlink.Iptun{
		LinkAttrs: netlink.LinkAttrs{Name: tunnelName},
		Remote:    hcTunDestNetIP,
	}
	if dbgLvl {
		span.AddEvent("netlink.LinkAdd",
			trace.WithAttributes(
				attribute.String("tunnel-name", tunnelName),
				attribute.Stringer("remote", hcTunDestNetIP),
			),
		)
	}
	if err = netlink.LinkAdd(linkNew); err != nil {
		return nil, errors.Errorf("netlinkLinkAdd('%v') -> %v", tunnelName, err)
	}

	if dbgLvl {
		span.AddEvent("netlink.LinkSetUp",
			trace.WithAttributes(
				attribute.String("tunnel-name", tunnelName),
				attribute.Stringer("remote", hcTunDestNetIP),
			),
		)
	}
	if err = netlink.LinkSetUp(linkNew); err != nil {
		return nil, errors.Errorf("netlink.LinkSetUp('%v') -> %v", tunnelName, err)
	}

	args := []string{"-w", "net.ipv4.conf." + tunnelName + ".rp_filter=0"}
	cmd := exec.CommandContext(ctx, "sysctl", args...) //nolint:gosec
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Noctty: true,
	}
	if dbgLvl {
		span.AddEvent("exec:sysctl",
			trace.WithAttributes(
				attribute.StringSlice("args", args),
			),
		)
	}
	ch := make(chan error, 1)
	go func() {
		defer close(ch)
		ch <- cmd.Run()
	}()
	select {
	case <-srv.appCtx.Done():
		err = srv.appCtx.Err()
		if p := cmd.Process; p != nil {
			_ = p.Kill()
		}
	case err = <-ch:
	}
	if err != nil {
		return nil, errors.Errorf("exec:sysctl -w %s -> %v", args[1], err)
	}
	if ec := cmd.ProcessState.ExitCode(); ec != 0 {
		return nil, errors.Errorf("exec:sysctl -w %s -> exit-code:%v", args[1], ec)
	}
	return new(emptypb.Empty), nil
}

//RemoveTunnel impl tunnel service
func (srv *tunnelService) RemoveTunnel(ctx context.Context, req *tunnel.RemoveTunnelRequest) (resp *emptypb.Empty, err error) {
	dbgLvl := logger.IsLevelEnabled(ctx, zap.DebugLevel)
	defer func() {
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				err = status.FromContextError(err).Err()
			}
			if status.Code(errors.Cause(err)) == codes.Unknown {
				err = status.Errorf(codes.Internal, "%v", err)
			}
		}
	}()
	tunnelIP := req.GetTunDestIP()

	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.String("req-tunnel-IP", tunnelIP))

	var hcTunDestNetIP net.IP
	if hcTunDestNetIP, _, err = net.ParseCIDR(tunnelIP + mask32); err != nil {
		return nil, err
	}
	tunnelName := fmt.Sprintf("tun%v", netPrivate.IPType(hcTunDestNetIP).Int())

	var leave func()
	if leave, err = srv.enter(ctx); err != nil {
		return nil, err
	}
	defer leave()

	if dbgLvl {
		span.AddEvent("netlink.LinkByName",
			trace.WithAttributes(attribute.String("tunnel-name", tunnelName)))
	}
	var linkOld netlink.Link
	linkOld, err = netlink.LinkByName(tunnelName)
	if err != nil && !errors.As(err, new(netlink.LinkNotFoundError)) {
		return nil, errors.Errorf("netlink.LinkByName(%s) -> %v", tunnelName, err)
	}

	if dbgLvl {
		span.AddEvent("netlink.LinkSetDown",
			trace.WithAttributes(attribute.String("tunnel-name", tunnelName)))
	}
	if err = netlink.LinkSetDown(linkOld); err != nil {
		return nil, errors.Errorf("netlink.LinkSetDown(%s) -> %v", tunnelName, err)
	}

	if dbgLvl {
		span.AddEvent("netlink.LinkDel",
			trace.WithAttributes(attribute.String("tunnel-name", tunnelName)))
	}
	if err = netlink.LinkDel(linkOld); err != nil {
		return nil, errors.Errorf("netlink.LinkDel(%s) -> %v", tunnelName, err)
	}
	return new(emptypb.Empty), nil
}

//GetState impl tunnel service
func (srv *tunnelService) GetState(ctx context.Context, _ *emptypb.Empty) (*tunnel.GetStateResponse, error) {
	leave, err := srv.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer leave()
	ret := new(tunnel.GetStateResponse)
	err = srv.enumLinks(func(nl netlink.Link) error {
		ret.Tunnels = append(ret.Tunnels, nl.Attrs().Name)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(ret.Tunnels)
	_ = slice.DedupSlice(&ret.Tunnels, func(i, j int) bool {
		l, r := ret.Tunnels[i], ret.Tunnels[j]
		return strings.EqualFold(l, r)
	})
	return ret, nil
}

func (srv *tunnelService) enter(ctx context.Context) (leave func(), err error) {
	select {
	case <-srv.appCtx.Done():
		err = srv.appCtx.Err()
	case <-ctx.Done():
		err = ctx.Err()
	case srv.sema <- struct{}{}:
		var o sync.Once
		leave = func() {
			o.Do(func() {
				<-srv.sema
			})
		}
		return
	}
	err = status.FromContextError(err).Err()
	return
}

func (srv *tunnelService) enumLinks(c listLinksConsumer) error {
	const api = "tunnel/enumLinks"

	linkList, err := netlink.LinkList()
	if err != nil {
		return errors.Wrapf(err, "%s: netlink.LinkList", api)
	}
	for _, link := range linkList {
		a := link.Attrs()
		if a != nil && reDetectRule.MatchString(a.Name) {
			e := c(link)
			if e != nil {
				return e
			}
		}
	}
	return nil
}
