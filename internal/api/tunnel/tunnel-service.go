package tunnel

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

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
	var leave func()
	if leave, err = srv.enter(ctx); err != nil {
		return nil, err
	}
	defer func() {
		leave()
		err = srv.correctError(err)
	}()

	tunnelIP := req.GetTunDestIP()

	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.String("tunDestIP", tunnelIP))

	var hcTunDestNetIP net.IP
	if hcTunDestNetIP, _, err = net.ParseCIDR(tunnelIP + mask32); err != nil {
		err = status.Errorf(codes.InvalidArgument, "bad 'tunDestIP': %v",
			errors.WithMessagef(err, "net.ParseCIDR(%s)", tunnelIP+mask32),
		)
		return
	}
	span.SetAttributes(attribute.String("hcTunDestNetIP", hcTunDestNetIP.String()))
	tunnelName := fmt.Sprintf("tun%v", netPrivate.IPType(hcTunDestNetIP).Int())
	span.SetAttributes(attribute.String("tunnel-name", tunnelName))

	if _, err = netlink.LinkByName(tunnelName); err == nil {
		err = status.Errorf(codes.AlreadyExists, "tunnel '%v'", tunnelName)
		return
	} else if !errors.As(err, new(netlink.LinkNotFoundError)) {
		err = errors.Wrapf(err, "netlink/LinkByName '%s'", tunnelName)
		return
	}
	linkNew := &netlink.Iptun{
		LinkAttrs: netlink.LinkAttrs{Name: tunnelName},
		Remote:    hcTunDestNetIP,
	}

	srv.addSpanDbgEvent(ctx, span, "netlink/LinkAdd",
		trace.WithAttributes(
			attribute.String("tunnel-name", tunnelName),
			attribute.Stringer("remoteIP", hcTunDestNetIP),
		))
	if err = netlink.LinkAdd(linkNew); err != nil {
		err = errors.Wrapf(err, "netlink/LinkAdd '%v'", tunnelName)
		return
	}
	srv.addSpanDbgEvent(ctx, span, "netlink/LinkSetUp")
	if err = netlink.LinkSetUp(linkNew); err != nil {
		err = errors.Wrapf(err, "netlink/LinkSetUp '%v'", tunnelName)
		return
	}
	srv.addSpanDbgEvent(ctx, span, "new-rp-filter",
		trace.WithAttributes(
			attribute.String("tunnelName", tunnelName),
		),
	)
	if err = srv.newRpFilter(ctx, tunnelName); err != nil {
		err = errors.Wrapf(err, "new-rp-filter '%s'", tunnelName)
	}
	return new(emptypb.Empty), err
}

//RemoveTunnel impl tunnel service
func (srv *tunnelService) RemoveTunnel(ctx context.Context, req *tunnel.RemoveTunnelRequest) (resp *emptypb.Empty, err error) {
	tunnelIP := req.GetTunDestIP()
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.String("tunnel-IP", tunnelIP))

	var leave func()
	if leave, err = srv.enter(ctx); err != nil {
		return nil, err
	}
	defer func() {
		leave()
		err = srv.correctError(err)
	}()

	var hcTunDestNetIP net.IP
	if hcTunDestNetIP, _, err = net.ParseCIDR(tunnelIP + mask32); err != nil {
		err = status.Errorf(codes.InvalidArgument, "'tunDestIP': %v",
			errors.Wrapf(err, "net.ParseCIDR(%s)", tunnelIP+mask32),
		)
		return
	}
	tunnelName := fmt.Sprintf("tun%v", netPrivate.IPType(hcTunDestNetIP).Int())

	var linkOld netlink.Link
	linkOld, err = netlink.LinkByName(tunnelName)
	if errors.As(err, new(netlink.LinkNotFoundError)) {
		err = status.Errorf(codes.NotFound, "tunnel '%v' is not found", tunnelName)
		return
	} else if err != nil {
		err = errors.WithMessagef(err, "netlink/LinkByName '%s'", tunnelName)
		return
	}
	srv.addSpanDbgEvent(ctx, span, "netlink.LinkSetDown",
		trace.WithAttributes(attribute.String("tunnel-name", tunnelName)),
	)
	if err = netlink.LinkSetDown(linkOld); err != nil {
		err = errors.WithMessagef(err, "netlink/LinkSetDown '%s'", tunnelName)
		return
	}
	srv.addSpanDbgEvent(ctx, span, "netlink/LinkDel",
		trace.WithAttributes(attribute.String("tunnel-name", tunnelName)),
	)
	if err = netlink.LinkDel(linkOld); err != nil {
		err = errors.WithMessagef(err, "netlink/LinkDel '%s'", tunnelName)
	}
	return new(emptypb.Empty), err
}

//GetState impl tunnel service
func (srv *tunnelService) GetState(ctx context.Context, _ *emptypb.Empty) (*tunnel.GetStateResponse, error) {
	leave, err := srv.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		leave()
		err = srv.correctError(err)
	}()
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

func (srv *tunnelService) correctError(err error) error {
	if err != nil && status.Code(err) == codes.Unknown {
		switch errors.Cause(err) {
		case context.DeadlineExceeded:
			return status.New(codes.DeadlineExceeded, err.Error()).Err()
		case context.Canceled:
			return status.New(codes.Canceled, err.Error()).Err()
		default:
			if e := new(url.Error); errors.As(err, &e) {
				switch errors.Cause(e.Err) {
				case context.Canceled:
					return status.New(codes.Canceled, err.Error()).Err()
				case context.DeadlineExceeded:
					return status.New(codes.DeadlineExceeded, err.Error()).Err()
				default:
					if e.Timeout() {
						return status.New(codes.DeadlineExceeded, err.Error()).Err()
					}
				}
			}
			err = status.New(codes.Internal, err.Error()).Err()
		}
	}
	return err
}

func (srv *tunnelService) addSpanDbgEvent(ctx context.Context, span trace.Span, eventName string, opts ...trace.EventOption) {
	if logger.IsLevelEnabled(ctx, zap.DebugLevel) {
		span.AddEvent(eventName, opts...)
	}
}

func (srv *tunnelService) newRpFilter(ctx context.Context, tunnelName string) error {
	const cmd = "sysctl"
	args := fmt.Sprintf("-w net.ipv4.conf.%s.rp_filter=0", tunnelName)
	ec, err := srv.execExternal(ctx, nil, cmd, strings.Split(args, " ")...)
	if err != nil {
		return errors.Wrapf(err, "exec-of '%s %s'", cmd, args)
	}
	if ec != 0 {
		return errors.Errorf("exec-of '%s %s' -> exit code %v", cmd, args, ec)
	}
	return nil
}

func (srv *tunnelService) execExternal(ctx context.Context, output io.Writer, command string, args ...string) (exitCode int, err error) {
	cmd := exec.Command(command, args...) //nolint:gosec
	if output != nil {
		cmd.Stdout = output
	}
	if err = cmd.Start(); err != nil {
		return
	}
	ch := make(chan error, 1)
	go func() {
		defer close(ch)
		ch <- cmd.Wait()
	}()
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-srv.appCtx.Done():
		err = srv.appCtx.Err()
	case err = <-ch:
		if err == nil {
			exitCode = cmd.ProcessState.ExitCode()
		}
	}
	if err == context.Canceled || err == context.DeadlineExceeded {
		_ = cmd.Process.Kill()
	}
	return
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
		return errors.Wrapf(err, "%s: netlink/LinkList", api)
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
