package lib

import (
	"context"
	gonmap "github.com/qiwentaidi/gonmap"
)

type SubnetDiscoveryOptions = gonmap.SubnetDiscoveryOptions
type SubnetDiscoveryResult = gonmap.SubnetDiscoveryResult

func DefaultSubnetDiscoveryOptions() SubnetDiscoveryOptions {
	return gonmap.DefaultSubnetDiscoveryOptions()
}

func (s *SDK) DiscoverSubnets(cidrs []string, options *SubnetDiscoveryOptions) ([]SubnetDiscoveryResult, error) {
	return s.DiscoverSubnetsWithContext(context.Background(), cidrs, options)
}

func (s *SDK) DiscoverSubnetsWithContext(ctx context.Context, cidrs []string, options *SubnetDiscoveryOptions) ([]SubnetDiscoveryResult, error) {
	merged := DefaultSubnetDiscoveryOptions()
	if options != nil {
		merged = *options
	}
	if merged.TCP.ProxyURL == "" {
		merged.TCP.ProxyURL = s.defaultScanOptions.ProxyURL
	}
	return gonmap.DiscoverSubnetsWithContext(ctx, cidrs, &merged)
}
