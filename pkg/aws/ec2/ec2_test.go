// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ec2

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

type Filters []ec2_types.Filter

func (s Filters) Len() int           { return len(s) }
func (s Filters) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s Filters) Less(i, j int) bool { return strings.Compare(*s[i].Name, *s[j].Name) > 0 }

func TestNewSubnetsFilters(t *testing.T) {
	type args struct {
		tags map[string]string
		ids  []string
	}
	tests := []struct {
		name string
		args args
		want []ec2_types.Filter
	}{
		{
			name: "empty arguments",
			args: args{
				tags: map[string]string{},
				ids:  []string{},
			},
			want: []ec2_types.Filter{},
		},

		{
			name: "ids only",
			args: args{
				tags: map[string]string{},
				ids:  []string{"a", "b"},
			},
			want: []ec2_types.Filter{
				{
					Name:   aws.String("subnet-id"),
					Values: []string{"a", "b"},
				},
			},
		},

		{
			name: "tags only",
			args: args{
				tags: map[string]string{"a": "b", "c": "d"},
				ids:  []string{},
			},
			want: []ec2_types.Filter{
				{
					Name:   aws.String("tag:a"),
					Values: []string{"b"},
				},
				{
					Name:   aws.String("tag:c"),
					Values: []string{"d"},
				},
			},
		},

		{
			name: "tags and ids",
			args: args{
				tags: map[string]string{"a": "b"},
				ids:  []string{"c", "d"},
			},
			want: []ec2_types.Filter{
				{
					Name:   aws.String("tag:a"),
					Values: []string{"b"},
				},
				{
					Name:   aws.String("subnet-id"),
					Values: []string{"c", "d"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewSubnetsFilters(tt.args.tags, tt.args.ids)
			sort.Sort(Filters(got))
			sort.Sort(Filters(tt.want))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSubnetsFilters() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewTagsFilters(t *testing.T) {
	type args struct {
		tags map[string]string
	}
	tests := []struct {
		name string
		args args
		want []ec2_types.Filter
	}{
		{
			name: "empty arguments",
			args: args{
				tags: map[string]string{},
			},
			want: []ec2_types.Filter{},
		},

		{
			name: "tags",
			args: args{
				tags: map[string]string{"a": "b", "c": "d"},
			},
			want: []ec2_types.Filter{
				{
					Name:   aws.String("tag:a"),
					Values: []string{"b"},
				},
				{
					Name:   aws.String("tag:c"),
					Values: []string{"d"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewTagsFilter(tt.args.tags)
			sort.Sort(Filters(got))
			sort.Sort(Filters(tt.want))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewTagsFilter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterVPCCIDRsBySubnets(t *testing.T) {
	tests := []struct {
		name        string
		vpcCIDRs    []string
		primaryCIDR string
		subnets     map[string]*ipamTypes.Subnet
		vpcID       string
		want        []string
	}{
		{
			name:        "empty subnets returns all CIDRs",
			vpcCIDRs:    []string{"10.0.0.0/16", "10.1.0.0/16"},
			primaryCIDR: "10.0.0.0/16",
			subnets:     ipamTypes.SubnetMap{},
			vpcID:       "vpc-1",
			want:        []string{"10.0.0.0/16", "10.1.0.0/16"},
		},
		{
			name:        "filters CIDRs to only those in available subnets",
			vpcCIDRs:    []string{"10.0.0.0/16", "10.1.0.0/16", "10.2.0.0/16"},
			primaryCIDR: "10.0.0.0/16",
			subnets: ipamTypes.SubnetMap{
				"subnet-1": {
					ID:                 "subnet-1",
					VirtualNetworkID:   "vpc-1",
					CIDR:               mustParseCIDR("10.0.0.0/24"),
					AvailabilityZone:   "us-east-1a",
					AvailableAddresses: 100,
				},
				"subnet-2": {
					ID:                 "subnet-2",
					VirtualNetworkID:   "vpc-1",
					CIDR:               mustParseCIDR("10.1.0.0/24"),
					AvailabilityZone:   "us-east-1b",
					AvailableAddresses: 200,
				},
			},
			vpcID: "vpc-1",
			want:  []string{"10.0.0.0/16", "10.1.0.0/16"},
		},
		{
			name:        "always includes primary CIDR even if not in subnets",
			vpcCIDRs:    []string{"10.0.0.0/16", "10.1.0.0/16"},
			primaryCIDR: "10.0.0.0/16",
			subnets: ipamTypes.SubnetMap{
				"subnet-1": {
					ID:                 "subnet-1",
					VirtualNetworkID:   "vpc-1",
					CIDR:               mustParseCIDR("10.1.0.0/24"),
					AvailabilityZone:   "us-east-1a",
					AvailableAddresses: 100,
				},
			},
			vpcID: "vpc-1",
			want:  []string{"10.0.0.0/16", "10.1.0.0/16"},
		},
		{
			name:        "filters out CIDRs from different VPC",
			vpcCIDRs:    []string{"10.0.0.0/16", "10.1.0.0/16"},
			primaryCIDR: "10.0.0.0/16",
			subnets: ipamTypes.SubnetMap{
				"subnet-1": {
					ID:                 "subnet-1",
					VirtualNetworkID:   "vpc-2",
					CIDR:               mustParseCIDR("10.1.0.0/24"),
					AvailabilityZone:   "us-east-1a",
					AvailableAddresses: 100,
				},
			},
			vpcID: "vpc-1",
			want:  []string{"10.0.0.0/16"},
		},
		{
			name:        "handles subnets without CIDR",
			vpcCIDRs:    []string{"10.0.0.0/16", "10.1.0.0/16"},
			primaryCIDR: "10.0.0.0/16",
			subnets: ipamTypes.SubnetMap{
				"subnet-1": {
					ID:                 "subnet-1",
					VirtualNetworkID:   "vpc-1",
					CIDR:               nil,
					AvailabilityZone:   "us-east-1a",
					AvailableAddresses: 100,
				},
			},
			vpcID: "vpc-1",
			want:  []string{"10.0.0.0/16"},
		},
		{
			name:        "returns only CIDRs present in subnets when primary is also in subnet",
			vpcCIDRs:    []string{"10.0.0.0/16", "10.1.0.0/16", "10.2.0.0/16"},
			primaryCIDR: "10.0.0.0/16",
			subnets: ipamTypes.SubnetMap{
				"subnet-1": {
					ID:                 "subnet-1",
					VirtualNetworkID:   "vpc-1",
					CIDR:               mustParseCIDR("10.0.0.0/24"),
					AvailabilityZone:   "us-east-1a",
					AvailableAddresses: 100,
				},
			},
			vpcID: "vpc-1",
			want:  []string{"10.0.0.0/16"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterVPCCIDRsBySubnets(tt.vpcCIDRs, tt.primaryCIDR, tt.subnets, tt.vpcID)

			// Sort for consistent comparison
			sort.Strings(got)
			sort.Strings(tt.want)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("filterVPCCIDRsBySubnets() = %v, want %v", got, tt.want)
			}
		})
	}
}

// mustParseCIDR is a helper function for tests
func mustParseCIDR(s string) *cidr.CIDR {
	c, err := cidr.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return c
}
