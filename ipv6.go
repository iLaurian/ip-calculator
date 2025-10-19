package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type IPv6Value struct {
	ip      net.IP
	netmask net.IPMask
}

func (v *IPv6Value) String() string {
	if v == nil || v.ip == nil {
		return ""
	}
	ones, _ := v.netmask.Size()
	return fmt.Sprintf("%s/%d", v.ip.String(), ones)
}

func (v *IPv6Value) Set(value string) error {
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid IPv6 address format. Must be in the form of 'address/mask'")
	}

	ip := net.ParseIP(parts[0])
	if ip == nil {
		return fmt.Errorf("invalid IPv6 address: %s", parts[0])
	}

	maskInt, err := strconv.Atoi(parts[1])
	if err != nil {
		panic(err)
	}

	mask := net.CIDRMask(maskInt, 128)
	if mask == nil {
		return fmt.Errorf("invalid mask: %s", parts[1])
	}

	v.ip = ip
	v.netmask = mask
	return nil
}

func (v *IPv6Value) GetNetworkAddress() net.IP {
	if v.ip == nil || len(v.ip) != net.IPv6len ||
		v.netmask == nil || len(v.netmask) != net.IPv6len {
		return nil // Invalid IPv6 address or subnet mask
	}

	network := make(net.IP, net.IPv6len)
	for i := 0; i < net.IPv6len; i++ {
		network[i] = v.ip[i] & v.netmask[i]
	}

	return network
}

func (v *IPv6Value) netmaskAsString() string {
	netmask := v.netmask.String()
	if len(netmask) != 32 {
		return ""
	}

	ipv6Blocks := make([]string, 8)
	for i := 0; i < 8; i++ {
		startIdx := i * 4
		endIdx := startIdx + 4
		ipv6Blocks[i] = netmask[startIdx:endIdx]
	}

	return strings.Join(ipv6Blocks, ":")
}

func DecompressIPv6(compressedAddress string) string {
	ip := net.ParseIP(compressedAddress)
	if ip == nil || ip.To16() == nil || ip.To4() != nil {
		return ""
	}

	segments := strings.Split(compressedAddress, ":")
	expandedSegments := make([]string, 0, 8)
	doubleColonIdx := -1

	for i, seg := range segments {
		if seg == "" {
			if doubleColonIdx != -1 {
				return ""
			}
			doubleColonIdx = i
		}
	}

	for i, seg := range segments {
		if i == doubleColonIdx {
			for j := 0; j < 8-len(segments)+1; j++ {
				expandedSegments = append(expandedSegments, "0000")
			}
		} else {
			expandedSegments = append(expandedSegments, ExpandIPv6Segment(seg))
		}
	}

	return strings.Join(expandedSegments, ":")
}

func ExpandIPv6Segment(segment string) string {
	expanded := segment
	if len(segment) < 4 {
		expanded = fmt.Sprintf("%s%s", strings.Repeat("0", 4-len(segment)), segment)
	}
	return expanded
}

func IPv6IPRange(networkAddress net.IP, netmask net.IPMask) (net.IP, net.IP) {
	if networkAddress == nil || netmask == nil || len(networkAddress) != len(netmask) {
		return nil, nil
	}

	networkSize := len(networkAddress)
	startIP := make(net.IP, networkSize)
	endIP := make(net.IP, networkSize)

	for i := 0; i < networkSize; i++ {
		startIP[i] = networkAddress[i] & netmask[i]
		endIP[i] = networkAddress[i] | ^netmask[i]
	}

	return startIP, endIP
}
