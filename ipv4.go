package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
)

type IPv4Value struct {
	ip      net.IP
	netmask net.IPMask
}

func (v *IPv4Value) String() string {
	if v == nil || v.ip == nil {
		return ""
	}
	ones, _ := v.netmask.Size()
	return fmt.Sprintf("%s/%d", v.ip.String(), ones)
}

func (v *IPv4Value) Set(value string) error {
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return fmt.Errorf("%s is not in the format 'address/netmask'", value)
	}

	ip := net.ParseIP(parts[0])
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("%s is not a valid IPv4 address", parts[0])
	}

	maskSize, err := strconv.Atoi(parts[1])
	if err != nil || maskSize < 0 || maskSize > 32 {
		return fmt.Errorf("%s is not a valid netmask size", parts[1])
	}

	mask := net.CIDRMask(maskSize, 32)

	v.ip = ip
	v.netmask = mask

	return nil
}

func (v *IPv4Value) GetNetworkAddress() net.IP {
	if v.ip == nil || v.netmask == nil {
		return nil
	}
	return v.ip.Mask(v.netmask)
}

func (v *IPv4Value) GetBroadcastAddress() (net.IP, error) {
	if v.ip.To4() == nil || v.netmask == nil {
		return nil, errors.New("invalid ip address")
	}
	ip := make(net.IP, len(v.ip.To4()))
	binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(v.ip.To4())|^binary.BigEndian.Uint32(net.IP(v.netmask).To4()))
	return ip, nil
}

func (v *IPv4Value) netmaskAsString() string {
	if len(v.netmask) != 4 {
		panic("ipv4Mask: len must be 4 bytes")
	}

	return fmt.Sprintf("%d.%d.%d.%d", v.netmask[0], v.netmask[1], v.netmask[2], v.netmask[3])
}

func (v *IPv4Value) GetWildCardMask() string {
	return fmt.Sprintf("%d.%d.%d.%d", 255-v.netmask[0], 255-v.netmask[1], 255-v.netmask[2], 255-v.netmask[3])
}

func (v *IPv4Value) GetUsableHostRange() (net.IP, net.IP) {

	networkAddress := v.GetNetworkAddress()
	broadcastAddress, _ := v.GetBroadcastAddress()

	hostMin := make(net.IP, net.IPv4len)
	copy(hostMin, networkAddress.To4())

	for i := len(networkAddress) - 1; i >= 0; i-- {
		hostMin[i]++
		if hostMin[i] > 0 {
			break
		}
	}

	hostMax := make(net.IP, net.IPv4len)
	copy(hostMax, broadcastAddress.To4())

	for i := net.IPv4len - 1; i >= 0; i-- {
		hostMax[i]--
		if hostMax[i] < 255 {
			break
		}
	}

	return hostMin, hostMax
}

func IP4toInt(IPv4Address net.IP) int64 {
	IPv4Int := big.NewInt(0)
	IPv4Int.SetBytes(IPv4Address.To4())
	return IPv4Int.Int64()
}

func IP4CidrToBinary(IPv4Address string) string {
	binaryAddress := strconv.FormatInt(IP4toInt(net.ParseIP(IPv4Address)), 2)
	if len(binaryAddress) < 32 {
		var padding string
		for j := 0; j < 32-len(binaryAddress); j++ {
			padding = padding + "0"
		}
		binaryAddress = padding + binaryAddress
	}
	return binaryAddress
}

func calculateNextIP(ip net.IP, newMaskSize int) net.IP {
	ip = ip.To4()
	shift := 32 - newMaskSize
	ipInt := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	nextIPInt := ipInt + (1 << shift)

	nextIP := make(net.IP, 4)
	nextIP[0] = byte(nextIPInt >> 24)
	nextIP[1] = byte(nextIPInt >> 16)
	nextIP[2] = byte(nextIPInt >> 8)
	nextIP[3] = byte(nextIPInt)

	return nextIP
}
