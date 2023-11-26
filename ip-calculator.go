package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"math"
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

func (v *IPv4Value) netmaskMaskString() string {
	if len(v.netmask) != 4 {
		panic("ipv4Mask: len must be 4 bytes")
	}

	return fmt.Sprintf("%d.%d.%d.%d", v.netmask[0], v.netmask[1], v.netmask[2], v.netmask[3])
}

func (v *IPv4Value) GetWildCardMask() string {
	return fmt.Sprintf("%d.%d.%d.%d", 255-v.netmask[0], 255-v.netmask[1], 255-v.netmask[2], 255-v.netmask[3])
}

func (v *IPv4Value) GetUsableHostRange() (net.IP, net.IP, error) {

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

	return hostMin, hostMax, nil
}

func main() {
	var ipv4 IPv4Value
	flag.Var(&ipv4, "ipv4", "IPv4 address with netmask (e.g., 192.168.1.1/24)")
	info := flag.Bool("info", false, "IP information")

	flag.Parse()

	if ipv4.ip != nil && ipv4.netmask != nil && *info {
		fmt.Printf("%-30s : %s\n", "IP Address", ipv4.ip)

		networkAddress := ipv4.GetNetworkAddress()
		fmt.Printf("%-30s : %s\n", "Network Address", networkAddress)

		broadcastAddress, err := ipv4.GetBroadcastAddress()
		if err != nil {
			panic(err)
		}
		fmt.Printf("%-30s : %s\n", "Broadcast Address", broadcastAddress)

		hostMin, hostMax, err := ipv4.GetUsableHostRange()
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		fmt.Printf("%-30s : %s%s%s\n", "Usable Host IP Range", hostMin, " - ", hostMax)

		ones, bits := ipv4.netmask.Size()
		fmt.Printf("%-30s : %d\n", "Total Number of Hosts", int(math.Pow(2, float64(bits-ones))))
		fmt.Printf("%-30s : %d\n", "Number of Usable Hosts", int(math.Pow(2, float64(bits-ones))-2))

		netmaskStr := ipv4.netmaskMaskString()
		fmt.Printf("%-30s : %s\n", "Subnet Mask", netmaskStr)

		wildCardMask := ipv4.GetWildCardMask()
		fmt.Printf("%-30s : %s\n", "Wildcard Mask", wildCardMask)

		return
	}
}
