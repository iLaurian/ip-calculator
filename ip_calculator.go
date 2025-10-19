package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
)

type IPAddressValue interface {
	String() string
	Set(string) error
	GetNetworkAddress() net.IP
	netmaskAsString() string
}

type Subnet struct {
	IP       net.IP
	MaskSize int
	Hosts    int
}

func isValidIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && strings.Count(ip, ".") == 3
}

func performVLSM(ip net.IP, mask net.IPMask, hosts []int) ([]Subnet, error) {
	var subnets []Subnet
	for _, requiredHosts := range hosts {
		requiredBits := int(math.Ceil(math.Log2(float64(requiredHosts + 2))))
		maskOnes, _ := mask.Size()

		availableBits := 32 - maskOnes
		if availableBits < requiredBits {
			return nil, fmt.Errorf("insufficient addresses for %d hosts", requiredHosts)
		}

		newMaskSize := 32 - requiredBits
		subnet := Subnet{
			IP:       ip,
			MaskSize: newMaskSize,
			Hosts:    requiredHosts,
		}
		subnets = append(subnets, subnet)

		ip = calculateNextIP(ip, newMaskSize)
		mask = net.CIDRMask(newMaskSize, 32)
	}

	return subnets, nil
}

func DisplayIPInfo(v IPAddressValue) {
	fmt.Printf("%-30s : %s\n", "IP Address (w/ mask)", v.String())
	fmt.Printf("%-30s : %s\n", "Network Address", v.GetNetworkAddress())
	fmt.Printf("%-30s : %s\n", "Subnet Mask", v.netmaskAsString())

	switch ipVal := v.(type) {
	case *IPv4Value:
		broadcastAddress, err := ipVal.GetBroadcastAddress()
		if err != nil {
			panic(err)
		}
		fmt.Printf("%-30s : %s\n", "Broadcast Address", broadcastAddress)

		hostMin, hostMax := ipVal.GetUsableHostRange()
		fmt.Printf("%-30s : %s%s%s\n", "Usable Host IP Range", hostMin, " - ", hostMax)

		ones, bits := ipVal.netmask.Size()
		fmt.Printf("%-30s : %d\n", "Total Number of Hosts", int(math.Pow(2, float64(bits-ones))))
		fmt.Printf("%-30s : %d\n", "Number of Usable Hosts", int(math.Pow(2, float64(bits-ones))-2))

		wildCardMask := ipVal.GetWildCardMask()
		fmt.Printf("%-30s : %s\n", "Wildcard Mask", wildCardMask)

	case *IPv6Value:
		fullAddress := DecompressIPv6(ipVal.ip.String())
		fmt.Printf("%-30s : %s\n", "Full IP Address", fullAddress)

		ipRangeStart, ipRangeEnd := IPv6IPRange(ipVal.ip, ipVal.netmask)
		fmt.Printf("%-30s : %s%s%s\n", "IP Range", ipRangeStart, " - ", ipRangeEnd)

	default:
		fmt.Println("Error: Unknown IP type for info display.")
	}
}

func showUsage() {
	fmt.Println("Usage: ip-calculator [options]")
	fmt.Println("Options:")
	flag.PrintDefaults()
	fmt.Println("\nUsage:")
	fmt.Println("Get help: \n\t./ip-calculator -h\n\t./ip-calculator --help")
	fmt.Println("Get IPv4 Information: \n\t./ip-calculator -ipv4 192.168.0.0/24 --info")
	fmt.Println("IPv4 Route Summarization: \n\t./ip-calculator --summary-route 10.0.0.0,10.0.0.1,10.0.0.2,10.0.0.3")
	fmt.Println("IPv4 VLSM Subnetting: \n\t./ip-calculator --ipv4=10.10.0.0/16 --vlsm 10,20,30,40")
	fmt.Println("IPv6 Information: \n\t./ip-calculator -ipv6=2001:0db8::1/64 --info")
	fmt.Println("IPv6 Shortening: \n\t./ip-calculator -ipv6 2001:0db8:0000:0000:0000:0000:0000:0001/64 --compress")
}

func main() {
	var ipv4 IPv4Value
	var routesToSum string
	var vlsm string
	var showHelp bool
	var ipv6 IPv6Value

	flag.Var(&ipv4, "ipv4", "IPv4 address with netmask (e.g., 192.168.1.1/24)")
	info := flag.Bool("info", false, "IP address information")
	flag.StringVar(&routesToSum, "summary-route", "", "Networks / IP addresses to be summarized in a single route separated by commas")
	flag.StringVar(&vlsm, "vlsm", "", "Number of hosts to subnet using Variable Length Subnet Mask (VLSM)")
	flag.Var(&ipv6, "ipv6", "IPv6 address with mask (e.g., '2001:0db8:85a3:0000:0000:8a2e:0370:7334/64')")
	compress := flag.Bool("compress", false, "Compress IPv6 Address")
	flag.BoolVar(&showHelp, "h", false, "")
	flag.BoolVar(&showHelp, "help", false, "Show info and documentation.")

	flag.Parse()

	if showHelp {
		showUsage()
		return
	}

	var ipVal IPAddressValue
	if ipv4.ip != nil {
		ipVal = &ipv4
	} else if ipv6.ip != nil {
		ipVal = &ipv6
	}

	if *info {
		if ipVal != nil {
			DisplayIPInfo(ipVal)
		}
		return
	}

	if routesToSum != "" {
		routes := strings.Split(routesToSum, ",")

		for _, route := range routes {
			if !isValidIP(route) {
				log.Fatal("Invalid network to summarize!")
			}
		}

		if len(routes) == 1 {
			fmt.Println("Please enter more than one route to summarize!")
			return
		}

		var binaryRoutes []string
		for _, route := range routes {
			binaryRoutes = append(binaryRoutes, IP4CidrToBinary(route))
		}

		var summaryNetmask int
		for i := 0; i < 32; i++ {
			bitsSum := 0
			for _, binaryRoute := range binaryRoutes {
				if binaryRoute[i] != 48 {
					bitsSum++
				}
			}
			if bitsSum != 0 && bitsSum != len(binaryRoutes) {
				summaryNetmask = i
				break
			}
		}

		var summaryRoute IPv4Value
		err := summaryRoute.Set(routes[0] + "/" + strconv.Itoa(summaryNetmask))
		if err != nil {
			return
		}
		summaryRoute.ip = summaryRoute.GetNetworkAddress()
		fmt.Println("Summarized Network Address:", fmt.Sprintf("%s/%d", summaryRoute.ip, summaryNetmask))

		return
	}

	if _, ok := ipVal.(*IPv4Value); ok && vlsm != "" {
		var hosts []int

		for _, part := range strings.Split(vlsm, ",") {
			host, err := strconv.Atoi(part)
			if err != nil {
				fmt.Println("Error converting to integer:", err)
				return
			}
			hosts = append(hosts, host)
		}

		sort.Slice(hosts, func(i, j int) bool {
			return hosts[i] > hosts[j]
		})

		subnets, err := performVLSM(ipv4.GetNetworkAddress(), ipv4.netmask, hosts)
		if err != nil {
			fmt.Println("Error performing VLSM:", err)
			return
		}

		fmt.Println("Subnets with VLSM:")
		for _, subnet := range subnets {
			fmt.Printf("Subnet: %s/%-5d \tHosts: %d\n", subnet.IP, subnet.MaskSize, subnet.Hosts)
		}

		return
	}

	if _, ok := ipVal.(*IPv6Value); ok && *compress {
		fmt.Println("Compressed IPv6 Address: ", ipv6.ip)

		return
	}

	defer fmt.Println("Error: Insufficient Parameters. See 'ip-calculator --help'")
}
