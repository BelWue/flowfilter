package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/bwNetFlow/flowfilter/parser"
	"github.com/bwNetFlow/flowfilter/visitors"
	"github.com/bwNetFlow/kafkaconnector"
	flow "github.com/bwNetFlow/protobuf/go"

	"github.com/dustin/go-humanize"
)

func main() {
	// parse our arg
	expr, err := parser.Parse(strings.Join(os.Args[1:], " "))
	if err != nil {
		fmt.Println(err)
		return
	}
	filter := &visitors.Filter{}

	server := os.Getenv("KAFKA_SERVER")
	topic := os.Getenv("KAFKA_TOPIC")
	group := os.Getenv("KAFKA_CONSUMER_GROUP")

	// connect to the Kafka cluster
	var kafkaConn = kafka.Connector{}
	err = kafkaConn.SetAuthFromEnv()

	if err != nil || server == "" || topic == "" || group == "" {
		fmt.Println("Set at least KAFKA_SERVER, KAFKA_SASL_USER and KAFKA_SASL_PASS, KAFKA_TOPIC and KAFKA_CONSUMER_GROUP please.")
		os.Exit(1)
	}

	err = kafkaConn.StartConsumer(server, []string{topic}, group, -1)

	// trap SIGINT to trigger a shutdown.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)

	// receive flows in a loop
	for {
		select {
		case flowmsg := <-kafkaConn.ConsumerChannel():
			if res, err := filter.CheckFlow(expr, flowmsg); res {
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				fmt.Println(format_flow(flowmsg))
			}
		case <-signals:
			return
		}
	}
}

func format_flow(flowmsg *flow.FlowMessage) string {
	timestamp := time.Unix(int64(flowmsg.TimeFlowEnd), 0).Format("15:04:05")
	src := net.IP(flowmsg.SrcAddr)
	dst := net.IP(flowmsg.DstAddr)
	router := net.IP(flowmsg.SamplerAddress)
	protomap := map[uint32]string{0: "HOPOPT", 1: "ICMP", 2: "IGMP",
		3: "GGP", 4: "IP-in-IP", 5: "ST", 6: "TCP", 7: "CBT", 8: "EGP",
		9: "IGP", 10: "BBN-RCC-MON", 11: "NVP-II", 12: "PUP",
		13: "ARGUS", 14: "EMCON", 15: "XNET", 16: "CHAOS", 17: "UDP",
		18: "MUX", 19: "DCN-MEAS", 20: "HMP", 21: "PRM", 22: "XNS-IDP",
		23: "TRUNK-1", 24: "TRUNK-2", 25: "LEAF-1", 26: "LEAF-2",
		27: "RDP", 28: "IRTP", 29: "ISO-TP4", 30: "NETBLT",
		31: "MFE-NSP", 32: "MERIT-INP", 33: "DCCP", 34: "3PC",
		35: "IDPR", 36: "XTP", 37: "DDP", 38: "IDPR-CMTP", 39: "TP++",
		40: "IL", 41: "IPv6", 42: "SDRP", 43: "IPv6-Route",
		44: "IPv6-Frag", 45: "IDRP", 46: "RSVP", 47: "GRE", 48: "DSR",
		49: "BNA", 50: "ESP", 51: "AH", 52: "I-NLSP", 53: "SwIPe",
		54: "NARP", 55: "MOBILE", 56: "TLSP", 57: "SKIP",
		58: "IPv6-ICMP", 59: "IPv6-NoNxt", 60: "IPv6-Opts",
		61: "Any host internal protocol", 62: "CFTP",
		63: "Any local network", 64: "SAT-EXPAK", 65: "KRYPTOLAN",
		66: "RVD", 67: "IPPC", 68: "Any distributed file system",
		69: "SAT-MON", 70: "VISA", 71: "IPCU", 72: "CPNX", 73: "CPHB",
		74: "WSN", 75: "PVP", 76: "BR-SAT-MON", 77: "SUN-ND",
		78: "WB-MON", 79: "WB-EXPAK", 80: "ISO-IP", 81: "VMTP",
		82: "SECURE-VMTP", 83: "VINES", 84: "TTP", 85: "NSFNET-IGP",
		86: "DGP", 87: "TCF", 88: "EIGRP", 89: "OSPF",
		90: "Sprite-RPC", 91: "LARP", 92: "MTP", 93: "AX.25", 94: "OS",
		95: "MICP", 96: "SCC-SP", 97: "ETHERIP", 98: "ENCAP",
		99: "Any private encryption scheme", 100: "GMTP", 101: "IFMP",
		102: "PNNI", 103: "PIM", 104: "ARIS", 105: "SCPS", 106: "QNX",
		107: "A/N", 108: "IPComp", 109: "SNP", 110: "Compaq-Peer",
		111: "IPX-in-IP", 112: "VRRP", 113: "PGM",
		114: "Any 0-hop protocol", 115: "L2TP", 116: "DDX",
		117: "IATP", 118: "STP", 119: "SRP", 120: "UTI", 121: "SMP",
		122: "SM", 123: "PTP", 124: "IS-IS over IPv4", 125: "FIRE",
		126: "CRTP", 127: "CRUDP", 128: "SSCOPMCE", 129: "IPLT",
		130: "SPS", 131: "PIPE", 132: "SCTP", 133: "FC",
		134: "RSVP-E2E-IGNORE", 135: "Mobility Header", 136: "UDPLite",
		137: "MPLS-in-IP", 138: "manet", 139: "HIP", 140: "Shim6",
		141: "WESP", 142: "ROHC", 143: "Ethernet",
	}
	proto := protomap[flowmsg.Proto]
	if proto == "" {
		proto = fmt.Sprintf("UNKOWN (%d)", flowmsg.Proto)
	}
	duration := flowmsg.TimeFlowEnd - flowmsg.TimeFlowStart
	if duration == 0 {
		duration += 1
	}
	return fmt.Sprintf("%s: %s:%d -> %s:%d [%s -> %s, @%s], %s, %ds, %s, %s",
		timestamp, src, flowmsg.SrcPort, dst, flowmsg.DstPort,
		flowmsg.SrcIfDesc, flowmsg.DstIfDesc, router, proto,
		duration, humanize.SI(float64(flowmsg.Bytes*8/duration),
			"bps"), humanize.SI(float64(flowmsg.Packets/duration), "pps"))
}
