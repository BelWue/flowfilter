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
	protomap := map[uint32]string{1: "ICMP", 6: "TCP", 17: "UDP"}
	proto := protomap[flowmsg.Proto]
	if proto == "" {
		proto = fmt.Sprintf("%d", flowmsg.Proto)
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
