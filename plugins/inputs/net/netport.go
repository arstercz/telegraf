package net

import (
	"fmt"
	"syscall"
	"strconv"

	"github.com/shirou/gopsutil/net"
	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/inputs"
	"github.com/influxdata/telegraf/plugins/inputs/system"
)

type NetPorts struct {
	ps system.PS
	Ports []uint32 `toml:"ports"`
}

func (ns *NetPorts) Description() string {
	return "Read TCP port metrics such as established, time wait and sockets counts."
}

var portSampleConfig = `
  ## gather the port connection status if you set ports parameter
  # ports = [22, 30022]
`

func (ns *NetPorts) SampleConfig() string {
	return portSampleConfig
}

func (ns *NetPorts) Gather(acc telegraf.Accumulator) error {
	netconns, err := ns.ps.NetConnections()
	if err != nil {
		return fmt.Errorf("error getting net connections info: %s", err)
	}

	// port gather
	acc.AddError(ns.gatherPorts(ns.Ports, netconns, acc))
	return nil
}


func (ns *NetPorts) gatherPorts(ports []uint32, netconns []net.ConnectionStat, acc telegraf.Accumulator) error {
	portsRes := map[uint32]map[string]int{}
	for _, port := range ports {
		portsRes[port] = map[string]int{
			"UDP":0,
		}

	}

	// TODO: add family to tags or else
	for _, netcon := range netconns {
		portC, ok := portsRes[netcon.Laddr.Port]
		if !ok {
			continue
		}

		if netcon.Type == syscall.SOCK_DGRAM {
			portC["UDP"]++
			continue // UDP has no status
		}
		c, ok := portC[netcon.Status]
		if !ok {
			portC[netcon.Status] = 0
		}
		portC[netcon.Status] = c + 1

	}
	for port, counts := range portsRes {
		tags := map[string]string{"port": strconv.Itoa(int(port))}
		fields := map[string]interface{}{
			"tcp_established": counts["ESTABLISHED"],
			"tcp_syn_sent":    counts["SYN_SENT"],
			"tcp_syn_recv":    counts["SYN_RECV"],
			"tcp_fin_wait1":   counts["FIN_WAIT1"],
			"tcp_fin_wait2":   counts["FIN_WAIT2"],
			"tcp_time_wait":   counts["TIME_WAIT"],
			"tcp_close":       counts["CLOSE"],
			"tcp_close_wait":  counts["CLOSE_WAIT"],
			"tcp_last_ack":    counts["LAST_ACK"],
			"tcp_listen":      counts["LISTEN"],
			"tcp_closing":     counts["CLOSING"],
			"tcp_none":        counts["NONE"],
			"udp_socket":      counts["UDP"],
		}
		acc.AddFields("netport", fields, tags)
	}
	return nil
}
func init() {
	inputs.Add("netport", func() telegraf.Input {
		return &NetPorts{ps: system.NewSystemPS()}
	})
}
