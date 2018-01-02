package main

import (
	"curses"
	"fmt"
	"panels"
	"sort"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var M = NewMonitor()

func NewMonitor() *Monitor {
	return &Monitor{
		showLayers: []gopacket.LayerType{
			layers.LayerTypeEthernet,
			layers.LayerTypeIPv4,
			layers.LayerTypeIPv6,
			layers.LayerTypeUDP,
			layers.LayerTypeTCP,
		},
	}
}

type Iface struct {
	Name           string
	Lock           sync.RWMutex
	LayersContents map[gopacket.LayerType]int
	LayersPayload  map[gopacket.LayerType]int
	IPV4PTPFlows   []*PointToPointFlow
	IPV6PTPFlows   []*PointToPointFlow
	AllLen         int
}

func (this *Iface) GetPTP(ip, net, src, dst string) *PointToPointFlow {
	flows := this.IPV4PTPFlows
	if ip == "v6" {
		flows = this.IPV6PTPFlows
	}
	for _, v := range flows {
		if v.Net == net && (src == v.Addr[0] || src == v.Addr[1]) {
			return v
		}
	}
	inst := &PointToPointFlow{IP: ip, Net: net, Addr: [2]string{src, dst}}
	if ip == "v6" {
		this.IPV6PTPFlows = append(this.IPV6PTPFlows, inst)
	} else {
		this.IPV4PTPFlows = append(this.IPV4PTPFlows, inst)
	}
	return inst
}

type PointToPointFlow struct {
	IP          string
	Net         string
	Addr        [2]string
	Flow        [2]int
	LastFlow    [2]int
	LastAllFlow int
	AllFlow     int
}

func (this *PointToPointFlow) LastReset() {
	this.LastFlow[0] = 0
	this.LastFlow[1] = 0
	this.LastAllFlow = 0
}

func (this *PointToPointFlow) Add(src, dst string, n int) {
	for i := range this.Addr {
		if this.Addr[i] == src {
			this.Flow[i] += n
			this.LastFlow[i] += n
			this.LastAllFlow += n
			this.AllFlow += n
		}
	}
}

type Monitor struct {
	showLayers []gopacket.LayerType
	ifaces     []*Iface
	title      *panels.Panel
	cntHead    *panels.Panel
	cntPanel   *panels.Panel
}

func (this *Monitor) GetIface(iface string) *Iface {
	for i := range this.ifaces {
		if this.ifaces[i].Name == iface {
			return this.ifaces[i]
		}
	}
	inst := &Iface{Name: iface, LayersContents: make(map[gopacket.LayerType]int),
		LayersPayload: make(map[gopacket.LayerType]int)}
	this.ifaces = append(this.ifaces, inst)
	return inst
}

var noCntHeight = 3
var curIface = 0
var curIfacePrintStart = 0

func (this *Monitor) Dump() {
	if this.title == nil {
		win, _ := curses.Newwin(2, 0, 0, 0)
		this.title = panels.NewPanel(win)
		win.Scroll()
	}
	start := 0
	win := this.title.Window()
	win.Clear()
	for k, v := range this.ifaces {
		color := curses.Color_pair(blk_white)
		if curIface == k {
			color = curses.Color_pair(white_blue)
			v.Lock.RLock()
			start2 := 0
			for _, v1 := range this.showLayers {
				win.Addstr(start2, 1, v1.String(), color)
				start2 += len(v1.String())
				show := BitShow(v.LayersPayload[v1])
				win.Addstr(start2, 1, ":%v ", color, show)
				start2 += len(show) + 2
			}
			v.Lock.RUnlock()
		}
		win.Addstr(start, 0, "%v ", color, v.Name)
		start += len(v.Name) + 1
	}
	win.Refresh()

	if this.cntHead == nil {
		win, _ := curses.Newwin(1, 0, 2, 0)
		this.cntHead = panels.NewPanel(win)
		win.Addstr(0, 0, "%-3v %-10v %-2v %-7v %-8v %-8v   %-8v %-8v   %-25v %-v",
			curses.Color_pair(white_blue), "NUM", "IFACE", "IP", "NET", "UP", "", "DOWN", "", "SRC ADDR", "DST ADDR")
		win.Refresh()
	}
	if this.cntPanel == nil {
		win, _ := curses.Newwin(0, 0, 3, 0)
		win.Refresh()
		this.cntPanel = panels.NewPanel(win)
	}
	var lastLine int = 0
	win = this.cntPanel.Window()
	win.Clear()
	flowPrint := func(iface string, ptpf []*PointToPointFlow) {
		curIfacePrintEnd := len(ptpf)
		if curIfacePrintEnd == 0 {
			return
		}
		if h := (*curses.Rows) - noCntHeight; h > 0 && h+curIfacePrintStart < curIfacePrintEnd {
			curIfacePrintEnd = h + curIfacePrintStart
		}
		for k1, v1 := range ptpf[curIfacePrintStart:curIfacePrintEnd] {
			color := curses.Color_pair(green_blk)
			if (k1+1)%2 == 0 {
				color = curses.Color_pair(red_blk)
			}
			win.Addstr(0, k1+lastLine, "%-3v %-10v %-2v %-7v %-8v %8v   %-8v %-8v   %-25v %-25v", color,
				curIfacePrintStart+k1, iface, v1.IP, v1.Net, BitShow(v1.Flow[0]), BitShow(v1.LastFlow[0])+"/s", BitShow(v1.Flow[1]), BitShow(v1.LastFlow[1])+"/s", v1.Addr[0], v1.Addr[1])
			v1.LastReset()
		}
		lastLine += len(ptpf) + 1
	}
	if curIface < len(this.ifaces) {
		v := this.ifaces[curIface]
		sort.Slice(v.IPV4PTPFlows, func(i, j int) bool {
			if v.IPV4PTPFlows[i].LastAllFlow > 0 || v.IPV4PTPFlows[j].LastAllFlow > 0 {
				return v.IPV4PTPFlows[i].LastAllFlow > v.IPV4PTPFlows[j].LastAllFlow
			}
			return v.IPV4PTPFlows[i].AllFlow > v.IPV4PTPFlows[j].AllFlow
		})
		//if len(v.IPV4PTPFlows) > 100 {
		//	v.IPV4PTPFlows = v.IPV4PTPFlows[:100]
		//}
		v.Lock.RLock()
		flowPrint(v.Name, v.IPV4PTPFlows)
		v.Lock.RUnlock()
	}
	this.cntPanel.Window().Refresh()
}

func (this *Monitor) AddPacket(iface string, pkg gopacket.Packet) {
	inst := this.GetIface(iface)
	var ipTp, netTp string
	var srcAddr, dstAddr string
	var netLen int

	inst.AllLen += pkg.Metadata().CaptureInfo.Length
	for _, ly := range pkg.Layers() {
		inst.AllLen += pkg.Metadata().CaptureInfo.Length
		inst.Lock.Lock()
		inst.LayersContents[ly.LayerType()] += len(ly.LayerContents())
		inst.LayersPayload[ly.LayerType()] += len(ly.LayerPayload())
		inst.Lock.Unlock()
		switch ly.LayerType() {
		case layers.LayerTypeIPv4:
			//ipv4 := pkg.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			ipv4 := ly.(*layers.IPv4)
			srcAddr, dstAddr = ipv4.SrcIP.String(), ipv4.DstIP.String()
			ipTp = "v4"
		case layers.LayerTypeIPv6:
			//ipv6 := pkg.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			ipv6 := ly.(*layers.IPv6)
			srcAddr, dstAddr = ipv6.SrcIP.String(), ipv6.DstIP.String()
			ipTp = "v6"
		case layers.LayerTypeUDP:
			//udp := pkg.Layer(layers.LayerTypeUDP).(*layers.UDP)
			udp := ly.(*layers.UDP)
			srcAddr = fmt.Sprintf("%v:%d", srcAddr, udp.SrcPort)
			dstAddr = fmt.Sprintf("%v:%d", dstAddr, udp.DstPort)
			netLen = len(ly.LayerPayload())
			netTp = "udp"
		case layers.LayerTypeTCP:
			//tcp := pkg.Layer(layers.LayerTypeTCP).(*layers.TCP)
			tcp := ly.(*layers.TCP)
			srcAddr = fmt.Sprintf("%v:%d", srcAddr, tcp.SrcPort)
			dstAddr = fmt.Sprintf("%v:%d", dstAddr, tcp.DstPort)
			netTp = "tcp"
			netLen = len(ly.LayerPayload())
		}
	}
	if ipTp == "" || netTp == "" {
		return
	}
	inst.Lock.Lock()
	inst.GetPTP(ipTp, netTp, srcAddr, dstAddr).Add(srcAddr, dstAddr, netLen)
	inst.Lock.Unlock()
}
