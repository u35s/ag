package main

import (
	"context"
	"curses"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	white_blk int = iota + 1
	yellow_blk
	red_blk
	green_blk
	white_blue
	blk_white
)

func winEnd() {
	curses.Endwin()
}
func winInit() {
	curses.Initscr()
	curses.Start_color()
	curses.Init_pair(white_blk, curses.COLOR_WHITE, curses.COLOR_BLACK)
	curses.Init_pair(yellow_blk, curses.COLOR_YELLOW, curses.COLOR_BLACK)
	curses.Init_pair(red_blk, curses.COLOR_RED, curses.COLOR_BLACK)
	curses.Init_pair(green_blk, curses.COLOR_GREEN, curses.COLOR_BLACK)
	curses.Init_pair(white_blue, curses.COLOR_WHITE, curses.COLOR_BLUE)
	curses.Init_pair(blk_white, curses.COLOR_BLACK, curses.COLOR_WHITE)

	go listenKeys()
}

var itfcs []net.Interface
var exit context.CancelFunc
var tabSwitch = make(chan int)

func main() {
	//f, _ := os.Create(fmt.Sprintf("profile_file_%v", time.Now().Unix()))
	//pprof.StartCPUProfile(f)     // 开始cpu profile，结果写到文件f中
	//defer pprof.StopCPUProfile() // 结束profile
	if os.Geteuid() != 0 {
		log.Fatal("ag must run as root.")
	}

	errFile, _ := os.OpenFile("stack", os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_SYNC, 0644)
	syscall.Dup2(int(errFile.Fd()), 2)

	winInit()
	itfcs, _ = net.Interfaces()
	for _, itfc := range itfcs {
		M.GetIface(itfc.Name)
		//ctx, cancel := context.WithCancel(context.Background())
		//go listenPacket(itfc.Name, ctx)
		//cancels = append(cancels, cancel)
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT)
	tick := time.Tick(time.Second * 1)

	if len(itfcs) > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		exit = cancel
		go listenPacket(itfcs[0].Name, ctx)
	} else {
		signalChan <- syscall.SIGINT
	}

	for {
		select {
		case <-tabSwitch:
			M.Dump()
		case <-tick:
			M.Dump()
		case <-signalChan:
			exit()
			goto END
		}
	}
END:
	winEnd()
}

func listenPacket(iface string, ctx context.Context) {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("pcap打开失败:", err)
	}
	handle.SetBPFFilter("udp || tcp")
	defer handle.Close()
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-ps.Packets():
			M.AddPacket(iface, p)
		}
	}
}

func listenKeys() {
	curses.Noecho()
	var ch int
	win := curses.Stdwin
	for {
		ch = win.Getch()
		switch ch {
		case 65: //up
			if curIfacePrintStart > 0 {
				curIfacePrintStart--
			}
		case 66: //down
			if curIface < len(M.ifaces) && len(M.ifaces[curIface].IPV4PTPFlows) > curIfacePrintStart {
				curIfacePrintStart++
			}
		case 67: //right
		case 68: //left
			curIfacePrintStart = 0
		case 9: //tab
			if curIface+1 >= len(M.ifaces) {
				curIface = 0
			} else {
				curIface++
			}
			exit()
			ctx, cancel := context.WithCancel(context.Background())
			exit = cancel
			go listenPacket(itfcs[curIface].Name, ctx)
			tabSwitch <- 1
		default:
			//log.Printf("keydown %v", ch)
			//log.Printf("cols:%d,rows:%d", *curses.Cols, *curses.Rows)
		}
	}
}
