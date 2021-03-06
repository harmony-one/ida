package main

import (
	"flag"
	ida "github.com/harmony-one/ida/raptorq"
	uni "github.com/harmony-one/ida/unicast"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"strconv"
	"time"
)

func InitNode(confignbr string, configallpeer string, t0 float64, t1 float64, t2 float64, base float64, hop int) *ida.Node {
	rand.Seed(time.Now().UTC().UnixNano())
	config1 := NewConfig()
	config1.ReadConfigFile(confignbr)
	selfPeer, peerList, _ := config1.GetPeerInfo()
	config2 := NewConfig()
	config2.ReadConfigFile(configallpeer)
	_, _, allPeers := config2.GetPeerInfo()
	Cache := make(map[ida.HashKey]*ida.RaptorQImpl)
	SenderCache := make(map[ida.HashKey]bool)
	PeerDecodedCounter := make(map[ida.HashKey]map[int]int)
	node := ida.Node{SelfPeer: selfPeer, PeerList: peerList, AllPeers: allPeers, Cache: Cache, PeerDecodedCounter: PeerDecodedCounter, SenderCache: SenderCache, T0: t0, T1: t1, Base: base, T2: t2, Hop: hop}
	return &node
}

func InitUniCastNode(confignbr string, configallpeer string) *uni.Node {
	config1 := NewConfig()
	config1.ReadConfigFile(confignbr)
	selfPeer, peerList, _ := config1.GetPeerInfo()
	config2 := NewConfig()
	config2.ReadConfigFile(configallpeer)
	_, _, allPeers := config2.GetPeerInfo()
	node := uni.Node{SelfPeer: selfPeer, PeerList: peerList, AllPeers: allPeers}
	return &node
}

func main() {
	graphConfigFile := flag.String("graph_config", "graph_config.txt", "file containing network structure")
	generateConfigFiles := flag.Bool("gen_config", false, "whether to generate config files from graph_config file")
	broadCast := flag.Bool("broadcast", false, "whether to broadcast a message")
	msgFile := flag.String("msg_file", "test.txt", "message file to broadcast")
	configFile := flag.String("nbr_config", "configs/config_0.txt", "config file contains neighbor peers")
	allPeerFile := flag.String("all_config", "configs/config_allpeers.txt", "config file contains all peer nodes info")
	mode := flag.String("mode", "ida", "choose benchmark testing mode, [ida|unicast|p2p]")
	t0 := flag.String("t0", "7", "initial delay time for symbol broadcasting")
	t1 := flag.String("t1", "70", "uppper bound delay time for symbol broadcasting")
	t2 := flag.String("t2", "7", "delay time for symbol relay")
	hop := flag.String("hop", "1", "number of hops")
	base := flag.String("base", "1.5", "base of exponential increase of symbol broadcasting delay")
	flag.Parse()

	if *generateConfigFiles {
		GenerateConfigFromGraph(*graphConfigFile)
		return
	}

	switch *mode {
	case "ida":
		var ta, tb, tc, b float64
		var h int
		var err error
		if ta, err = strconv.ParseFloat(*t0, 64); err != nil {
			log.Printf("unable to parse t0 %v with error %v", t0, err)
			return
		}
		if tb, err = strconv.ParseFloat(*t1, 64); err != nil {
			log.Printf("unable to parse t1 %v with error %v", t1, err)
			return
		}
		if tc, err = strconv.ParseFloat(*t2, 64); err != nil {
			log.Printf("unable to parse t2 %v with error %v", t2, err)
			return
		}
		if b, err = strconv.ParseFloat(*base, 64); err != nil {
			log.Printf("unable to parse base %v with error %v", base, err)
			return
		}
		if h, err = strconv.Atoi(*hop); err != nil {
			log.Printf("unable to parse hop %v with error %v", hop, err)
			return
		}
		node := InitNode(*configFile, *allPeerFile, ta, tb, tc, b, h)
		uaddr := net.JoinHostPort("", node.SelfPeer.UDPPort)
		pc, err := net.ListenPacket("udp", uaddr)
		if err != nil {
			log.Printf("cannot connect to udp port")
			return
		}
		log.Printf("server start listening on udp port %s", node.SelfPeer.UDPPort)

		if *broadCast {
			go node.ListeningOnBroadCast(pc)
			filecontent, err := ioutil.ReadFile(*msgFile)
			log.Printf("file size is %v", len(filecontent))
			if err != nil {
				log.Printf("cannot open file %s", *msgFile)
				return
			}
			cancels, raptorq := node.BroadCast(filecontent, pc)
			node.StopBroadCast(cancels, raptorq)
		} else {
			node.ListeningOnBroadCast(pc)
		}
	case "unicast":
		node := InitUniCastNode(*configFile, *allPeerFile)
		if *broadCast {
			filecontent, err := ioutil.ReadFile(*msgFile)
			log.Printf("file size is %v", len(filecontent))
			if err != nil {
				log.Printf("cannot open file %s", *msgFile)
				return
			}
			node.BroadCast(filecontent)
		} else {
			node.ListeningOnUniCast()
		}

	default:
		log.Printf("mode %v not supported", *mode)
	}
}
