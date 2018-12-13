package main

import (
	"flag"
	ida "github.com/harmony-one/ida/raptorq"
	uni "github.com/harmony-one/ida/unicast"
	"io/ioutil"
	"log"
	"net"
	"strconv"
)

func InitNode(confignbr string, configallpeer string, t0 float64, base float64) *ida.Node {
	config1 := NewConfig()
	config1.ReadConfigFile(confignbr)
	selfPeer, peerList, _ := config1.GetPeerInfo()
	config2 := NewConfig()
	config2.ReadConfigFile(configallpeer)
	_, _, allPeers := config2.GetPeerInfo()
	Cache := make(map[ida.HashKey]*ida.RaptorQImpl)
	SenderCache := make(map[ida.HashKey]bool)
	PeerDecodedCounter := make(map[ida.HashKey]map[int]int)
	node := ida.Node{SelfPeer: selfPeer, PeerList: peerList, AllPeers: allPeers, Cache: Cache, PeerDecodedCounter: PeerDecodedCounter, SenderCache: SenderCache, T0: t0, Base: base}
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
	base := flag.String("base", "1.8", "base of exponential increase of symbol broadcasting delay")
	flag.Parse()

	if *generateConfigFiles {
		GenerateConfigFromGraph(*graphConfigFile)
		return
	}

	switch *mode {
	case "ida":
		var t, b float64
		var err error
		if t, err = strconv.ParseFloat(*t0, 64); err != nil {
			log.Printf("unable to parse t0 %v with error %v", t0, err)
			return
		}
		if b, err = strconv.ParseFloat(*base, 64); err != nil {
			log.Printf("unable to parse base %v with error %v", base, err)
			return
		}
		node := InitNode(*configFile, *allPeerFile, t, b)
		uaddr := net.JoinHostPort(node.SelfPeer.Ip, node.SelfPeer.UDPPort)
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
