package main

import (
	"flag"
	ida "ida/raptorq"
	"io/ioutil"
	"log"
	"net"
)

func InitNode(confignbr string, configallpeer string) *ida.Node {
	config1 := NewConfig()
	config1.ReadConfigFile(confignbr)
	selfPeer, peerList, _ := config1.GetPeerInfo()
	config2 := NewConfig()
	config2.ReadConfigFile(configallpeer)
	_, _, allPeers := config2.GetPeerInfo()
	Cache := make(map[ida.HashKey]*ida.RaptorQImpl)
	SenderCache := make(map[ida.HashKey]bool)
	PeerDecodedCounter := make(map[ida.HashKey]int)
	node := ida.Node{SelfPeer: selfPeer, PeerList: peerList, AllPeers: allPeers, Cache: Cache, PeerDecodedCounter: PeerDecodedCounter, SenderCache: SenderCache}
	return &node
}

func main() {
	graphConfigFile := flag.String("graph_config", "graph_config.txt", "file containing network structure")
	generateConfigFiles := flag.Bool("gen_config", false, "whether to generate config files from graph_config file")
	broadCast := flag.Bool("broadcast", false, "whether to broadcast a message")
	msgFile := flag.String("msg_file", "test.txt", "message file to broadcast")
	configFile := flag.String("nbr_config", "configs/config_0.txt", "config file contains neighbor peers")
	allPeerFile := flag.String("all_config", "configs/config_allpeers.txt", "config file contains all peer nodes info")
	flag.Parse()

	if *generateConfigFiles {
		GenerateConfigFromGraph(*graphConfigFile)
		return
	}

	node := InitNode(*configFile, *allPeerFile)
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
		ctx, cancel, hashkey := node.BroadCast(filecontent, pc)
		if ctx != nil {
			node.StopBroadCast(ctx, cancel, hashkey)
		}
	} else {
		node.ListeningOnBroadCast(pc)
	}
}
