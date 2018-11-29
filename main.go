package main

import (
	ida "ida/raptorq"
	"io/ioutil"
	"log"
	"net"
	"os"
)

func Client(filename string) {
	var conn net.Conn

	filecontent, err := ioutil.ReadFile(filename)
	log.Printf("file size is %v", len(filecontent))
	if err != nil {
		log.Printf("cannot open file %s", filename)
		return
	}
	addr := net.JoinHostPort("127.0.0.1", "9999")
	conn, err = net.Dial("tcp", addr)
	if err != nil {
		log.Printf("cannot connect to peer")
		return
	}
	log.Printf("connection established to server %s", addr)
	defer conn.Close()
	raptorq := ida.RaptorQImpl{}
	raptorq.HandleConnectionEncoder(conn, filecontent)

}

func Server() {

	port := "9999"
	buf := make([]byte, 2256)
	addr := net.JoinHostPort("127.0.0.1", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("cannot listening to the port %s", port)
		return
	}

	log.Printf("server start listening on port %s", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("cannot accept connection")
			return
		}
		clientinfo := conn.RemoteAddr().String()
		log.Printf("accept connection from %s", clientinfo)
		raptorq := ida.RaptorQImpl{}
		go raptorq.HandleConnectionDecoder(conn, buf)
	}

}

func main() {
	filename := "./test.txt"
	if os.Args[1] == "server" {
		Server()
	} else {
		Client(filename)
	}
}
