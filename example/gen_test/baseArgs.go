package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"reflect"
	"strconv"
	"time"

	"github.com/k4ra5u/quic-go"
)

type Flags struct {
	targetLen    int
	targetHost   []string
	targetAddr   []string
	targetSN     []string
	targetAlpn   []string
	targetPort   []string
	targetFile   string
	startPos     int
	endPos       int
	repeatTimes  uint64
	targetMethod string
	multiThread  int
	quiet        bool
}

type BaseArgs struct {
	targetHost  string
	targetPort  string
	targetAddr  string
	targetSN    string
	targetAlpn  string
	repeatTimes uint64
	quiet       bool
}

func (b *BaseArgs) GetStringArgs(targetName string) string {
	v := reflect.ValueOf(b)
	name := v.FieldByName(targetName)
	if name.IsValid() && name.Kind() == reflect.String {
		return name.String()
	} else {
		return ""
	}

}

func (b *BaseArgs) GetUInt64Args(targetName string) uint64 {
	v := reflect.ValueOf(b)
	name := v.FieldByName(targetName)
	if name.IsValid() && name.Kind() == reflect.Uint64 {
		return name.Uint()
	} else {
		return 0
	}
}

func (b *BaseArgs) GetIntArgs(targetName string) int {
	v := reflect.ValueOf(b)
	name := v.FieldByName(targetName)
	if name.IsValid() && name.Kind() == reflect.Int {
		return int(name.Int())
	} else {
		return 0
	}
}

func (b *BaseArgs) GetBoolArgs(targetName string) bool {
	v := reflect.ValueOf(b)
	name := v.FieldByName(targetName)
	if name.IsValid() && name.Kind() == reflect.Bool {
		return name.Bool()
	} else {
		return false
	}
}

func (b *BaseArgs) AddTargetInfo(flags Flags, pos int) {
	b.targetAddr = flags.targetAddr[pos]
	b.targetSN = flags.targetSN[pos]
	b.targetAlpn = flags.targetAlpn[pos]
	b.targetHost = flags.targetHost[pos]
	b.targetPort = flags.targetPort[pos]
}

func (b *BaseArgs) Make_one_session() (session quic.Connection, cancel context.CancelFunc, err error) {
	connectAddr := b.targetAddr
	serverName := b.targetSN
	// targetAlpn:= b.targetAlpn
	println(serverName)

	address := connectAddr
	name, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid address %v: %w", address, err)
	}

	ip, err := net.LookupIP(name)
	if err != nil {
		return nil, nil, fmt.Errorf("lookup for %v failed: %w", name, err)
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid port: %w", err)
	}

	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, nil, err
	}
	// defer func() { _ = udpConn.Close() }()

	// ctx, cancel := context.WithTimeout(context.Background(), time.Second*1000)
	// defer cancel()
	// go func() {
	// 	<-ctx.Done()
	// 	_ = udpConn.Close()
	// }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*1000)

	udpAddr := &net.UDPAddr{
		IP:   ip[0],
		Port: portInt,
	}
	NextProtos := []string{"h3", "h3-29", "h3-34", "h3-27", "http/0.9", "hq", "hq-29", "doq", "dns", "spdy", "http/1.1", "http/2", "ftp", "imap", "smtp", "pop3", "quic", "h3-q050", "h3-23", connectAddr}

	session, err = quic.Dial(ctx, udpConn, udpAddr,
		&tls.Config{
			NextProtos:         NextProtos,
			ServerName:         serverName,
			InsecureSkipVerify: true,
			KeyLogWriter:       keyLog,
		},
		&quic.Config{
			Versions:             []quic.VersionNumber{quic.Version1},
			MaxIncomingStreams:   -1,
			HandshakeIdleTimeout: 1337 * time.Minute,
			MaxIdleTimeout:       42 * time.Hour,
		})

	if err != nil {
		log.Printf("%s:%s", connectAddr, err.Error())
		return nil, cancel, err
	}

	if err := setup_session(session); err != nil {
		return nil, cancel, err
	}
	return session, cancel, err
}

type Attacker interface {
	GetStringArgs(targetName string) string
	GetUInt64Args(targetName string) uint64
	GetIntArgs(targetName string) int
	AddTargetInfo(Flags, int)
	Make_one_session() (session quic.Connection, cancel context.CancelFunc, err error)
	Attack() (*HTTPMessage, error)
}
