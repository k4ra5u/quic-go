package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/k4ra5u/quic-go"
	"github.com/quic-go/qpack"
)

type Header struct{ Name, Value string }
type Headers []Header

type Task func()

// WorkerPool 结构体包含一个工作池的基本信息
type WorkerPool struct {
	taskQueue chan Task
	wg        sync.WaitGroup
}

type HTTPMessage struct {
	Headers Headers
	Body    []byte
}

var keyLog io.Writer

func main() {
	keyLogFile := "../key.log"
	options := []string{"cidFlood", "quicVersion", "cryptoFlood", "frameFlood", "pcdos", "quicheFlood", "h3Req", "all"}

	if len(keyLogFile) > 0 {
		f, err := os.Create(keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}
	parseFlags, err := parse_flags(options)
	if err != nil {
		os.Exit(1)
	}
	flags := *parseFlags
	var base_arg BaseArgs
	base_arg.repeatTimes = flags.repeatTimes
	attackModel := createAttackModel(flags.targetMethod, base_arg)

	if flags.multiThread <= 1 {
		for i := 0; i < flags.targetLen; i++ {
			if flags.startPos != 0 {
				if i < flags.startPos {
					continue
				}
			}
			if flags.endPos != 0 {
				if i > flags.endPos {
					break
				}
			}
			attackModel.AddTargetInfo(flags, i)
			try_failed := 1
			for j := 0; j < 1; j++ {
				_, err := attackModel.Attack()
				if err == nil {
					break
				}
				try_failed -= 1
			}
			if try_failed == 0 {

				fmt.Printf("failed: %s:%s", attackModel.GetStringArgs("targetAddr"), err.Error())
			}
		}
	} else {
		pool := NewWorkerPool(flags.multiThread)
		for i := 0; i < flags.targetLen; i++ {
			if flags.startPos != 0 {
				if i < flags.startPos {
					continue
				}
			}
			if flags.endPos != 0 {
				if i > flags.endPos {
					break
				}
			}
			pool.AddTask(func() {
				attackModel.AddTargetInfo(flags, i)
				try_failed := 1
				for j := 0; j < 1; j++ {
					_, err := attackModel.Attack()
					if err == nil {
						break
					}
					try_failed -= 1
				}
				if try_failed == 0 {
					fmt.Printf("failed: %s:%s", attackModel.GetStringArgs("targetAddr"), err.Error())
				}
				time.Sleep(time.Second * 1)
			})
		}
	}

	log.Printf("All workers have finished, exiting the program.")
}

type http3Frame struct {
	Type int
	Len  uint64
	Data []byte
}

func readFrame(b *bufio.Reader) (*http3Frame, error) {
	t, err := readVarInt(b)
	if err != nil {
		return nil, err
	}
	l, err := readVarInt(b)
	if err != nil {
		return nil, err
	}
	data := make([]byte, l)
	if _, err := io.ReadFull(b, data); err != nil {
		return nil, err
	}
	return &http3Frame{
		Type: int(t),
		Len:  l,
		Data: data,
	}, nil
}

func encodeHeaders(headers Headers) []byte {
	qpackBuf := bytes.NewBuffer(nil)
	e := qpack.NewEncoder(qpackBuf)
	for _, h := range headers {
		_ = e.WriteField(qpack.HeaderField{Name: h.Name, Value: h.Value})
	}
	headersFrame := bytes.NewBuffer(nil)
	writeVarInt(headersFrame, 0x1)
	writeVarInt(headersFrame, uint64(qpackBuf.Len()))
	headersFrame.Write(qpackBuf.Bytes())
	return headersFrame.Bytes()
}

func encodeBodyHeader(size int) (frame []byte) {
	buf := bytes.NewBuffer(nil)
	writeVarInt(buf, 0x00)
	writeVarInt(buf, uint64(size))
	return buf.Bytes()
}

const (
	maxVarInt1 = 63
	maxVarInt2 = 16383
	maxVarInt4 = 1073741823
	maxVarInt8 = 4611686018427387903
)

func readVarInt(b io.ByteReader) (uint64, error) {
	firstByte, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	// the first two bits of the first byte encode the length
	intLen := 1 << ((firstByte & 0xc0) >> 6)
	b1 := firstByte & (0xff - 0xc0)
	if intLen == 1 {
		return uint64(b1), nil
	}
	b2, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	if intLen == 2 {
		return uint64(b2) + uint64(b1)<<8, nil
	}
	b3, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b4, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	if intLen == 4 {
		return uint64(b4) + uint64(b3)<<8 + uint64(b2)<<16 + uint64(b1)<<24, nil
	}
	b5, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b6, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b7, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b8, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	return uint64(b8) + uint64(b7)<<8 + uint64(b6)<<16 + uint64(b5)<<24 + uint64(b4)<<32 + uint64(b3)<<40 + uint64(b2)<<48 + uint64(b1)<<56, nil
}

func writeVarInt(b *bytes.Buffer, i uint64) {
	if i <= maxVarInt1 {
		b.WriteByte(uint8(i))
	} else if i <= maxVarInt2 {
		b.Write([]byte{uint8(i>>8) | 0x40, uint8(i)})
	} else if i <= maxVarInt4 {
		b.Write([]byte{uint8(i>>24) | 0x80, uint8(i >> 16), uint8(i >> 8), uint8(i)})
	} else if i <= maxVarInt8 {
		b.Write([]byte{
			uint8(i>>56) | 0xc0, uint8(i >> 48), uint8(i >> 40), uint8(i >> 32),
			uint8(i >> 24), uint8(i >> 16), uint8(i >> 8), uint8(i),
		})
	} else {
		panic(fmt.Sprintf("%#x doesn't fit into 62 bits", i))
	}
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	fmt.Printf("Server: Got '%s'\n", string(b))
	return w.Writer.Write(b)
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}

func setup_session(session quic.Connection) error {
	str, err := session.OpenUniStream()
	if err != nil {
		return err
	}
	buf := &bytes.Buffer{}
	buf.Write([]byte{0x0, 0x4, 0x0}) // TODO: this is shit
	if _, err := str.Write(buf.Bytes()); err != nil {
		return err
	}
	return nil
}

func parse_flags(options []string) (*Flags, error) {
	var flags Flags

	// 没有指定 inputFile 需要执行以下几个字段
	target_addr := flag.String("i", "myserver.xx", "IP")
	target_port := flag.String("p", "58443", "PORT")
	target_alpn := flag.String("a", "h3", "ALPN")
	target_sn := flag.String("n", "", "ServerName")
	// 指定了inputFile 可选startPOS和endPOS，inputFile中需要给出上面的内容
	target_file := flag.String("f", "", "inputFile")
	start_pos := flag.Int("s", 0, "startPos")
	end_pos := flag.Int("e", 0, "endPos")
	// 需要给出用来攻击的模式 以及攻击的参数
	flag.StringVar(&flags.targetMethod, "m", options[0], fmt.Sprintf("Specify an option: %v", options))
	repeat_times := flag.Uint64("rep", 1000, "repeatTimes")
	multi_thread := flag.Int("thread", 1, "threads for this attack")
	quiet := flag.Bool("q", false, "don't print the data")

	// 检查 option 是否在备选项中
	validOption := false
	for _, opt := range options {
		if flags.targetMethod == opt {
			validOption = true
			break
		}
	}
	// 如果 option 不在备选项中，打印使用说明并退出程序
	if !validOption {
		fmt.Printf("Invalid method for -m. Please choose one of: %v\n", options)
		flag.Usage()
		return nil, fmt.Errorf("invalid args")
	}
	//如果既没有指定文件名 也没有指定端口信息，则报错
	if *target_file == "" && (*target_addr == "" || *target_port == "" || *target_alpn == "") {
		fmt.Printf("Invalid args for -f. Please specify choice for input flie or address & port & alpn\n")
		flag.Usage()
		return nil, fmt.Errorf("invalid args")
	}

	flag.Usage = func() {
		flag.PrintDefaults()
	}

	flag.Parse()
	flags.startPos = *start_pos
	flags.endPos = *end_pos
	flags.repeatTimes = *repeat_times
	flags.targetFile = *target_file
	flags.multiThread = *multi_thread
	flags.quiet = *quiet

	if *target_file == "" {
		targetAddr := *target_addr
		targetPort := *target_port
		targetAlpn := *target_alpn
		targetSN := *target_sn
		if targetSN == "" {
			targetSN = targetAddr
		}

		//检查targetaddr是否包含端口信息
		if thisHost, thisPort, err := net.SplitHostPort(targetAddr); err != nil {
			//如果没有端口信息，则添加默认端口
			flags.targetHost = append(flags.targetHost, targetAddr)
			flags.targetPort = append(flags.targetPort, targetPort)
			targetAddr = net.JoinHostPort(targetAddr, targetPort)
		} else {
			//如果有端口信息，则使用splitHostPort返回的端口信息
			flags.targetHost = append(flags.targetHost, thisHost)
			flags.targetPort = append(flags.targetPort, thisPort)
		}
		flags.targetLen = 1
		flags.targetAddr = append(flags.targetAddr, targetAddr)
		flags.targetPort = append(flags.targetPort, targetPort)
		flags.targetAlpn = append(flags.targetAlpn, targetAlpn)
		flags.targetSN = append(flags.targetSN, targetSN)
	} else {
		Content, ferr := os.ReadFile(*target_file)
		if ferr != nil {
			fmt.Errorf("invalid file : %w", ferr)
			return nil, fmt.Errorf("invalid filename")
		}
		addrs := [...]string{}
		addrSlice := addrs[:]
		ports := [...]string{}
		portSlice := ports[:]
		alpns := [...]string{}
		alpnSlice := alpns[:]
		serverNames := [...]string{}
		snSlice := serverNames[:]

		file_contents := bytes.Split(Content, []byte("\n"))
		length := len(file_contents)
		log.Println("Total %d items\n", length)

		for _, file_content := range file_contents {
			if len(file_content) == 0 {
				length -= 1
				continue
			}
			contents := bytes.Split(file_content, []byte(" "))
			addrSlice = append(addrSlice, string(contents[0]))
			// port is optional
			if len(contents) <= 1 {
				portSlice = append(portSlice, "443")
			} else {
				portSlice = append(portSlice, string(contents[1]))
			}
			// alpn is optional
			if len(contents) <= 2 {
				alpnSlice = append(alpnSlice, "h3")
			} else {
				alpnSlice = append(alpnSlice, string(contents[2]))
			}
			// SN is optional
			if len(contents) <= 3 {
				snSlice = append(snSlice, string(contents[0]))
			} else {
				snSlice = append(snSlice, string(contents[3]))
			}
		}
		flags.targetLen = length
		for i := 0; i < length; i++ {
			thisAddr := addrSlice[i]
			thisPort := portSlice[i]
			thisAlpn := alpnSlice[i]
			thisSn := snSlice[i]
			var targetAddr string

			//检查targetaddr是否包含端口信息
			if thisHost, thisPort, err := net.SplitHostPort(thisAddr); err != nil {
				//如果没有端口信息，则添加默认端口
				flags.targetHost = append(flags.targetHost, targetAddr)
				targetAddr = net.JoinHostPort(thisAddr, thisPort)
			} else {
				//如果有端口信息，则使用splitHostPort返回的端口信息
				flags.targetHost = append(flags.targetHost, thisHost)
			}

			flags.targetAddr = append(flags.targetAddr, targetAddr)
			flags.targetPort = append(flags.targetPort, thisPort)
			flags.targetAlpn = append(flags.targetAlpn, thisAlpn)
			flags.targetSN = append(flags.targetSN, thisSn)

		}
	}
	return &flags, nil
}

// NewWorkerPool 创建一个新的工作池
func NewWorkerPool(numWorkers int) *WorkerPool {
	pool := &WorkerPool{
		taskQueue: make(chan Task),
	}

	// 启动指定数量的 worker
	for i := 0; i < numWorkers; i++ {
		pool.wg.Add(1)
		go pool.worker()
	}

	return pool
}

// worker 是一个工作函数，用于从任务队列中获取任务并执行
func (wp *WorkerPool) worker() {
	defer wp.wg.Done()
	for task := range wp.taskQueue {
		task()
	}
}

// AddTask 向任务队列中添加一个任务
func (wp *WorkerPool) AddTask(task Task) {
	wp.taskQueue <- task
}

// Shutdown 关闭任务队列，并等待所有 worker 完成任务
func (wp *WorkerPool) Shutdown() {
	close(wp.taskQueue)
	wp.wg.Wait()
}

func createAttackModel(targetMethod string, base_arg BaseArgs) Attacker {
	var attackModel Attacker
	switch targetMethod {
	case "quicVersion":
		attackModel = &quicVersion{
			BaseArgs: base_arg,
		}
	case "cidFlood":
		attackModel = &cidFlood{
			BaseArgs: base_arg,
		}
	case "cryptoFlood":
		attackModel = &cryptoFlood{
			BaseArgs: base_arg,
		}
	case "frameFlood":
		attackModel = &frameFlood{
			BaseArgs: base_arg,
		}
	case "pcDos":
		attackModel = &pcDos{
			BaseArgs: base_arg,
		}
	case "quicheFlood":
		attackModel = &quicheFlood{
			BaseArgs: base_arg,
		}
	case "all":
		attackModel = &allField{
			BaseArgs: base_arg,
		}
	case "h3Req":
		attackModel = &h3Req{
			BaseArgs: base_arg,
		}
	}
	return attackModel
}
