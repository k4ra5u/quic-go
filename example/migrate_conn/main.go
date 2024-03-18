package main

import (
	"encoding/json"
	"fmt"
	"net"
)

type Message struct {
	Aaa string
	Bbb string
	Ccc []byte
}

func main() {
	// 定义监听的UDP端口
	serverPort := "10443"

	// 创建UDP地址
	serverAddr, err := net.ResolveUDPAddr("udp", ":"+serverPort)
	if err != nil {
		fmt.Println("无法解析地址:", err)
		return
	}

	// 监听UDP端口
	conn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		fmt.Println("无法监听UDP端口:", err)
		return
	}
	defer conn.Close()

	fmt.Println("等待接收消息...")

	// 读取消息
	buffer := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		fmt.Println("读取消息时发生错误:", err)
		return
	}

	// 反序列化消息
	var receivedMessage Message
	err = json.Unmarshal(buffer[:n], &receivedMessage)
	if err != nil {
		fmt.Println("反序列化消息时发生错误:", err)
		return
	}

	// 打印接收到的消息
	fmt.Println("收到的消息:")
	fmt.Println("Aaa:", receivedMessage.Aaa)
	fmt.Println("Bbb:", receivedMessage.Bbb)
	fmt.Println("Ccc:", receivedMessage.Ccc)
}
