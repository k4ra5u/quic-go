
package main
 
import (
    "fmt"
    "net"
    "os"
)
 
func main() {
    // 获取所有网络接口
    interfaces, err := net.Interfaces()
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
 
    // 假设我们选择第一个接口
    var selectedInterface net.Interface
    if len(interfaces) > 0 {
        selectedInterface = interfaces[0]
    } else {
        fmt.Println("No network interfaces found")
        os.Exit(1)
    }
 
    // 获取所有添加到选定接口的非全局未icmp地址
    addrs, err := selectedInterface.Addrs()
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
 
    // 假设我们使用接口上的第一个IPv4地址
    var selectedAddr net.Addr
    for _, addr := range addrs {
        if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            if ipnet.IP.To4() != nil {
                selectedAddr = addr
                break
            }
        }
    }
 
    if selectedAddr == nil {
        fmt.Println("No suitable address found on interface")
        os.Exit(1)
    }
 
    // 使用选定的网卡和地址进行数据发送
    conn, err := net.Dial(selectedAddr.Network(), selectedAddr.String())
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
    defer conn.Close()
 
    _, err = conn.Write([]byte("Hello, world!"))
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}
