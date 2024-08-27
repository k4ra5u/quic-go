# gen_test使用方法
## 参数
```sh
  -a string
        ALPN (default "h3")
  -e int
        endPos
  -f string
        inputFile
  -i string
        IP (default "myserver.xx")
  -m string
        Specify an option: [cidFlood quicVersion cryptoFlood frameFlood pcdos quicheFlood h3Req all] (default "cidFlood")
  -n string
        ServerName
  -p string
        PORT (default "58443")
  -q    don't print the data
  -rep uint
        repeatTimes (default 1000)
  -s int
        startPos
  -thread int
        threads for this attack (default 1)
  example:
        ./gen_test -i myserver.xx -a h3 -rep 10000 -m cryptoFlood
        ./gen_test -i myserver.xx -a h3 -p 58443 -q -m h3Req
        ./gen_test -i myserver.xx -a h3 -m cidFlood
        ./gen_test -i myserver.xx -a h3 -rep 10000 -m quicheFlood
```

- cidFlood 握手完成后批量发送new_cid = retire_cid 的 nci 帧，目前无法做到控制回复retirecid帧的速率，所以基本只能靠进行概念验证
    - ./gen_test -i myserver.xx -a h3 -m cidFlood
- quicVersion 进行测量时需要预测其在哪个端口开放了quic协议，quicVersion会根据ip列表测试常见的端口是否开放了quic协议
    - ./gen_test -i myserver.xx -m quicVersion
    - ./gen_test -f ips.txt -s 100 -e 200 -m quicVersion
- cryptoFlood: 握手完成后批量的发送 offset 跳跃的 CRFYPTO 帧，检测是否会造成大量的内存和CPU占用
    - ./gen_test -i myserver.xx -a h3 -rep 10000 -m cryptoFlood
- frameFlood: 握手完成后先指定一个较小的http3 header length ,之后在流上覆盖一个大的,尝试发送大量的数据
    - 本意是测试所有标记内容长度的字段,因为quic为这些字段提供的长度范围相当大,假如设置了相当大的长度,在后续的传输过程中是否会出现什么问题
    - 目前有3种衍生的想法,以HTTP/3中header头长度为例:
    - 当指定header长度为非常大的数字时,并试图发送大量的数据时,会产生什么样的后果
    - 当header长度不允许过大的数字时,先指定一个较小的值,再在stream流上覆盖一个较大的值,能否混淆或绕过长度限制
    - 每种quic实现都会对这类字段进行一些硬编码的限制,这些限制轻易不会随着版本更迭来修改,同时缺乏统一标准,各个quic实现对此限制的大小也不同,组合起来可以作为指纹尝试来判断quic服务器版本.
    - ./gen_test -i myserver.xx -p 58443 -a h3 -m frameFlood
- pcdos: 测试基于path challenge的流量放大攻击，基于服务器没有严格要求客户端对path challenge进行填充，客户端生成path callenge请求，并通过python程序伪造四元组发送
    - ./gen_test
- quicheFlood: 针对0.24.0（可能）之前的 cloudflare quiche，握手完成并在流上发送带有fin的数据，重复上述过程可以造成DOS攻击
    - ./gen_test -i myserver.xx -a h3 -rep 10000 -m quicheFlood
- h3Req: 正常发送http3请求，可以设置访问间隔
    - ./gen_test -i myserver.xx -a h3 -p 58443 -q -m h3Req
- all: 本意是同时测试上述所有的攻击模型，但是目前没有实现