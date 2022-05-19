# SimplePacketCapture

这个是一个小玩具

它可以统计经过指定规则的IP速率

它精简短小，尽可能减少代码冗余，而且cBPF会被翻译成eBPF，过滤效率极高，得益于eBPF和libpcap库，该小玩具统计效率非常高。

## 编译

`gcc capture.c -o capture -lpcap -O2`

## 使用

`./capture "网卡名" "规则"`

规则格式为Pcap所使用的cBPF

例如

`tcp port 1234`

则记录所有经过1234端口的IP速度

## 效果图

![效果图](https://github.com/MeteorsLiu/SimplePacketCapture/raw/main/imgs/image6-1.png)

