kprobe 一些跟网络监控常见场景的钩子：ip_send_skb、skb_consume_udp 和 tcp_sendmsg 

## ip_send_skb
监控ip协议层发送的所有数据包
监控主机的总出站流量

## skb_consume_udp
udp消费的数据包，接受udp的数据包的时候调用

## tcp_sendmsg
监控tcp协议的出站流量

如果是设计一个按namespace维度，按出口ip维度来设计k8s流量计费系统，使用ebpf技术