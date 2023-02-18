

# 网络安全课程设计

![image](https://github.com/BIIIANG/HUST-CSE-CourseProjectOfNetworkSecurity-FrontEnd--2022/blob/main/imgs/xwall_frontend.png)

## 实验环境

- Ubuntu 22.04.1 LTS, Linux 5.15.0-50-generic；
- 配置方式见“2022网络安全课程设计报告.pdf”中的“6.1 测试环境”。

## 使用方法

- 见“2022网络安全课程设计报告.pdf”中的“六、系统测试”。

## 一些指令

- 防火墙主机网络设置


```shell
# https://blog.csdn.net/weixin_45623111/article/details/117325657
# 主机启用IP转发
sudo sysctl net.ipv4.ip_forward=1
# 清除iptables规则
sudo iptables -F
# 允许路由转发
sudo iptables -P FORWARD ACCEPT
# 查看iptables规则
sudo iptables -nL
# 添加路由
sudo route add -net 10.0.12.0/24 ens37
sudo route add -net 192.168.44.0/24 ens38
```

- 测试指令


```shell
# 监听所有网卡上的ICMP包
sudo tcpdump -i any icmp
# 启动HTTP服务和简单UDP服务
# https://blog.csdn.net/chenfei3306/article/details/119103292
python3 -m http.server 9000
python3 udp.server.py
# 向简单UDP服务发送hello并接收到响应
# https://www.cnblogs.com/frisk/p/14963881.html
# https://blog.csdn.net/demon7552003/article/details/117162103
echo "hello" | nc -u 10.0.12.3 9001
```

- ifconfig只显示lo的解决方法


```shell
# https://blog.csdn.net/u012082566/article/details/122665702
sudo ifconfig ens33 up 
sudo lshw -numeric -class network
sudo route -nv
sudo dhclient -v
```

## 参考资料

```shell
# 编程风格和技巧
# Linux内核编程代码风格
https://www.kernel.org/doc/html/v4.10/process/coding-style.html#
# VSCODE 代码风格配置
{ BasedOnStyle: LLVM, IndentWidth: 4, ColumnLimit: 0, UseTab: Never, BreakBeforeBraces: Linux, AllowShortIfStatementsOnASingleLine: false, IndentCaseLabels: false, AlignConsecutiveMacros: true, ColumnLimit: 80, AlignConsecutiveAssignments: true }
# FALLTHROUGH
https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html#index-Wimplicit-fallthrough
https://borting.github.io/journal/2021/10/02/gcc-switch-fallthrough-warning.html
https://stackoverflow.com/questions/45129741/gcc-7-wimplicit-fallthrough-warnings-and-portable-way-to-clear-them/45137452#45137452
# htoll
https://w3toppers.com/is-there-any-standard-htonl-like-function-for-64-bits-integers-in-c/
```

```shell
# Linux内核编程
# kvzlloc()
https://lwn.net/Articles/711653/
```

```shell
# Netfilter编程
# nf_hook_ops的使用方法
https://github.com/torvalds/linux/blob/fc02cb2b37fe2cbf1d3334b9f0f0eab9431766c4/net/ipv4/netfilter/iptable_nat.c
# nf_register_net_hooks的使用方法
https://github.com/torvalds/linux/blob/6f2b76a4a384e05ac8d3349831f29dff5de1e1e2/security/smack/smack_netfilter.c
# NAT
https://github.com/gtungatkar/NAT
```

```shell
# 内核hlist相关
https://blog.csdn.net/weixin_39094034/article/details/104803967
http://www.davidespataro.it/kernel-linux-list-efficient-generic-linked-list/
http://liuluheng.github.io/wiki/public_html/Embedded-System/kernel/list-and-hlist.html
# 内核哈希表相关
https://kernelnewbies.org/FAQ/Hashtables
https://lwn.net/Articles/510202/
https://github.com/torvalds/linux/blob/5bfc75d92efd494db37f5c4c173d3639d4772966/include/linux/hashtable.h
https://github.com/torvalds/linux/blob/5bfc75d92efd494db37f5c4c173d3639d4772966/drivers/net/wireguard/peerlookup.c
# 哈希函数
https://github.com/troydhanson/uthash
https://troydhanson.github.io/uthash/userguide.html#hash_functions
```

```shell
# 数据包相关
# ICMP
https://blog.csdn.net/u012206617/article/details/115519107
# TCP FLAG
https://github.com/torvalds/linux/blob/fc02cb2b37fe2cbf1d3334b9f0f0eab9431766c4/tools/testing/selftests/bpf/progs/xdpwall.c
```

```shell
# 锁相关
# RWLOCK
https://embetronicx.com/tutorials/linux/device-drivers/read-write-spinlock/
# RWLOCK & SEQLOCK
https://blog.csdn.net/wangquan1992/article/details/124837620
# MUTEX
https://embetronicx.com/tutorials/linux/device-drivers/linux-device-driver-tutorial-mutex-in-linux-kernel/
```

```shell
# Linux内核定时器
https://blog.csdn.net/qq_42174306/article/details/122770059
https://blog.csdn.net/hhhhhyyyyy8/article/details/102885037
```

```shell
# Linux内核文件读写
参考Linux内核代码
```

## TODOs

### 后端

- 若存在一个`ACCEPT`规则且通过该规则建立了连接，那么删除该规则后，为了清除根据该规则建立的连接，采取了最简单的策略：删除规则后清空整个连接表，但这会影响到其他连接（另一个情况是默认策略从`ACCEPT`修改到`DROP`时，采用相同的策略）；
- 若默认策略为`ACCEPT`且有一个包没有匹配的规则和连接从而使用了默认策略，则是否要根据这个包建立连接（当前建立了连接）；
- 目前对所有`ACCEPT`和`DROP`的包都记录了相应的日志，没有日志自动清理功能，面对大量包时可能会由于内存不足导致系统崩溃（但是在内存分配时有相应的错误处理，是否真的会导致崩溃未知）；
- 备份时规则的超时时间也会被保存到文件中，且下次再次读入时没有做相应的延时；
- 删除规则时为了保持规则的有序没有将规则数目相应减1，导致`rule_num`不一定是实际的规则数，在交互时（如`xwall_ruletable_read()`）有一些约定；
- 在`xwall_save_rule()`中，如果已有的`/tmp/xwall.rule`里的规则数比当前要备份的规则数多，那么多余的规则无法被覆盖（也有可能和读写锁导致写锁不能及时将规则删除有关）；
- 为了开发期间方便进行调试，未做`INPUT`包和`OUTPUT`包的过滤，可以在`NF_INET_LOCAL_IN`和`NF_INET_LOCAL_OUT`添加相应的`Hook`，也可以将`NF_INET_FORWARD`处的`Hook`更改到`NF_INET_PRE_ROUTING`的`NAT`后和`NF_INET_POST_ROUTING`处的`NAT`前；
- `XWALL_OP_ADDNAT`、`XWALL_OP_DELNAT`及`XWALL_OP_READNAT`均未实现。

### 前端

- 添加规则的页面当协议为`ICMP`时应不用填写端口相关信息；
- 添加规则的页面中，日志默认没有表单默认值，若需要添加日志为`FALSE`的规则，需要将日志的开关打开再关闭；
- 查看规则的页面中的端口转换函数`getPort (portMin, portMax)`的逻辑与运算符写成了算数与，源码中已修改，但`AppImage`没有重新打包。
