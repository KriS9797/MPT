# ddoster

## About
Repository of Reactive firewall for SSP and MPT projects.

## Installation

Sample:
via git clone: git clone https://github.com/KriS9797/MPT.git

## Usage

Repository contains topology of network in mininet and python scripts for ryu controller. 

## Code

### Requirements

OpenFlow => 1.0

### Setup environment


1. Controller installation:
 
```sh
$ pip install ryu
```

2. Starting the controller:
 
```sh
$ ryu-manager simple_manager_13.py
```
_You can find this file on your local pc via command: $ find / -name simple_monitor*_

3. Running topology:

```sh
$ sudo mn --custom topology.py --topo mytopo --controller=remote,ip=127.0.0.1 --switch ovsk,protocols=OpenFlow13
```
 
4. Collecting packages (pcap files):
 
```sh
$ tcpdump -i h4-eth0 -w h4.pcap &
$ tcpdump -i h5-eth0 -w h5.pcap &
$ tcpdump -i h6-eth0 -w h6.pcap &
 ```
 
5. Generating server traffic:

```sh
$ iperf -s -u -p 80 -i 1 &
$ iperf -s -u -p 53 -i 1 &
$ iperf -s -u -p 10 -i 1 &
```

```sh
$ perf -c 10.0.0.7 -p 80 -u -t 15 &
$ iperf -c 10.0.0.8 -p 53 -u -t 15 &
$ iperf -c 10.0.0.9 -p 10 -u -t 15 &
 ```
 
6. Generating attack traffic:

- SYNFLOOD

```sh
$ hping3 -c 10000 -i u10 -d 150 -S -p 80 --flood 10.0.0.3
```

- UDPFLOOD

```sh
$ hping3 -c 10000 -i u10 -d 150 --udp -p 80 --flood 10.0.0.3
```
 
## License

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0.html)
