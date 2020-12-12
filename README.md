UCLA CS118 Project (Simple Router)
====================================

For more detailed information about the project and starter code, refer to the project description on CCLE.

(For build dependencies, please refer to [`Vagrantfile`](Vagrantfile).)

## Makefile

The provided `Makefile` provides several targets, including to build `router` implementation.  The starter code includes only the framework to receive raw Ethernet frames and to send Ethernet frames to the desired interfaces.  Your job is to implement the routers logic.

Additionally, the `Makefile` a `clean` target, and `tarball` target to create the submission file as well.

You will need to modify the `Makefile` to add your userid for the `.tar.gz` turn-in at the top of the file.

## Academic Integrity Note

You must host your code in private repositories on [GitHub](https://github.com/), [GitLab](https://gitlab.com), or other places.  At the same time, you are PROHIBITED to make your code for the class project public during the class or any time after the class.  If you do so, you will be violating academic honestly policy that you have signed, as well as the student code of conduct and be subject to serious sanctions.

## Known Limitations

When POX controller is restrated, the simpler router needs to be manually stopped and started again.

## Acknowledgement

This implementation is based on the original code for Stanford CS144 lab3 (https://bitbucket.org/cs144-1617/lab3).

## My information
**Name:** Zijian Zhao<br>
**UID:** 005355458

## Higher level design
The main idea of router is to maintain a list of ARP/NAT cache and handle ICMP or ARP request from client or other iterfaces. The major part of this project is the `simple_router()`, where the part `handlePacket()` handles both the ARP and IPv4 packets. To simplify the implementation and increase code readability, I have implemented two new class methods: `handle_arp` and `handle_ipv4`, which deal with two different types of packets respectively. In each methods, I carefully parse the receiving packets' header and create new buffer packets with the new header information which includes new dst_ip and src_ip, new checksum, updated ttl, etc. Packets are sent using given class method `sendPackets()` with built-in CRC error check. All we need to take care of is the header information. Also, for the arp_cache, I need to implement a method in arp_cache class which periodically check for requests and decide their fate. Back in the router, this method only needs to be called when an arp request is pulled (whenever the ip is not seen in arp cache).

Another part of the project is to implement an NAT translator. To accomplish this funcionality, I have several methods implemented in NAT class and routing table to properly lookup the NAT table and give back translated (mapped) internal/external ip address correcponding to the given external/internal ip address.

## Difficulty
When I implemented all classes in the way I thought, the first few trials of pings failed. I looked back to my packet handler and printed out all header information and turns out the destination ip address was mis-given. Another problem I have encountered was that when I tried to send large files, the arp cache usually needs to maintain a relatively long time. When the arp entries dies after 30s, new arp entries should be requested. The problem was tens of new entries was pushed back at time 0 and the transmission fails immediately probably caused by the timeout. Then I figure out the time period between each requests should be actually at least 1 second, so adding an extra layer of time interval check in the `ArpCache::periodicCheckArpRequestsAndCacheEntries()` solved the issue.

There is one more issue not yet to be solved completely (I think) is the random fails in large file transmission. The large file sometimes paused to transmit and just let the packet timeout. The problem was solved by a random change: by changing `m_cacheEntries.erase()` to built-in class method `removeRequest()` in `ArpCache::periodicCheckArpRequestsAndCacheEntries()`. The error indeed disappeared after a few tests but not yet sure it's gone for good since I do not know how it works. One guess is that the `removeRequest` uses `std::lock_guard<std::mutex>` which is a thread-safe operation, shared memory would not be messed up under such operation.
