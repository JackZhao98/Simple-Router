/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface, int nat_flag)
{
    std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

    const Interface* iface = findIfaceByName(inIface);
    if (iface == nullptr) {
        std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
        return;
    }

    std::cerr << getRoutingTable() << std::endl;

    // FILL THIS IN
    
    // Verify packet size, if smaller than ether min size, return
    if (packet.size() < sizeof(ethernet_hdr)) {
        std::cerr << "[ERROR] Wrong packet length! Ignored.\n";
        return;
    }
    
    
    
    // Then, verify the address.
    std::string iface_addr = macToString(iface -> addr);
    std::string packet_dest = macToString(packet);

    if ((packet_dest != iface_addr) && (packet_dest != "FF:FF:FF:FF:FF:FF") && (packet_dest != "ff:ff:ff:ff:ff:ff")) {
        std::cerr << "[NOTE] Packet not destined to this router!\n";
        return;
    }
    
    Buffer packet_copy(packet);
    uint8_t* packet_hdr = packet_copy.data();
    ethernet_hdr* ether_hdr = (ethernet_hdr*)packet_header;
    
    auto ether_type = ether_hdr -> ether_type;
    if (ether_type == htons(ethertype_arp)) {
        // TODO: Handle ARP Packets
        handle_arp(packet_hdr + sizeof(ethernet_hdr), ether_hdr -> ether_shost, iface);
    }
    else if (ether_type == htons(ethertype_ip)) {
        // TODO: Handle IPv4 Packets
        handle_ipv4(packet, inIface, nat_flag);
    }
    else {
        std::cerr << "[ERROR] Unknown type of packet, ignored.\n";
        return;
    }
}

// New Class methods, TODO: Add definition to hpp file
void SimpleRouter::handle_arp(uint8_t* arp, uint8_t* sender_mac, const Interface* iface) {
    arp_hdr* arp_header = (arp_hdr*)arp;
    
    if (arp_header -> arp_hrd != htons(arp_hrd_ethernet)) return;
    
    uint16_t ARP_OP = ntohs(arp_header->arp_op);
    
    if (ARP_OP == arp_op_request) {
        
        std::cout << "[DEBUG] Handling arp_op_request...\n";
        
        if (arp_header -> arp_tip != iface -> ip) {
            // It means the request is not for this router
            return;
        }
        // Preparing output buffer
        Buffer outputBuffer(sizeof(ethernet_hdr) + sizeof(arp_hdr));
        uint8_t* output_hdr = (uint8_t *)outputBuffer.data();
         
        // Generate Ether header
        ethernet_hdr* output_e_hdr = (ethernet_hdr *)output_hdr;
        output_e_hdr -> ether_type = htons(ethertype_arp);
        memcpy(output_e_hdr -> ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
        memcpy(output_e_hdr -> ether_dhost, sender_mac, ETHER_ADDR_LEN);
        
        // Generate ARP header
        arp_hdr* output_a_hdr = (arp_hdr *)(output_hdr + sizeof(ethernet_hdr));
        memcpy(output_a_hdr, arp_header, sizeof(arp_hdr));
        output_a_hdr -> arp_op = htons(arp_op_reply);
        memcpy(output_a_hdr -> arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
        output_a_hdr -> arp_sip = iface -> ip;
        memcpy(output_a_hdr -> arp_tha, arp_header -> arp_sha, ETHER_ADDR_LEN);
        output_a_hdr -> arp_tip = arp_header -> arp_sip;
        
        sendPacket(outputBuffer, iface->name);
    }
    
    else if (ARP_OP == arp_op_reply) {
        std::cout << "[DEBUG] Handling arp_op_reply...\n";
        uint32_t sip = arp_header -> arp_sip;
        Buffer mac(ETHER_ADDR_LEN);
        memcpy(mac.data(), arp_header -> arp_sha, ETHER_ADDR_LEN);
        
        std::shared_ptr<ArpRequest> request = m_arp.insertArpEntry(mac, sip);
        
        if (request) {
            for (auto packetIter = request -> packets.begin(); packetIter != packets.end(); packetIter ++) {
                ethernet_hdr * tmp_e_header = (ethernet_hdr *)(packetIter -> packet.data());
                memcpy(tmp_e_header -> ether_shost, iface -> addr.data(), ETHER_ADDR_LEN);
                memcpy(tmp_e_header -> ether_dhost, arp_header -> arp_sha, ETHER_ADDR_LEN);
                
                sendPacket(packetIter -> packet, packetIter -> iface);
            }
            m_arp.removeRequest(request);
        }
    }
    
    else {
        std::cerr << "[handle_arp] Unknown ARP type. Ignored\n";
    }

    return;
}

void SimpleRouter::handle_ipv4(const Buffer& packet, const std::string &inface, int& nat) {
    // TODO: Veridy packet_size
    if (packet.size() < (sizeof(ethernet_hdr) + sizeof(ip_hdr))) {
        std::cerr << "[handle_ip] IPv4 packet received, but the size is too small.\n";
        return;
    }
    Buffer new_packet(packet);
    ip_hdr* ip_header = (ip_hdr *)(new_packet.data() + sizeof(ethernet_hdr));
    // TODO: Verify Checksum
    uint16_t checksum = ip_header -> ip_sum;
    ip_header -> ip_sum = 0;
    if (checksum != cksum(ip_header, sizeof(ip_hdr))) {
        std::cerr << "[handle_ip] IPv4 packet received, but the checksum value is incorrect.\n";
        return;
    }
    
    /*
      ##############
        TODO: NAT!!
      ##############
     
     */
    
    bool NAT_processed = false;
    switch (nat_flag) {
        case 1:
            icmp_hdr *icmp_header = (icmp_hdr *)(new_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
            ip_hdr *ip_h = (ip_hdr *)(new_packet.data() + sizeof(ethernet_hdr));
            const Interface* internal_iface = findIfaceByName(inface);
            uint32_t internal_ip = 0;
            uint32_t external_ip = 0;
            auto found_nat = m_natTable.lookup(icmp_header -> icmp_id);
            if (found_nat) {
                std::cerr << "[DEBUG] Found NAT! Converting...\n";
                internal_ip = found_nat -> internal_ip;
                external_ip = found_nat -> external_ip;
                found_nat -> timeUsed = steady_clock::now();
            }
            if (icmp_header -> icmp_type == 8) {
                std::cerr << "[DEBUG] Type 8, NAT processed!\n";
                if (!found_nat) {
                    internal_ip = internal_iface -> ip;
                    // Assign external ip
                    external_ip = 0;
                    for (auto iter = m_routingTable.begin(); iter != m_routingTable.end(); iter ++) {
                        auto tmp = m_routingTable.lookup(iter -> ip);
                        if (!tmp -> dest) {
                            external_ip = iter -> ip;
                            break;
                        }
                        else if (tmp -> gw != internal_ip && tmp -> dest != internal_ip) {
                            external_ip = iter -> ip;
                            break;
                        }
                        else
                            continue;
                    }
                    if (!external_ip) {
                        std::cerr << "[ERROR] Oops, no external ip can be assigned!\n";
                        return;
                    }
                    else {
                        std::cerr << "[DEBUG] External ip is now: " << ipToString(external_ip) << std::endl;
                    }
                    
                    auto tmp_dst = findIfaceByName(ip_h -> ip_dst);
                    if (!tmp_dst) {
                        NAT_processed = !NAT_processed;
                        m_natTable.insertNatEntry(icmp_header -> icmp_id, internal_ip, external_ip);
                        ip_h -> ip_src = external_ip;
                    }
                    else {}
                }
                else if (found_nat) {
                    NAT_processed = !NAT_processed;
                    // Having NAT found,
                    // Change the destination ip to the internal ip address
                    ip_h -> ip_dst = internal_ip; // necessary?
                    ip_h -> ip_dst = m_routingTable.lookup(internal_ip).gw;
                }
                std::cerr << "[DEBUG] NAT is done.\n";
                std::cerr << "\tInternal: " << ipToString(internal_ip) << std::endl;
                std::cerr << "\tExternal: " << ipToString(external_ip) << std::endl;
            }
            break;
        default:
            break;
    }
    /*
      ##############
        END OF NAT!!
      ##############
     
     */
    const Interface* dest = findIfaceByIp(ip_header -> ip_dst);
    
    if (dest && !NAT_processed) {
        std::cerr << "[DEBUG] handle_ip: ICMP is detined for this router\n";
        if (ip_header -> ip_p != ip_protocol_icmp) {
            std::cerr << "[ERROR] handle_ip: Protocol is not icmp.\n";
            return;
        }
        icmp_hdr *icmp_header = (icmp_hdr *)(new_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
        if (icmp_header -> icmp_type != 8) {
            std::cerr << "[ERROR] hadnle_ip: icmp_type is not 8: " << icmp_header->icmp_type << std::endl;
            return;
        }
        // TODO: Send icmp packet
        std::cerr << "[DEBUG] Sending ICMP echo reply...\n";
        const Interface* tmp_iface = findIfaceByName(inface);
        
        // This is the return/reply datapack
        Buffer reply(packet);
        
        uint8_t* original_hdr = (uint8_t *)packet.data();
        uint8_t* reply_hdr = (uint8_t *)reply.data();
        ethernet_hdr* original_ether = (ethernet_hdr *)packet.data();
        ethernet_hdr* reply_ether = (ethernet_hdr *)reply.data();
        ip_hdr* original_ip = (ip_hdr *)(packet.data() + sizeof(ethernet_hdr));
        ip_hdr* reply_ip = (ip_hdr *)(reply.data() + sizeof(ethernet_hdr));
        icmp_hdr* original_icmp = (icmp_hdr *)(packet.data() + sizeof(ether_hdr) + sizeof(ip_hdr));
        icmp_hdr* reply_icmp = (icmp_hdr *)(reply.data() + sizeof(ether_hdr) + sizeof(ip_hdr));
        
        // Create ethernet header
        memcpy(reply_ether -> ether_shost, tmp_iface -> addr.data(), ETHER_ADDR_LEN);
        memcpy(reply_ether -> ether_dhost, original_ether -> ether_shost, ETHER_ADDR_LEN);
        reply_ether -> ether_type = original_ether -> ether_type;
        
        // Create ip header
        reply_ip -> ip_len = htons(packet.size() - sizeof(ether_hdr));
        reply_ip -> ip_ttl = 64;
        reply_ip -> ip_p = ip_protocol_icmp;
        // Swap src and dst
        reply_ip -> ip_src = original_ip -> ip_dst;
        reply_ip -> ip_dst = original_ip -> ip_src;
        reply_ip -> ip_sum = 0;
        reply_ip -> ip_sum = cksum(reply_ip, sizeof(ip_hdr));
        
        // Create icmp header
        reply_icmp -> icmp_type = 0;
        reply_icmp -> icmp_code = 0;
        reply_icmp -> icmp_id = original_icmp -> icmp_id;
        reply_icmp -> icmp_seq = original_icmp -> icmp_seq;
        reply_icmp -> icmp_sum = 0;
        reply_icmp -> icmp_sum = cksum(reply_icmp, reply.size() - (sizeof(ethernet_hdr) + sizeof(ip_hdr)));
        
        // Prepare to send
        std::cerr << "[DEBUG] ICMP reply header is prepared, preparing to send...\n";
        RoutingTableEntry routing_entry = m_routingTable.lookup(original_hdr -> ip_dst);
        if (!m_arp.lookup(routing_entry.gw)) {
            std::cerr << "[WARNING] No arp\nTrying to request...\n";
            m_arp.queueRequest(original_hdr -> ip_dst, reply, tmp_iface -> name);
            m_arp.periodicCheckArpRequestsAndCacheEntries();
            return;
        }
        sendPacket(reply, tmp_iface -> name);
        
        // Send complete
        std::cerr << "[DEBUG] send ICMP reply sucess.\n";
    }
    
    else {
        // TODO: Forward to the next hop
        if (ip_header -> ip_ttl <= 1) {
            return;
        }
        ip_header -> ip_ttl --;
        Buffer forward(packet);
        ip_hdr* forward_ip_hdr = (ip_hdr *)(forward.data() + sizeof(ethernet_hdr));
        
        // recalculate checksum
        forward_ip_hdr -> ip_sum = 0;
        forward_ip_hdr -> ip_sum = cksum(forward_ip_hdr, sizeof(ip_hdr));
        RoutingTableEntry routing_entry = m_routingTable.lookup(forward_ip_hdr -> ip_dst);
        const Interface* nextHop = findIfaceByName(routing_entry.ifName);
        if (!nextHop) {
            std::cerr << "[ERROR] Cannot find entry in the routing table!\n";
            return;
        }
        
        ethernet_hdr* forward_ether_hdr = (ethernet_hdr *)forward.data();
        forward_ether_hdr -> ether_type = htons(ethertype_ip);
        memcpy(forward_ether_hdr -> ether_shost, nextHop -> addr.data(), ETHER_ADDR_LEN);
        
        if (!m_arp.lookup(routing_entry.gw)) {
            m_arp.queueRequest(ip_header -> ip_dst, forward, nextHop -> name);
            m_arp.periodicCheckArpRequestsAndCacheEntries();
            return;
        }
        auto nexthop_iface = m_arp.lookup(routing_entry.gw);
        
        memcpy(forward_ether_hdr -> ether_dhost, nexthop_iface -> mac.data(), ETHER_ADDR_LEN);
        sendPacket(forward, nextHop -> name);
        std::cerr << "[DEBUG] Forwarded packet to the next hop.\n";
    }
    
    
}
//
//void SimpleRouter::handle_ip(Buffer& mutable_packet, uint8_t* sender_mac, const Interface* iface) {
//    ehternet_hdr* ehter_h = (ethernet_hdr *)mutable_packet.data();
//    ip_hdr* ip_header = (ip_hdr *)(mutable_packet.data() + sizeof(ethernet_hdr));
//
//    // TODO: Verify packet size
//    if (mutable_packet.size() < (sizeof(ethernet_hdr) + sizeof(ip_hdr))) {
//        std::cerr << "[handle_ip] IPv4 packet received, but the size is too small.\n";
//        return;
//    }
//
//    // TODO: Verify checksum
//    uint16_t checksum = ip_header -> ip_sum;
//    // reset to 0 after store the temp checksum value
//    ip_header -> ip_sum = 0;
//
//    if (checksum != cksum(ip_header, sizeof(ip_hdr))) {
//        std::cerr << "[handle_ip] IPv4 packet received, but the checksum value is incorrect.\n";
//        return;
//    }
//
//    /*
//      ##############
//        TODO: NAT!!
//      ##############
//     */
//
//    const Interface* dest = findIfaceByIp(ip_header -> ip_dst);
//
//    if (dest) {
//        // Case (1), packet is destined to this router
//        std::cerr << "[DEBUG] handle_ip: ICMP is detined for this router\n";
//
//        if (ip_header -> ip_p != ip_protocol_icmp) {
//            std::cerr << "[ERROR] handle_ip: Protocol is not icmp.\n";
//            return;
//        }
//        if (!m_arp.lookup(ip_header -> ip_src)) {
//            Buffer src_addr(sender_mac, sender_mac + ETHER_ADDR_LEN);
//            m_arp.insertArpEntry(src_addr, ip_header -> ip_src);
//        }
//        icmp_hdr *icmp_header = (icmp_hdr *)(mutable_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
//        if (icmp_header -> icmp_type != 8) {
//            std::cerr << "[ERROR] hadnle_ip: icmp_type is not 8: " << icmp_header->icmp_type << std::endl;
//            return;
//        }
//        // TODO: send ICMP reply
//
//    }
//    else {
//        std::cerr << "[DEBUG] handle_ip: forwarding...\n";
//        if (ip_header -> ip_ttl <= 1) {
//            std::cerr << "[WARNING] TTL is out of time.\n";
//            return;
//        }
//
//        // TODO: Forward IP packet
//    }
//
//}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
  , m_natTable(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
