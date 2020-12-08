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
    }
    else if (ether_type == htons(ethertype_ip)) {
        // TODO: Handle IPv4 Packets
    }
    else {
        std::cerr << "[ERROR] Unknown type of packet, ignored.\n";
        return;
    }
    
    
    
//
//    auto EtherType = ethertype((const uint8_t *)packet.data());
//
//    if (EtherType == ethertype_ip) {
//        // For this IPv4 packet...
//        std::cout << "[NOTE] Checking IPv4...\n";
//        ip_hdr* ip_header = (ip_hdr *)(packet_ptr + ether_size);
//
//        // verify its minimum length
//        if (packet.size() < (ether_size + sizeof(ip_hdr))) {
//            std::cerr << "[ERROR] Packet size is smaller than the minimum size, discarded...\n";
//            return;
//        }
//
//        // verify its checksum
//        uint16_t tmp_cksum = ip_header -> ip_sum;
//        ip_header -> ip_sum = 0;
//        uint16_t new_cksum = cksum(ip_headerm sizeof(ip_hdr));
//
//        if (new_cksum != tmp_cksum) {
//            std::cerr << "[ERROR] Invalid checksum, ignore...\n";
//            return;
//        }
//
//        // Decrement TTL
//        ip_header -> ip_ttl --;
//        if (ip_header -> ip_ttl <= 0) {
//            std::cerr << "[ERROR] Oops, timeout. Packet has exceeded TTL.\n";
//            return;
//        }
//        // Recompute the checksum after TTL decrement.
//        ip_header->ip_sum = cksum(ip_header, sizeof(ip_hdr));
//
//        uint32_t dest = ip_header -> ip_dst;
//        bool is_destined = false;
//        for (auto iter = m_ifaces.begin(); iter != m_ifaces.end(); iter++) {
//            if (it -> ip == dest) {
//                // Found the destinition ip address
//                is_destined = true;
//                break;
//            }
//        }
//
//        if (is_destined) {
//            // case (1), datapacket is for this router, need to check for ICMP payload
//            // Step 1: ICMP?
//            if (ip_header -> ip_p != ip_protocol_icmp) {
//                std::cerr << "[WARNING] Packet is destined to router but not carrying ICMP payload, discarded.\n";
//                return;
//            }
//            if (ip_header -> )
//            ethernet_hdr* ether_header = (ethernet_hdr *)packet_ptr;
//
//        }
//
//        else {
//            // case (2), use the longest prefix match to find a next-hop IP
//            //  and attemp to forward to that address.
//        }
//
//    }
//    else if (EtherType == ethertype_arp) {
//        // This is an ARP packet
//    }
//    else {
//        std::cerr << "[ERROR] Packet's ether type is neitehr IPv4 nor ARP.\n";
//        return;
//    }
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
        output_a_hdr -> arp_sip = iface -> ip;
        output_a_hdr -> arp_tip = arp_header -> arp_sip;
        memcpy(output_a_hdr -> arp_tha, arp_header -> arp_sha, ETHER_ADDR_LEN);
        memcpy(output_a_hdr -> arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
        
        sendPacket(outputBuffer, iface->name);
    }
    
    else if (ARP_OP == arp_op_reply) {
        std::cout << "[DEBUG] Handling arp_op_reply...\n";
        
    }
    
    else {
        std::cerr << "[handle_arp] Unknown ARP type. Ignored\n";
    }

    return;
}
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
