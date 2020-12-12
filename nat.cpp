#include "nat.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THESE METHODS
void
NatTable::checkNatTable()
{
    if (m_natTable.size() == 1 && !(m_natTable.begin()->second->isValid)) {
      m_natTable.clear();
      return;
    }
    for (auto iter = m_natTable.begin(); iter != m_natTable.end(); iter ++) {
        if (!iter -> second -> isValid) {
            m_natTable.erase(iter->first);
            iter --;
        }
    }

}

std::shared_ptr<NatEntry>
NatTable::lookup(uint16_t id)
{
    std::cerr << "[NAT] before NAT lookup\n";
    auto found = m_natTable.find(id);
      if (found == m_natTable.end()) {
          return nullptr;
      }
      std::cerr << "[NAT] after NAT lookup\n";
      return found -> second;
}


void
NatTable::insertNatEntry(uint16_t id, uint32_t in_ip, uint32_t ex_ip)
{
    std::cerr << "[NAT] before insertNatEntry\n";
    auto existed = lookup(id);
    if (!existed) {
        auto tmp_entry = std::make_shared<NatEntry>();
        tmp_entry -> internal_ip = in_ip;
        tmp_entry -> external_ip = ex_ip;
        tmp_entry -> timeUsed = steady_clock::now();
        tmp_entry -> isValid = true;
        m_natTable.insert(std::pair<uint16_t, std::shared_ptr<NatEntry>>(id, tmp_entry));
    }
    else {
        existed -> timeUsed = steady_clock::now();
        return;
    }
    std::cerr << "[NAT] After insertNatEntry\n";
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

NatTable::NatTable(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&NatTable::ticker, this))
{
}

NatTable::~NatTable()
{
  m_shouldStop = true;
  m_tickerThread.join();
}


void
NatTable::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_natTable.clear();
}

void
NatTable::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      std::map<uint16_t, std::shared_ptr<NatEntry>>::iterator entryIt;
      for (entryIt = m_natTable.begin(); entryIt != m_natTable.end(); entryIt++ ) {
        if (entryIt->second->isValid && (now - entryIt->second->timeUsed > SR_ARPCACHE_TO)) {
          entryIt->second->isValid = false;
        }
      }
      checkNatTable();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const NatTable& table)
{
  std::lock_guard<std::mutex> lock(table.m_mutex);

  os << "\nID            Internal IP         External IP             AGE               VALID\n"
     << "-----------------------------------------------------------------------------------\n";

  auto now = steady_clock::now();

  for (auto const& entryIt : table.m_natTable) {
    os << entryIt.first << "            "
       << ipToString(entryIt.second->internal_ip) << "         "
       << ipToString(entryIt.second->external_ip) << "         "
       << std::chrono::duration_cast<seconds>((now - entryIt.second->timeUsed)).count() << " seconds         "
       << entryIt.second->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
