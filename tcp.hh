

#include <cstdint>
#include <unordered_map>

struct connection_id {
  uint32_t source_ip;
  uint32_t dest_ip;
  uint16_t source_port;
  uint16_t dest_port;

  bool operator()(const connection_id &x) const {
    return source_ip == x.source_ip && dest_ip == x.dest_ip &&
           source_port == x.source_port && dest_port == x.dest_port;
  }
};

class tcb {
public:
  tcb();
  ~tcb();

  private:
  std::unordered_map<connection_id, typename Tp> tcbs_;
};