#include "packet.hh"
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <ostream>
#include <unistd.h>
#include <cstring>
extern "C" {
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <linux/netfilter/nfnetlink_queue.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
}
#define DEBUG_ERROR(level, format, args...) (std::cout << format);

int dp_nfq_rx_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                 struct nfq_data *nfa, void *data) {
  uint32_t id;
  uint16_t protocol;
  nfqnl_msg_packet_hdr *ph;
  ph = nfq_get_msg_packet_hdr(nfa);
  if (ph) {
    id = ntohl(ph->packet_id);
    protocol = ntohl(ph->hw_protocol);
    std::cout << "received packet: id " << id << "protocol " << protocol
              << std::endl;
    // DEBUG_PACKET("hw_protocol=0x%04x hook=%u id=%u, dp ctx:%s\n",
    // ntohs(ph->hw_protocol), ph->hook, id, ctx->name);
  }

  char *pktdata;
  auto ret = nfq_get_payload(nfa, reinterpret_cast<unsigned char **>(&pktdata));
  if (ret > 0) {
    seastar::net::packet p(pktdata, ret);
    p.get_header<iphdr>(0);
    iphdr *iph = (iphdr *)pktdata;
    unsigned ip_len = ntohs(iph->tot_len);
    struct in_addr tmp_in_addr;
    
    char addr_str[16];
   
   
    tmp_in_addr.s_addr = iph->saddr;
    strcpy(addr_str, inet_ntoa(tmp_in_addr));
    std::string s_addr(addr_str);
    tmp_in_addr.s_addr = iph->daddr;
    strcpy(addr_str, inet_ntoa(tmp_in_addr));
    std::string d_addr(addr_str);

    std::cout<< "source addr: " << s_addr << "  dest: "<<d_addr<<std::endl;
    // Trim IP header 
    unsigned ip_hdr_len = iph->ihl * 4;
    p.trim_front(ip_hdr_len);
    if (iph->protocol == IPPROTO_TCP) {
      auto h = p.get_header(0, 20);
      tcphdr *th = (tcphdr*)h;
      // tcphdr *th = (struct tcphdr *)(pktdata + iph->ihl *4);
      unsigned th_len = th->doff * 4;
      std::cout<< "source: " << ntohs(th->source) << "  dest: "<<ntohs(th->dest)<<std::endl;
    }
  }
  nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
  return 0;
}

static int enter_netns(const char *netns) {
  int curfd, netfd;

  if ((curfd = open("/proc/self/ns/net", O_RDONLY)) == -1) {
    DEBUG_ERROR(DBG_CTRL, "failed to open current network namespace\n");
    return -1;
  }
  if ((netfd = open(netns, O_RDONLY)) == -1) {
    std::cout<< "failed to open network namespace: netns=" << netns <<std::endl;
    close(curfd);
    return -1;
  }
  if (setns(netfd, CLONE_NEWNET) == -1) {
    DEBUG_ERROR(DBG_CTRL,
                "failed to enter network namespace: netns=%s error=%s\n", netns,
                strerror(errno));
    close(netfd);
    close(curfd);
    return -1;
  }
  close(netfd);
  return curfd;
}

static int restore_netns(int fd) {
  if (setns(fd, CLONE_NEWNET) == -1) {
    DEBUG_ERROR(DBG_CTRL, "failed to restore network namespace: error=%s\n",
                strerror(errno));
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
}

int main(int argc, char **argv) {
  uint32_t nfq_queue_num = 100;
  struct nfq_handle *nfq_hdl;
  struct nfq_q_handle *nfq_q_hdl;
  int fd;
  int err;
  int curns_fd;
  if ((curns_fd = enter_netns("/proc/2477008/ns/net")) < 0) {
    return -1;
  }
  nfq_hdl = nfq_open();
  if (!nfq_hdl) {
    DEBUG_ERROR(DBG_CTRL, "fail to open nfq_hdl\n");
    return -1;
  }

  if (nfq_bind_pf(nfq_hdl, AF_INET) < 0) {
    DEBUG_ERROR(DBG_CTRL, "error during nfq_bind_pf()\n");
    return -1;
  }

  std::cout << "binding this socket to queue(%d)" << nfq_queue_num << std::endl;

  nfq_q_hdl = nfq_create_queue(nfq_hdl, nfq_queue_num, &dp_nfq_rx_cb, NULL);
  if (!nfq_q_hdl) {
    DEBUG_ERROR(DBG_CTRL, "error during nfq_create_queue()\n");
    return -1;
  }

  std::cout << ("setting nfq copy_packet mode\n");
  if (nfq_set_mode(nfq_q_hdl, NFQNL_COPY_PACKET, 0xffff) < 0) {
    DEBUG_ERROR(DBG_CTRL, "can't set packet_copy mode\n");
    return -1;
  }

  // NFQA_CFG_F_FAIL_OPEN (requires Linux kernel >= 3.6): the kernel will
  // accept the packets if the kernel queue gets full. If this flag is not
  // set, the default action in this case is to drop packets.
  std::cout << ("setting flags to fail open\n");
  if (nfq_set_queue_flags(nfq_q_hdl, NFQA_CFG_F_FAIL_OPEN,
                          NFQA_CFG_F_FAIL_OPEN)) {
    DEBUG_ERROR(DBG_CTRL,
                "This kernel version does not allow to set fail oepn.\n");
    // return -1;
  }
  // NFQA_CFG_F_GSO (requires Linux kernel >= 3.10): the kernel will
  // not normalize offload packets, i.e. your application will need to
  // be able to handle packets larger than the mtu.
  // Normalization is expensive, so this flag should always be set.
  std::cout << ("setting flags to gso\n");
  if (nfq_set_queue_flags(nfq_q_hdl, NFQA_CFG_F_GSO, NFQA_CFG_F_GSO)) {
    DEBUG_ERROR(DBG_CTRL, "This kernel version does not allow to set gso.\n");
    // return -1;
  }

  /*DEBUG_CTRL("setting flags to request UID and GID\n");
      if (nfq_set_queue_flags(nfq_q_hdl, NFQA_CFG_F_UID_GID,
  NFQA_CFG_F_UID_GID)) { DEBUG_ERROR(DBG_CTRL, "This kernel version does not
  allow to retrieve process UID/GID.\n");
      //return -1;
      }

  DEBUG_CTRL("setting flags to request security context\n");
      if (nfq_set_queue_flags(nfq_q_hdl, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX))
  { DEBUG_ERROR(DBG_CTRL, "This kernel version does not allow to retrieve
  security context.\n");
      //return -1;
      }*/
  fd = nfq_fd(nfq_hdl);
  if (fd < 0) {
    // DEBUG_CTRL("fd(%d), dp ctx(%p)\n", fd, ctx);
    return -1;
  }
  restore_netns(curns_fd);
  char buf[4096];
  int rv;
  while (1) {
    if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
      nfq_handle_packet(nfq_hdl, buf, rv);
    }
  }
  while (1) {
    sleep(1000);
  }
}