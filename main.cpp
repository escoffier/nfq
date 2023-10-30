#include "packet.hh"
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <ostream>
#include <string>
#include <unistd.h>
#include <unordered_map>
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

/* This piece of code has been used many times in a lot of differents tools. */
/* I haven't been able to determine the author of the code but it looks like */
/* this is a public domain implementation of the checksum algorithm */
unsigned short in_cksum(unsigned short *addr, int len) {

  int sum = 0;
  u_short answer = 0;
  u_short *w = addr;
  int nleft = len;

  /*
   * Our algorithm is simple, using a 32-bit accumulator (sum),
   * we add sequential 16-bit words to it, and at the end, fold back
   * all the carry bits from the top 16 bits into the lower 16 bits.
   */

  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(u_char *)(&answer) = *(u_char *)w;
    sum += answer;
  }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
  sum += (sum >> 16);                 /* add carry */
  answer = ~sum;                      /* truncate to 16 bits */
  return (answer);

} /* End of in_cksum() */

/* Pseudoheader (Used to compute TCP checksum. Check RFC 793) */
typedef struct pseudoheader {
  u_int32_t src;
  u_int32_t dst;
  u_char zero;
  u_char protocol;
  u_int16_t tcplen;
} tcp_phdr_t;

int send_rst(u_int32_t seq, u_int32_t src_ip, u_int32_t dest_ip,
             u_int16_t src_prt, u_int16_t dst_prt) {
  seastar::net::packet p;
  auto pth = p.prepend_uninitialized_header(sizeof(tcphdr));

  static int i = 0;
  int one =
      1; /* R.Stevens says we need this variable for the setsockopt call */

  /* Raw socket file descriptor */
  int rawsocket = 0;

  /* Buffer for the TCP/IP SYN Packets */
  char packet[sizeof(struct tcphdr) + sizeof(struct ip) + 1];

  /* It will point to start of the packet buffer */
  struct ip *ipheader = (struct ip *)packet;

  /* It will point to the end of the IP header in packet buffer */
  struct tcphdr *tcpheader = (struct tcphdr *)(packet + sizeof(struct ip));

  /* TPC Pseudoheader (used in checksum)    */
  tcp_phdr_t pseudohdr;

  /* TCP Pseudoheader + TCP actual header used for computing the checksum */
  char tcpcsumblock[sizeof(tcp_phdr_t) + 20];

  /* Although we are creating our own IP packet with the destination address */
  /* on it, the sendto() system call requires the sockaddr_in structure */
  struct sockaddr_in dstaddr;

  memset(&pseudohdr, 0, sizeof(tcp_phdr_t));
  memset(&packet, 0, sizeof(packet));
  memset(&dstaddr, 0, sizeof(dstaddr));

  dstaddr.sin_family = AF_INET; /* Address family: Internet protocols */
  // dstaddr.sin_port = dst_prt;       /* Leave it empty */
  dstaddr.sin_addr.s_addr = dest_ip; /* Destination IP */

  /* Get a raw socket to send TCP packets */
  if ((rawsocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
    perror("TCP_RST_send():socket()");
    exit(1);
  }

  /* We need to tell the kernel that we'll be adding our own IP header */
  /* Otherwise the kernel will create its own. The ugly "one" variable */
  /* is a bit obscure but R.Stevens says we have to do it this way ;-) */
  if (setsockopt(rawsocket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
    perror("TCP_RST_send():setsockopt()");
    exit(1);
  }

  /* IP Header */
  ipheader->ip_hl = 5;  /* Header lenght in octects                       */
  ipheader->ip_v = 4;   /* Ip protocol version (IPv4)                     */
  ipheader->ip_tos = 0; /* Type of Service (Usually zero)                 */
  ipheader->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
  ipheader->ip_off = 0;  /* Fragment offset. We'll not use this            */
  ipheader->ip_ttl = 64; /* Time to live: 64 in Linux, 128 in Windows...   */
  ipheader->ip_p = 6;    /* Transport layer prot. TCP=6, UDP=17, ICMP=1... */
  ipheader->ip_sum = 0;  /* Checksum. It has to be zero for the moment     */
  ipheader->ip_id = htons(1337);
  ipheader->ip_src.s_addr = src_ip;  /* Source IP address                    */
  ipheader->ip_dst.s_addr = dest_ip; /* Destination IP address               */

  /* TCP Header */
  tcpheader->th_seq = seq;      /* Sequence Number                         */
  tcpheader->th_ack = htonl(1); /* Acknowledgement Number                  */
  tcpheader->th_x2 = 0;         /* Variable in 4 byte blocks. (Deprecated) */
  tcpheader->th_off = 5;        /* Segment offset (Lenght of the header)   */
  tcpheader->th_flags = TH_RST; /* TCP Flags. We set the Reset Flag        */
  tcpheader->th_win = htons(4500) + rand() % 1000; /* Window size */
  tcpheader->th_urp = 0;         /* Urgent pointer.                         */
  tcpheader->th_sport = src_prt; /* Source Port                             */
  tcpheader->th_dport = dst_prt; /* Destination Port                        */
  tcpheader->th_sum = 0;         /* Checksum. (Zero until computed)         */

  /* Fill the pseudoheader so we can compute the TCP checksum*/
  pseudohdr.src = ipheader->ip_src.s_addr;
  pseudohdr.dst = ipheader->ip_dst.s_addr;
  pseudohdr.zero = 0;
  pseudohdr.protocol = ipheader->ip_p;
  pseudohdr.tcplen = htons(sizeof(struct tcphdr));

  /* Copy header and pseudoheader to a buffer to compute the checksum */
  memcpy(tcpcsumblock, &pseudohdr, sizeof(tcp_phdr_t));
  memcpy(tcpcsumblock + sizeof(tcp_phdr_t), tcpheader, sizeof(struct tcphdr));

  /* Compute the TCP checksum as the standard says (RFC 793) */
  tcpheader->th_sum =
      in_cksum((unsigned short *)(tcpcsumblock), sizeof(tcpcsumblock));

  /* Compute the IP checksum as the standard says (RFC 791) */
  ipheader->ip_sum = in_cksum((unsigned short *)ipheader, sizeof(struct ip));

  /* Send it through the raw socket */
  if (sendto(rawsocket, packet, ntohs(ipheader->ip_len), 0,
             (struct sockaddr *)&dstaddr, sizeof(dstaddr)) < 0) {
    return -1;
  }

  printf("Sent RST Packet:\n");
  printf("   SRC: %s:%d\n", inet_ntoa(ipheader->ip_src),
         ntohs(tcpheader->th_sport));
  printf("   DST: %s:%d\n", inet_ntoa(ipheader->ip_dst),
         ntohs(tcpheader->th_dport));
  printf("   Seq=%u\n", ntohl(tcpheader->th_seq));
  printf("   Ack=%d\n", ntohl(tcpheader->th_ack));
  printf("   TCPsum: %02x\n", tcpheader->th_sum);
  printf("   IPsum: %02x\n", ipheader->ip_sum);

  close(rawsocket);

  return 0;
  return 0;
}
// std::unordered_map<typename Key, typename Tp>
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
  auto len = nfq_get_payload(nfa, reinterpret_cast<unsigned char **>(&pktdata));
  if (len > 0) {
    std::cout << "len: " << std::endl;
    seastar::net::packet p(pktdata, len);
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

    std::cout << "source addr: " << s_addr << "  dest: " << d_addr << std::endl;
    // Trim IP header
    unsigned ip_hdr_len = iph->ihl * 4;
    p.trim_front(ip_hdr_len);
    if (iph->protocol == IPPROTO_TCP) {

      // struct in_addr addr;
      // inet_aton(blocked_ip.c_str(), &addr);

      auto h = p.get_header(0, 20);
      tcphdr *th = (tcphdr *)h;
      // tcphdr *th = (struct tcphdr *)(pktdata + iph->ihl *4);
      unsigned th_len = th->doff * 4;
      if (p.len() > th_len) {
        p.trim_front(th_len);
        std::string playload(p.get_header(0, p.len()), p.len());
        std::cout << "playload: " << playload << std::endl;
        std::cout << "playload length: " << p.len() << std::endl;
        std::string blocked_ip{"172.17.0.4"};
        if (d_addr == blocked_ip) {
          send_rst(th->th_ack, iph->daddr, iph->saddr, th->th_dport, th->th_sport);
          send_rst(htonl(ntohl(th->th_seq)+1), iph->saddr, iph->daddr, th->th_sport, th->th_dport);

        }
      }

      std::cout << "source: " << ntohs(th->source)
                << "  dest: " << ntohs(th->dest) << std::endl;
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
    std::cout << "failed to open network namespace: netns=" << netns
              << std::endl;
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

  char *ns = argv[1];
  std::string ns_path{"/proc/"};
  ns_path += ns;
  ns_path += "/ns/net";
  std::cout << "ns path: " << ns_path << std::endl;
  if ((curns_fd = enter_netns(ns_path.c_str())) < 0) {
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