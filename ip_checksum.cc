/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * Copyright (C) 2014 Cloudius Systems, Ltd.
 */

#include "ip_checksum.hh"
#include <arpa/inet.h>

namespace seastar {

namespace net {

inline uint64_t ntohq(uint64_t v) {
#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    // big endian, nothing to do
    return v;
#else
    // little endian, reverse bytes
    return __builtin_bswap64(v);
#endif
}

void checksummer::sum(const char* data, size_t len) {
    auto orig_len = len;
    if (odd) {
        csum += uint8_t(*data++);
        --len;
    }
    auto p64 = reinterpret_cast<const packed<uint64_t>*>(data);
    while (len >= 8) {
        csum += ntohq(*p64++);
        len -= 8;
    }
    auto p16 = reinterpret_cast<const packed<uint16_t>*>(p64);
    while (len >= 2) {
        csum += ntohs(*p16++);
        len -= 2;
    }
    auto p8 = reinterpret_cast<const uint8_t*>(p16);
    if (len) {
        csum += *p8++ << 8;
        len -= 1;
    }
    odd ^= orig_len & 1;
}

uint16_t checksummer::get() const {
    __int128 csum1 = (csum & 0xffff'ffff'ffff'ffff) + (csum >> 64);
    uint64_t csum = (csum1 & 0xffff'ffff'ffff'ffff) + (csum1 >> 64);
    csum = (csum & 0xffff) + ((csum >> 16) & 0xffff) + ((csum >> 32) & 0xffff) + (csum >> 48);
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return htons(~csum);
}

void checksummer::sum(const packet& p) {
    for (auto&& f : p.fragments()) {
        sum(f.base, f.size);
    }
}

uint16_t ip_checksum(const void* data, size_t len) {
    checksummer cksum;
    cksum.sum(reinterpret_cast<const char*>(data), len);
    return cksum.get();
}


}

}
