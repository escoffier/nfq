FROM ubuntu:22.04

RUN sed -i 's/ports.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list
    # && apt-get update && apt-get -y install libnetfilter-queue-dev clangd \
    # && sudo update-alternatives --install /usr/bin/clangd clangd /usr/bin/clangd-10 100 \
    # && apt-get clean \
    # && rm -rf /var/lib/apt/lists/*