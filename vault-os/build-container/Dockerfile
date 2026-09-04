FROM --platform=linux/amd64 ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    bc bison build-essential ca-certificates ccache curl file flex g++-multilib \
    gcc-multilib git git-lfs gnupg gperf imagemagick lib32readline-dev \
    lib32z1-dev libdw-dev libelf-dev libgnutls28-dev libsdl1.2-dev libssl-dev \
    libxml2 libxml2-utils lz4 lzop openssh-client pngcrush protobuf-compiler \
    python-is-python3 python3-protobuf repo rsync schedtool squashfs-tools \
    unzip xxd xsltproc zip zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Ubuntu 24.04 already reserves uid/gid 1000 for its unprivileged `ubuntu`
# account. Rename it so the persistent volume has stable non-root ownership.
RUN usermod --login builder --home /home/builder --move-home ubuntu \
    && groupmod --new-name builder ubuntu

USER builder
WORKDIR /home/builder/android/lineage
ENV USE_CCACHE=1 \
    CCACHE_EXEC=/usr/bin/ccache \
    CCACHE_DIR=/home/builder/.cache/ccache

CMD ["bash"]
