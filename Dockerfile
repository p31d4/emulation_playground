FROM archlinux:latest

# Dirty fix for the case a proxy is giving you a bad time with certificates
#RUN cd /tmp && curl -k https://archlinux.org/mirrorlist/all/ -o mirrorlist && \
#        sed -i '/https/d' mirrorlist && sed -i 's/^#Ser/Ser/g' mirrorlist && \
#        mv mirrorlist /etc/pacman.d/mirrorlist

RUN echo 'Y' | pacman -Syu

RUN echo "Y" | pacman -Sy vim git rustup python \
        python-unicorn python-capstone python-pyelftools python-pwntools \
        base-devel aarch64-linux-gnu-gcc gdb \
        qemu-user-static

# Dirty hack to avoid the following error when calling ghidra: 
# Exited with error.  Run in foreground (fg) mode for more details.
RUN echo "Y" | pacman -Sy terminator

# Ghidra: this makes the docker image too big
#RUN echo "Y" | pacman -Sy libpng jdk-openjdk ghidra

RUN rm -r /var/cache/pacman/pkg/*

RUN rustup default stable
