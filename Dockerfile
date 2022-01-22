FROM ubuntu:20.04
COPY . /lightning
RUN apt update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake clang-6.0 llvm-9-dev wget unzip python3-dev libz3-dev libelf-dev libboost-dev gdb vim tmux

WORKDIR /tmp
RUN wget https://github.com/dafny-lang/dafny/releases/download/v3.3.0/dafny-3.3.0-x64-ubuntu-16.04.zip
RUN unzip dafny-3.3.0-x64-ubuntu-16.04.zip

WORKDIR /lightning
CMD bash
