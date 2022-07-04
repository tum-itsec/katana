FROM ubuntu:bionic
RUN apt-get -y update
RUN apt-get -y install build-essential git gcc-5 libncurses5-dev bison flex libelf-dev vim bc
RUN apt-get -y install gcc-5-plugin-dev g++-5
RUN git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git /linux/
RUN apt-get -y install gcc-4.8 g++-4.8 gcc-4.8-plugin-dev
RUN apt-get -y install gcc-6 g++-6 gcc-6-plugin-dev
RUN apt-get -y install openssl libssl-dev
RUN apt-get -y install cpio dwarves
RUN apt-get -y install python3
RUN mkdir /output
COPY gcc-plugin /gcc-plugin-4.8/
COPY gcc-plugin /gcc-plugin-5/
COPY gcc-plugin /gcc-plugin-6/
RUN cd /gcc-plugin-4.8/ && make clean && make CXX="g++-4.8"
RUN cd /gcc-plugin-5/ && make clean && make CXX="g++-5"
RUN cd /gcc-plugin-6/ && make clean && make CXX="g++-6"
COPY docker-build-kernel.sh /linux/
WORKDIR /linux

ENTRYPOINT ["./docker-build-kernel.sh"]
CMD []
