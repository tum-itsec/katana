#CXX = g++-4.8
CXX ?= g++
# Flags for the C++ compiler: enable C++11 and all the warnings, -fno-rtti is required for GCC plugins
CXXFLAGS = -std=c++11 -Wall -fno-rtti 
# Workaround for an issue of -std=c++11 and the current GCC headers
CXXFLAGS += -Wno-literal-suffix

# Determine the plugin-dir and add it to the flags
PLUGINDIR=$(shell $(CXX) -print-file-name=plugin)
CXXFLAGS += -I$(PLUGINDIR)/include -g

# top level goal: build our plugin as a shared library
all: flowana.so const_structs.so

.PHONY: clean test
clean: 
	rm -f const_structs.so const_structs.o flow_analysis.so flow_analysis.o flowana.so flowana.o

const_structs.so: const_structs.o
	$(CXX) $(LDFLAGS) -shared -o $@ $<

const_structs.o: const_structs.c
	$(CXX) $(CXXFLAGS) -fPIC -c -o $@ $<

flowana.so: flowana.o
	$(CXX) $(LDFLAGS) -shared -o $@ $<

flowana.o : flowana.cc
	$(CXX) $(CXXFLAGS) -fPIC -c -o $@ $<

test:
	$(CC) -fplugin=./flowana.so flow_test.c
