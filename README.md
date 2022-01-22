# Lightning In-Memory Object Store
Lightning is a high-performance in-memory object store. Compared to traditional in-memory object stores (e.g., Redis, Memcached, Plasma), Lightning does not have inter-process communication (IPC) overheads on client operations (e.g., object creation, object fetching, object deletion).

Our VLDB 2022 paper (https://danyangzhuo.com/papers/VLDB22-Lightning.pdf) describes the technical details. Please email Danyang Zhuo (danyang@cs.duke.edu) if you have any question.

This is just a research prototype. Please don't use it in production systems.

## Requirement
Lightning runs on the following configuration:
* Linux (4.15.0)
* Clang (6.0.0)
* Boost (1.65.1)
* Z3 (4.8.9)
* Mono (6.8.0)
* Dafny (2.3.0)

## Docker
We suggest you use docker to construct the environment for compiling and running Lightning. We provide a dockerfile to simply this process.

First, you need to build the docker image.
```bash
docker build -t lightning .
```

Second, you need to instantiate a container. You need to enlarge the size of maximum shm the container use to at least 10G.
```bash
docker run -it --rm --shm-size=10g lightning
```

## Build
```bash
mkdir build
cd build
cmake -DVERIFIER=ON ..
make -j
```
If you don't want to build the verifier, you can delete the "-DVERIFIER=ON" flag.

## Run
```bash
./store
```
In another terminal,
```bash
./benchmark
```

## Verify
We verify Lightning's crash fault isolation property in two steps.

### Step #1: Verify the correctness of log implementation
```bash
dafny ../verifier/undo_log.dfy
```

### Step #2: Verify that Lightning's C++ implementation uses the log correctly
```bash
./verifier/verify_num_logwrite
```
This will take around 10-15 minutes.

## Build the Java Client
```bash
mkdir build
cd build
cmake -DJAVA_CLIENT=ON ..
make -j
```

## Build the Python Client
```bash
cd python
make
```
