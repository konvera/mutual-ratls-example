# Mutual RATLS Example

This repository contains an example of TLS attestation in [Gramine](https://gramine.readthedocs.io/en/stable/) written in Golang. It utilises the [golang wrapper](https://github.com/konvera/gramine-ratls-golang) for attestation verification.

## Prequisites

**OS:** Ubuntu 20.04, Linux Kernel >= 5.11

**Hardware:** CPU supporting SGX2 (Intel Skylake and newer), +8GB EPC Enclave Memory

## Running the example

This example includes running a simple HTTP server in an **SGX enclave** that listen on `:8443`, exposes a dummy `/hello` endpoint and an HTTP client, in another enclave that expect a response from the server. The connection between the server and client is secured by TLS where the certificates are generated when the enclave is started and is verifed by the receiver using the [Gramine RATLS wrapper](https://github.com/konvera/gramine-ratls-golang/blob/main/gramine_ratls.go#L193) exposed function.

More info about the wrapper and its usage can be found at the [repository](https://github.com/konvera/gramine-ratls-golang).

> **Note**: Some of the configurations like [`ALLOW_OUTDATED_TCB`](./client/Makefile#18) used by this example are considered insecure practice in a production SGX environment. It is not advisable to use the default project configuration in production.

### Generating manifest

Run `make` (non-debug) or `make DEBUG=1` (debug) in the [server](./server/) and [client](./client/) directory.

### Building for SGX

Run `make SGX=1` (non-debug) or `make SGX=1 DEBUG=1` (debug) in the directory.

### Enclave size

To change the amount of memory allocated to the enclave to 256 GB, run `make SGX=1 ENCLAVE_SIZE=256G`. Default is 8 GB.

### Run the components

Run server

```bash
cd server
sudo gramine-sgx server
```

Run client

```bash
cd client
sudo gramine-sgx client
```
