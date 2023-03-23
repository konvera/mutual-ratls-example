# Mutual RATLS Example

This repository contains an example of TLS attestation in [Gramine](https://gramine.readthedocs.io/en/stable/) written in Golang. It utilises the [golang wrapper](https://github.com/konvera/gramine-ratls-golang) for attestation verification.

## Prequisites

**OS:** Ubuntu 20.04, Linux Kernel >= 5.11

**Hardware:** CPU supporting SGX2 (Intel Skylake and newer), +8GB EPC Enclave Memory

## Running the example

This example includes running a simple HTTP server in an **SGX enclave** that listen on `:8443`, exposes a dummy `/hello` endpoint and an HTTP client, in another enclave that expect a response from the server. The connection between the server and client is secured by TLS where the certificates are generated when the enclave is started and is verifed by the receiver using the [Gramine RATLS wrapper](https://github.com/konvera/gramine-ratls-golang/blob/main/gramine_ratls.go#L193) exposed function.

More info about the wrapper and its usage can be found at the [repository](https://github.com/konvera/gramine-ratls-golang).

> **Warning:** Some of the configurations like `RA_TLS_ALLOW_OUTDATED_TCB_INSECURE` used by this example are considered insecure practice in a production SGX environment. It is not advisable to use the default project configuration in production.

### Generating manifest

Run `make` (non-debug) or `make DEBUG=1` (debug) in the [server](./server/) and [client](./client/) directory.

### Building for SGX

Run `make SGX=1` (non-debug) or `make SGX=1 DEBUG=1` (debug) in the directory.

### Enclave size

To change the amount of memory allocated to the enclave to 2 GB, run `make SGX=1 ENCLAVE_SIZE=2G`. Default is 1 GB.

### Run the components

`mrneclave` is required for SGX enclave measurement and should be provided as an enviornment variable for both `server` and `client` when running in SGX. Note that other enclave measurement arguments namely, `mrsigner`, `isv_prod_id`, `isv_svn` can be provided in a similar manner through environemnt variables and will be verified by `RATLSVerifyDer`.

Run server

```bash
cd server
make clean && make SGX=1 DEBUG=1 RA_TYPE=dcap

// pass client's mrenclave measurement
sudo RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1 DEBUG=1 mrenclave=2293a150ecd3e29cbb7f24003683aec2b045929fad0e40b9ba8d563f6ff8237c gramine-sgx server
```

Run client

```bash
cd client
make clean && make SGX=1 DEBUG=1 RA_TYPE=dcap

// pass server's mrenclave measurement
sudo RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1 DEBUG=1 mrenclave=ea8bffa9e38710da7c74451d75400b285c1c7f16d958bf4e6ae822700bdb9ce9 gramine-sgx client
```