## Specifications

- OS: Linux x64, MAC OS x64

- Language: C++

- Requires: OpenSSL

- The default elliptic curve is "NID_secp256k1"


## Installation

The current implementation is based on OpenSSL library. See the installment instructions of OpenSSL as below:  

1. Clone the code [openssl-master](https://github.com/openssl/openssl.git)

```
    git clone https://github.com/openssl/openssl.git
```

2. install openssl on your machine

```
    ./config --prefix=/usr/local/ssl shared
    make 
    sudo make install
    export OPENSSL_ROOT_DIR=/usr/local/ssl/
```


## Testing


To compile and test the system, do the following: 

```
  $ cd {PATH}/Escrow-protocol/PGC_openssl/
  $ mkdir build && cd build
  $ cmake ..
  $ make
  $ ./test_escrow_protocol
```

## Our contribution

1. Escrow Protocol https://github.com/MengLing-L/Escrow-protocol/blob/master/PGC_openssl/test/test_escrow_protocol.cpp

2. Sigma Protocol https://github.com/MengLing-L/Escrow-protocol/tree/master/PGC_openssl/depends/sigma

3. Signature Algorithm https://github.com/MengLing-L/Escrow-protocol/tree/master/PGC_openssl/depends/signature



