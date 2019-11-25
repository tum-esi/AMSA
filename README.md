

# Adaptive Merkle Signature Architecture (AMSA)

This repository provides the code for the hash-based signature (HBS) described in the paper:

E. Regnath, S. Steinhorst: “AMSA: Adaptive Merkle Signature Architecture”, 2020



## Getting Started

**Compile binary** with gcc using the `Makefile`
```
git clone git@github.com:tum-esi/AMSA.git
cd AMSA
make
```

**Run a test** by calling `bin/test_amsa`

Expected output:
```
.:: Testing AMSA
=====================================================
Signing the average hash 0x8888888.... 
 => gen:    HASH_PROFILE: Calls: 1115135,  Processed: 37846976 B
 => sign:   HASH_PROFILE: Calls: 1695,  Processed: 56320 B
 => verify: HASH_PROFILE: Calls: 521,  Processed: 19072 B

AMSA: sizes: pk=50 B, sk=48 B, sig=(2112+320)= 2432 B, aux=5703 B
 +TREE=(n=32B, h=10)
 +WOTS=(n=32B, l1=64, w1=16, l2=2, w2=31)
```

Further tests include `test_merkle`, `test_wots`, `test_hash`.



### Use as a library
```c
#include "amss.h"

// allocate data structures
AMSA_Config cfg  = AMSA_SHA256_H10;        // select config
AMSA_Amss   amss = AMSA_Amss_init( cfg );  // alloc amsa
byte_t seed[CFG_AMSA_SEED_SIZE] = { 'x' }; // seed (replace!)
AMSA_Pubkey pubkey;                        // public key
AMSA_Sig    sig  = AMSA_Sig_init( cfg );   // init signature

// generate
AMSA_generate( &amss, seed, &pubkey );

// sign
AMSA_sign( &amss, msg_digest, sig );

// verify
bool succ = AMSA_verify( &pubkey, msg_digest, sig );
```


**Configuration** is done by editing `config.h`.




## Implementation

### Security
This is not a secure implementation! This implementation is only intended to explore several time/memory trade-offs. Security issues include

* the private key is stored in plaintext in the RAM
* the seed needs to come from a real random source
* implementation might not be resistant to side-channel attacks


### Performance
* LOG_x and PROFILER_x will not be compiled when they are disabled in `config.h`
* Optimization parameters for the compiler are specified in the `Makefile`



### Future Work
* key management on filesystem with import/export
* determine best height of subtrees according to available memory
* proper encoding of typecode (`AMSA_Config`)






## Related Work
Two related hash-based signature schemes are XMSS and LMS.

* A. Huelsing, D. Butin, S. Gazdag, J. Rijneveld, and A. Mohaisen: [“XMSS: eXtended Merkle Signature Scheme”](https://tools.ietf.org/html/rfc8391), IRTF, RFC 8391, 2018
* D. McGrew, M. Curcio, and S. Fluhrer, [“Leighton-Micali Hash-Based Signatures”](https://tools.ietf.org/html/rfc8554), IRTF, RFC 8554, 4 2019.




