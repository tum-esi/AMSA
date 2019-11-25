/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
 * Institution: Technical University of Munich, Germany
 * Department:  Electrical and Computer Engineering 
 * Group:       Embedded Systems and Internet of Things
 * 
 * Project:     Hash-based Signature
 * Authors:     Emanuel Regnath (emanuel.regnath@tum.de)
 *
 * Description: The Winternitz One Time Signature
 * 
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef AMSS_WOTS_H_
#define AMSS_WOTS_H_

// system includes
#include <stdint.h>

// own includes
#include "hash.h"


// ============================================================================
// public defines
// ============================================================================

#ifndef CFG_WOTS_SEED_SIZE
#define CFG_WOTS_SEED_SIZE 32
#endif


// ============================================================================
// public types
// ============================================================================

typedef struct {
    HASH_Config cfg_hash;
    uint16_t code_base;
} WOTS_Config;


typedef struct {
    uint8_t seed[CFG_WOTS_SEED_SIZE];   // private key => make it a pointer?
    WOTS_Config config;
    uint8_t num_chains;
    uint8_t csum_base;
    uint8_t has_seckey;
    uint8_t has_pubkey;
    uint8_t code_digits;  // deprecated?
    uint8_t csum_digits;  // deprecated
    key_s hashkey;   // security key
    hash_t* root;   // public key
    //hash_t* chains;   // chains expanded
} WOTS_Wots;


typedef unsigned char WOTS_chains_t;


// configs
extern const WOTS_Config WOTS_SHA2_256_W4      ;
extern const WOTS_Config WOTS_SHA2_256_W16     ;
extern const WOTS_Config WOTS_SHA2_256_W256    ;

extern const WOTS_Config WOTS_BLAKE2B_128_W4   ;
extern const WOTS_Config WOTS_BLAKE2B_128_W16  ;
extern const WOTS_Config WOTS_BLAKE2B_128_W256 ;

extern const WOTS_Config WOTS_BLAKE2B_160_W4   ;
extern const WOTS_Config WOTS_BLAKE2B_160_W16  ;
extern const WOTS_Config WOTS_BLAKE2B_160_W32  ;
extern const WOTS_Config WOTS_BLAKE2B_160_W256 ;

extern const WOTS_Config WOTS_BLAKE2B_256_W4   ;
extern const WOTS_Config WOTS_BLAKE2B_256_W16  ;


// ============================================================================
// public functions
// ============================================================================


// returns the number of hash chains
unsigned WOTS_num_chains(const WOTS_Config* config);


/**
 * Allocates and initializes the WOTS data structure.
 */
WOTS_Wots WOTS_init(const WOTS_Config* config);


/**
 * Frees allocated memory of the WOTS data structure.
 */
void WOTS_free(WOTS_Wots* wots);



/**
 * WOTS key generation. Takes a 32 byte seed for the private key, expands it to
 * a full WOTS private key and computes the corresponding public key.
 * It requires the seed and the hashkey of this WOTS key pair.
 */
void WOTS_generate_pubkey(WOTS_Wots* wots);



/**
 * WOTS preparation. Takes a 32 byte seed for the private key, expands it to
 * a full WOTS private key ready for signing.
 * It requires the seed and the hashkey of this WOTS key pair.
 */
void WOTS_import_seckey(WOTS_Wots* wots, const hash_t* seckey, const key_s hashkey);



/**
 * Import WOTS public key for verification.
 */
void WOTS_import_pubkey(WOTS_Wots* wots, const hash_t* pubkey, const key_s hashkey);


/**
 * Takes a n-byte message digest and the wots to compute a
 * signature that is writen to sig_out.
 */
void WOTS_sign(const WOTS_Wots* wots, const hash_t* msg, WOTS_chains_t* sig_out);



/**
 * Verifies a WOTS. Takes a WOTS struct created from a public key, an n-byte message digest, and the WOTS chains of a signature. 
 * Verifies that the signature encodes the message digest and that the signature corresponds to the root in wots.
 * \return True if signature is valid else False
 */
bool WOTS_verify(const WOTS_Wots* wots, const hash_t* msg, const WOTS_chains_t* sig);


/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS root hash (public key).
 */
void WOTS_root_from_sig(const WOTS_Wots* wots, const hash_t* msg, const WOTS_chains_t* sig, hash_t* root_out);



#endif
