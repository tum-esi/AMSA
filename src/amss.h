/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
 * Institution: Technical University of Munich, Germany
 * Department:  Electrical and Computer Engineering 
 * Group:       Embedded Systems and Internet of Things
 * 
 * Project:     Adaptive Merkle Signature Architecture
 * Authors:     Emanuel Regnath (emanuel.regnath@tum.de)
 *
 * Description: The interface for AMSS, the signature scheme in AMSA. 
 *              Include this file to start testing. 
 *  
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


#ifndef _AMSA_H__
#define _AMSA_H__

// system includes (<> searches only include paths)
#include <stdint.h>

// own includes. Should be in same dir or include path (-I)
#include "hash.h"
#include "merkle.h"
#include "wots.h"


// ============================================================================
// public types
// ============================================================================

#define AMSA_SEED_SIZE (CFG_WOTS_SEED_SIZE + CFG_HASH_KEY_SIZE)

typedef struct {
    MT_Config cfg_tree;
    WOTS_Config cfg_wots;
} AMSA_Config;


// amss strcuture. Holds private key data and auxiliary data
typedef struct {
    hash_t secret_key[CFG_WOTS_SEED_SIZE];
    key_s hashkey;
    MT_Tree tree;
    WOTS_Wots wots;
} AMSA_Amss;


typedef struct {
    //uint16_t leaf_idx;
    WOTS_chains_t* wots;
    MT_Path auth_path;
} AMSA_Sig;


typedef struct {
    AMSA_Config config;
    key_s hashkey;
    hash_t* root;
} AMSA_Pubkey;



// some common configs
#define AMSA_SHA256_H4 {{HASH_SHA2_256, 4}, WOTS_SHA2_256_W16}
#define AMSA_SHA256_H10 {{HASH_SHA2_256, 10}, WOTS_SHA2_256_W16}
#define AMSA_SHA256_H12 {{HASH_SHA2_256, 12}, WOTS_SHA2_256_W16}

#define AMSA_BLAKE2B_160_H4  {{HASH_BLAKE2B_160, 4},  WOTS_BLAKE2B_160_W16}
#define AMSA_BLAKE2B_160_H10 {{HASH_BLAKE2B_160, 10}, WOTS_BLAKE2B_160_W16}
#define AMSA_BLAKE2B_160_H12 {{HASH_BLAKE2B_160, 12}, WOTS_BLAKE2B_160_W16}



// ============================================================================
// public functions
// ============================================================================

/*
 * Allocates and initializes memory for the AMSA
 * \return allocated amss structure
 */
AMSA_Amss AMSA_Amss_init(const AMSA_Config config);

/*
 * Allocates and initializes memory for the signature
 * \param[in] config configuration
 * \return allocated signature structure
 */
AMSA_Sig AMSA_Sig_init(const AMSA_Config config);

/*
 * Frees the memory of the AMSA object.
 * \param[in] amss struct holding the private key data
 */
void AMSA_Amss_free(AMSA_Amss* amss);


/*
 * Frees the memory of the signature.
 * \param[in] sig signature struct
 */
void AMSA_Sig_free(AMSA_Sig* sig);


/*
 * Generate AMSA secret key and public key. Will read 48 byte from seed pointer
 * \param[in,out] amss struct holding the private key data
 * \param[in] seed pointer to a 48 byte random data source. 
 * \param[out] pubkey_out generated public key
 */
void AMSA_generate(AMSA_Amss* amss, const byte_t* seed, AMSA_Pubkey* pubkey_out); 


/*
 * Exports a public key from the AMSA object.
 * \param[in,out] amss struct holding the private key data.
 * \param[out] pubkey_out copy of the public key stored in amss
 */
void AMSA_export_pubkey(AMSA_Amss* amss, AMSA_Pubkey* pubkey_out);


/*
 * Sign a message hash digest. 
 * \param[in,out] amss struct holding the private key data
 * \param[in] msg_digest hash of the message that should be signed. check length
 * \param[out] sig_out signature of the message
 */
void AMSA_sign(AMSA_Amss* amss, const hash_t* msg_digest, AMSA_Sig* sig_out);


/*
 * Verify a signature message hash digest. 
 * \param[in] pubkey certificate containing the public key
 * \param[in] msg_digest hash of the message that should be signed. check length
 * \param[in] sig signature of the message
 * \return True if the signature is valid. False otherwise.
 */
bool AMSA_verify(const AMSA_Pubkey* pubkey, const hash_t* msg_digest, const AMSA_Sig* sig);


#endif /* _AMSA_H__  */
