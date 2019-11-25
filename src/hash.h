/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
 * Institution: Technical University of Munich, Germany
 * Department:  Electrical and Computer Engineering 
 * Group:       Embedded Systems and Internet of Things
 * 
 * Project:     Hash-based Signature
 * Authors:     Emanuel Regnath (emanuel.regnath@tum.de)
 *
 * Description: Interface for cryptographic hash functions.
 * 
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


#ifndef HASH_H_
#define HASH_H_

// system includes
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>



// ============================================================================
// public defines
// ============================================================================

#ifndef CFG_HASH_KEY_SIZE
#define CFG_HASH_KEY_SIZE 16
#endif

#ifndef CFG_HASH_PROFILING
#define CFG_HASH_PROFILING 1  // 1: profiling (performance statistics)  0: no profiling
#endif


// ============================================================================
// public types
// ============================================================================

/*
 * Hash algorithms
 */
typedef enum {
    HASH_SHA2,
    HASH_SHA3,
    HASH_SHAKE128,
    HASH_SHAKE256,
    HASH_BLAKE2B,
} HASH_Algo_t;


/*
 * Hash configs. This can be compressed to 1 byte.
 */
typedef struct {
    HASH_Algo_t algo;
    uint8_t size;
} HASH_Config;


typedef unsigned char byte_t;  // general length

typedef unsigned char hash_t;  // blocks of hash_size bytes


typedef struct {
    unsigned char bytes[CFG_HASH_KEY_SIZE];
} key_s;



// ============================================================================
// public constants
// ============================================================================

extern const HASH_Config HASH_SHA2_256;    
extern const HASH_Config HASH_SHAKE_128;
extern const HASH_Config HASH_SHAKE_256;
extern const HASH_Config HASH_BLAKE2B_128; 
extern const HASH_Config HASH_BLAKE2B_160; 
extern const HASH_Config HASH_BLAKE2B_192; 
extern const HASH_Config HASH_BLAKE2B_224; 
extern const HASH_Config HASH_BLAKE2B_256; 



// ============================================================================
// public functions
// ============================================================================

/* Sets the global hash algorithm and its parameters.
 * \param[in] config struct that specifies algorithm and size of the hash
 */
void HASH_config(const HASH_Config config);

/**
 * Allocates and initializes a byte array suitable to store a hash value. 
 * \param[in] config struct that specifies algorithm and size of the hash
 * \return pointer to the byte array
 */
hash_t* HASH_init(const HASH_Config config);

/**
 * Calculates the hash value of an arbitrary input without a key.
 * \param[out] output pointer to the memory where the hash will be stored
 * \param[in] input pointer to the input
 * \param[in] input_length size of the input in bytes
 */
void HASH_hash(hash_t *output, const byte_t *input, size_t input_length);

/**
 * Calculates the hash value of an arbitrary input WITH a key.
 * \param[out] output pointer to the memory where the hash will be stored
 * \param[in] input pointer to the input
 * \param[in] input_length size of the input in bytes
 * \param[in] key key that will modify the output of the hash function
 */
void HASH_keyhash(hash_t *output, const byte_t *input, size_t input_length, const key_s* key);



/* helpers */
const char* HASH_hexstr(const byte_t *hash); // for printing a hash
void HASH_print_stats(); // benchmark
void HASH_reset_stats();

#endif /* HASH_H_  */
