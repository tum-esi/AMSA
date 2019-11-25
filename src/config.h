/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
 * Institution: Technical University of Munich, Germany
 * Department:  Electrical and Computer Engineering 
 * Group:       Embedded Systems and Internet of Things
 * 
 * Project:     Adaptive Merkle Signature Architecture
 * Authors:     Emanuel Regnath (emanuel.regnath@tum.de)
 *
 * Description: Main configuration file. Include this file before amss.h
 *              If you do not include this file, default values will be
 *              used.
 *   
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


#ifndef AMSA_CONFIG_H_
#define AMSA_CONFIG_H_

// profiler.h
#define CFG_PROFILER_ENABLED 1 // 1: enabled, 0: disable profiling and remove any function calls

// logger.h
#define CFG_LOG_ENABLED 1      // 1: enabled, 0: disable logging and remove any function calls 

// hash.h
#define CFG_HASH_KEY_SIZE 16   // size of the hash key in bytes. Corresponds to the security string.
#define CFG_HASH_PROFILING 1   // 1: profiling (performance statistics)  0: no profiling

// sha256.h
#define CFG_SHA256_USE_OPENSSL 0  // 1: use openssl 0: use c implementation

// wots.h
#define CFG_WOTS_SEED_SIZE 32  // size of the seed in bytes. Corresponds to AMSA secret key.

#endif
