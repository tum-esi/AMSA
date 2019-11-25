/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
 * Institution: Technical University of Munich, Germany
 * Department:  Electrical and Computer Engineering 
 * Group:       Embedded Systems and Internet of Things
 * 
 * Project:     Hash-based Signature
 * Authors:     Emanuel Regnath (emanuel.regnath@tum.de)
 *
 * Description: Command line interface, which provides functions to 
 *              display internal data structures in a nice way on
 *              the command line.
 * 
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef _CLI_H_
#define _CLI_H_

#include "../wots.h"
#include "../merkle.h"
#include "../amss.h"


// print functions. Will directly printf to stdout.
void CLI_print_hashname(const HASH_Config config);

void CLI_print_wots_config(const WOTS_Config config);

void CLI_print_wots_params(const WOTS_Wots* wots);

void CLI_print_wots_sig(const WOTS_Wots* wots, const WOTS_chains_t* sig);

void CLI_print_merkle(const MT_Tree* tree);

void CLI_print_amss(const AMSA_Amss* amss);

void CLI_print_pubkey(const AMSA_Pubkey* pubkey);




// convert hash to a hex string representation
const char* CLI_hexstr(const unsigned char *hash);


#endif // _CLI_H_
