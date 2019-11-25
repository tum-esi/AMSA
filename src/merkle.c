/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
 * Institution: Technical University of Munich, Germany
 * Department:  Electrical and Computer Engineering 
 * Chair:       Embedded Systems and Internet of Things
 * 
 * Project:     Hash-based Signature
 * Authors:     Emanuel Regnath (emanuel.regnath@tum.de)
 *
 * Description: Models a Merkle Tree
 * 
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


#include <stdio.h>
#include <stdlib.h>  // for malloc

#include "merkle.h"
#include "util/logger.h"


// ============================================================================
// private functions
// ============================================================================



// returns ceil( log_2(leaf_idx) )
// leaf_idx → height
//        0 → 0
//        1 → 1
//        2 → 2
//        3 → 3
//        4 → 3
//        5 → 4
int cur_height(const MT_Subtree* tree){
	int leaf_count = tree->leaf_idx;
	if (leaf_count < 1) return 0;
	int h = 1;
	while(leaf_count > 1){
		h++;
		leaf_count = (leaf_count+1) / 2;
	}
	return h;
}


// todo: adjust hashkey
void hash_two(const hash_t* left_in, const hash_t* right_in, hash_t* output, size_t size_hash){
	unsigned char input[size_hash*2];
	memcpy(input, left_in, size_hash);
	memcpy(input+size_hash, right_in, size_hash);
	HASH_keyhash(output, input, size_hash*2, 0);
	LOG_trace("hash_two: h_l=%.8s + h_r=%.8s => %.8s", HASH_hexstr( (hash_t*)input ), HASH_hexstr( (hash_t*)(input+size_hash) ), HASH_hexstr(output) );
}


// this time, all rights
int num_rights(const int height){
	return (1 << height) -1;
}



MT_Subtree init_subtree(MT_Tree *tree, uint8_t height){
	uint8_t size_hash = tree->config.cfg_hash.size;
	unsigned int num_hashes = 1+height+num_rights(height);
	LOG_debug("num_hashes: %d, height: %d", num_hashes, height);
	MT_Subtree subtree;

	subtree.cfg_hash = tree->config.cfg_hash;
	subtree.height = height;
	subtree.leaf_idx = 0;
	subtree.is_full = false;
	subtree.root = malloc(num_hashes*size_hash);
	if (subtree.root == NULL) LOG_error("Allocation error!");
	subtree.left_nodes  = subtree.root + 1*size_hash;   // height left nodes
	subtree.right_nodes = subtree.left_nodes + height*size_hash;   // 2**(height-1) - 1 right nodes
	LOG_debug("init_subtree: num_hashes=%d, root=%p, left=%p, right=%p, diff=%d", num_hashes, subtree.root, subtree.left_nodes, subtree.right_nodes, subtree.right_nodes - subtree.root);
	return subtree;	
}



void clear_subtree(MT_Subtree* subtree){
	subtree->leaf_idx = 0;
	subtree->is_full = false;
}



// add to subtree
void add_subtree_leaf(MT_Subtree* subtree, const hash_t* leaf){
	if(subtree->is_full == true) return;

	const uint8_t size_hash = subtree->cfg_hash.size;

	// abuse root hash to store first left hash until tree is full
	if(subtree->leaf_idx == 0) memcpy(subtree->root, leaf, size_hash);

	MT_index_t nodeidx = subtree->leaf_idx;
	MT_index_t curr_height = cur_height(subtree);
	hash_t node_hash[size_hash];
	memcpy(node_hash, leaf, size_hash);

	// infos
	LOG_trace("add_subtree_leaf: Adding %.8s (currh=%d, leaf=%d)", HASH_hexstr(leaf), curr_height, nodeidx);

	// traverse subtree to the top, adding nodes
	for (int h = 0; h < curr_height; h++){
		//LOG_trace("   - (h=%d, nodeidx=%d)", h, nodeidx );

		if ((nodeidx & 1) == 0){   // node is left
			if (h < subtree->height) memcpy(subtree->left_nodes + h*size_hash, node_hash, size_hash); //works, overflow
			LOG_trace("  - Add Left (h=%d, i=%d) hash: %.8s", h, nodeidx, HASH_hexstr( subtree->left_nodes + h*size_hash ));
			break;
		} else {
			unsigned int right_idx = (nodeidx*(1 << h) -1);
			LOG_trace("  - Add Right %d (h=%d, i=%d) hash: %.8s", right_idx, h, nodeidx, HASH_hexstr(node_hash) );
			memcpy( subtree->right_nodes + right_idx*size_hash, node_hash, size_hash);
			nodeidx /= 2;  // round to lower
			if (h < subtree->height){  // when not reached the top: compute next parent
				hash_two(subtree->left_nodes + h*size_hash, node_hash, node_hash, size_hash); 
			}
		}
	}
	subtree->leaf_idx += 1;

	// check if subsubtree is now full
	if(subtree->leaf_idx == (1 << subtree->height)){
		subtree->is_full = true;
		if (subtree->height > 0) memcpy(subtree->left_nodes, subtree->root, size_hash); // restore first left 
		memcpy(subtree->root, node_hash, size_hash);  // assign correct root value
		LOG_trace("add_subtree_leaf: Full! root=%.8s, lidx=%d", HASH_hexstr(node_hash), subtree->leaf_idx );
		subtree->leaf_idx = 0;
		return;
	}

	// Else: check if leaf index is a power of 2 => add new left node:
	if(subtree->leaf_idx == (1 << curr_height)){
		memcpy(subtree->left_nodes + curr_height*size_hash, node_hash, size_hash);
		LOG_trace("  - 2^x! Add %d. hash to left_nodes: %.8s", curr_height, HASH_hexstr( node_hash ) );
	}	
}



// generates the path from a subtree
void gen_subpath(MT_Subtree* subtree, const hash_t* leaf, hash_t* path){
	const size_t size_hash = subtree->cfg_hash.size;    
	bool first_time_left = true;	
    MT_index_t nodeidx = subtree->leaf_idx;

	// walk up the subtree
	for (int h = 0; h < subtree->height; h++){
		if (nodeidx % 2 == 0){   // node is left
			memcpy(path + h*size_hash, subtree->right_nodes + ((nodeidx+1)*(1<<h) -1)*size_hash, size_hash);
			if (first_time_left == true){  // update subtree->left_nodes
				if(h==0){
					memcpy(subtree->left_nodes, leaf, size_hash);
				} else {
					hash_two(path + (h-1)*size_hash, subtree->right_nodes + ((2*nodeidx+1) * (1<<(h-1))-1)*size_hash, subtree->left_nodes + h*size_hash, size_hash);   // Timing-Attack possible here? => No! Only leaks leaf index
				}
				//LOG_trace("first time left, on h=%d, l=%d", h, subtree->leaf_idx);
				first_time_left = false;
			}
		} else {  // node is right
			memcpy(path + h*size_hash, subtree->left_nodes + h*size_hash, size_hash);
		}
		nodeidx /= 2;
	}
}







// ============================================================================
// public function implementations
// ============================================================================


// todo: add height as argument
MT_Tree MT_init(const MT_Config* config, const MT_Fractal_t levels){
	uint8_t height_top = height_top = config->height / 2;
	switch (levels){
		case MT_FRACTAL_ZERO: 
			height_top = 0;
			break;;
		case MT_FRACTAL_ONE: 
			height_top = config->height - 1;
			break;;
		case MT_FRACTAL_HALF:
			height_top = config->height / 2;
			break;;
		default: LOG_warn("Fractal level %d not supported. Fallback to 2.");
	}
	uint8_t height_bottom = config->height - height_top;
	MT_Tree tree;
	tree.config = *config;
	tree.leaf_idx = 0;
	tree.is_full = false;
	tree.top = init_subtree(&tree, height_top);
	tree.exist = init_subtree(&tree, height_bottom);
	tree.desire = init_subtree(&tree, height_bottom);
	tree.root = tree.top.root;
	return tree;	
}


MT_Path MT_init_path(const MT_Config* config){
    MT_Path path;
    path.cfg_hash = config->cfg_hash;
    path.height = config->height;
    path.leaf_idx = 0;
    path.hashes = (hash_t*) malloc( path.height*path.cfg_hash.size );
    return path;
}



void MT_free(MT_Tree* tree){
	free( tree->exist.root );
	free( tree->desire.root );
	free( tree->top.root );
}


void MT_free_path(MT_Path* path){
	free( path->hashes );
}



// Build Merkle Tree from right nodes
void MT_add(MT_Tree* tree, const hash_t* leaf){
	if(tree->is_full == true) return;

	const uint8_t subheight = tree->exist.height;

	// build first bottom tree:
	if(tree->leaf_idx < (1 << subheight)){
		add_subtree_leaf( &(tree->exist), leaf);

		// if full, add first top
		if(tree->exist.is_full){
			LOG_debug("MT_add: Exist tree is full, h=%d root=%.8s", tree->exist.height, HASH_hexstr(tree->exist.root) );
			add_subtree_leaf( &(tree->top), tree->exist.root);
		}

	} else {  // build next desire tree

		add_subtree_leaf( &(tree->desire), leaf);

		// if full, add next top leaf
		if(tree->desire.is_full){
			LOG_trace("Desire tree is full, h=%d root=%.8s", tree->desire.height, HASH_hexstr(tree->desire.root) );
			add_subtree_leaf( &(tree->top), tree->desire.root); 
			clear_subtree( &(tree->desire) );
		}
	}
	tree->leaf_idx += 1;

	// check if tree is now full
	if(tree->leaf_idx == (1 << tree->config.height)){
		LOG_debug("MT_add: tree is full, h=%d root=%.8s", tree->config.height, HASH_hexstr(tree->root) );
		tree->is_full = true;
		tree->leaf_idx = 0;
	}
}




// generate using fractal tree
void MT_generate_path(MT_Tree* tree, const hash_t* leaf, MT_Path* path){

	const size_t size_hash = tree->config.cfg_hash.size; 

	// check if bottom subtree is exhausted
	if (tree->exist.leaf_idx == (1 << tree->exist.height)){
		LOG_trace("MT_grow_dtree: Exist Exhausted");
		clear_subtree( &(tree->exist) );
		MT_Subtree swap_tree = tree->exist;
		tree->exist = tree->desire;  // swap subtrees
		tree->desire = swap_tree;
		tree->top.leaf_idx += 1;
	}

	// bottom part
	gen_subpath( &(tree->exist), leaf, path->hashes);
	tree->exist.leaf_idx += 1;

	// top part
	gen_subpath( &(tree->top), tree->exist.root, path->hashes + size_hash*tree->exist.height );

	// update leaf index
	tree->leaf_idx += 1;
}



// grow the desire tree
void MT_grow_dtree(MT_Tree* tree, const hash_t* leaf){
	LOG_debug("Growing tree. leaf=%.8s, idx=%d", HASH_hexstr(leaf), tree->desire.leaf_idx );
	add_subtree_leaf( &(tree->desire), leaf);
}




void MT_root_from_path(const MT_Path* path, const hash_t* leaf, const MT_index_t leaf_idx, hash_t* root){
	MT_index_t nodeidx = leaf_idx;
	const size_t size_hash = path->cfg_hash.size; 
	memcpy(root, leaf, path->cfg_hash.size);

	for (int h = 0; h < path->height; h++){
		if(nodeidx % 2 == 0){
			hash_two(root, path->hashes + h*size_hash, root, size_hash);
		} else {
			hash_two(path->hashes + h*size_hash, root, root, size_hash);
		}
		nodeidx /= 2;
	}
	LOG_debug("Root from Path. leaf=%.8s, idx=%d, root=%.8s", HASH_hexstr(leaf), leaf_idx, HASH_hexstr(root) );
}



MT_index_t MT_get_grow_leaf_idx(MT_Tree* tree){
	if(tree->top.height > 0){
		return tree->leaf_idx + (1 << tree->exist.height) - 1;
	} else {
		if (tree->leaf_idx % 2 == 0){ // leaf is left
			return tree->leaf_idx + 1;
		} else {
			return 0;
		}
	}
}



// todo: use tree pointer
size_t MT_sizeof_tree(const MT_Config config){
	uint8_t topheight = config.height/2;
	uint8_t botheight = config.height - topheight;
	return sizeof(config) + 3 + 3*sizeof(void*) + config.cfg_hash.size * (3 + topheight + num_rights(topheight) + 2*num_rights(botheight) + 2*botheight);
}

