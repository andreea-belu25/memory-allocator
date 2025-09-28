// SPDX-License-Identifier: BSD-3-Clause

#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include "osmem.h"
#include "block_meta.h"

#define MMAP_THRESHOLD (128 * 1024)
#define PAGE_SIZE 4096

struct block_meta *head_list;  // Beginning of the heap
int numberCallBrk = -1;

/* Function that finds the smallest multiple of
 * 8 greater than the sent size
 */
size_t allignEightBytes(size_t size)
{
	size_t rest = size % 8, Max = -1;

	if (rest == 0) {
		Max = size;
	} else {
		if (size - rest > size + (8 - rest))
			Max = size - rest;
		else
			Max = size + (8 - rest);
	}
	return Max;
}

// Blocks are put in a doubly linked list
/* Insertion to the right in the list of a new block,
 * also handling the case where it's the first block added to the list,
 * as well as the case where the block next to which I insert has another
 * block to the right
 */
void insertRight(struct block_meta *insert_elem, struct block_meta *reference_elem)
{
	if (!head_list) {
		head_list = insert_elem;
		head_list->next = NULL;
		head_list->prev = NULL;
		return;
	}
	
	if (reference_elem) {
		insert_elem->next = reference_elem->next;
		insert_elem->prev = reference_elem;
		if (reference_elem->next)
			reference_elem->next->prev = insert_elem;
		reference_elem->next = insert_elem;
	}
}

// Deletion of a block from the list
void deleteFromList(struct block_meta *block)
{
	if (block == head_list && block)
		head_list = block->next;
	if (block && block->prev != NULL)
		block->prev->next = block->next;
	if (block && block->next != NULL)
		block->next->prev = block->prev;
}

/* Function used for debugging to print
 * the characteristics of a block
 */
void printBlock(struct block_meta *block)
{
	if (block)
		printf("address: %p size: %lu status: %d prev: %p next: %p\n",
		block, block->size, block->status, block->prev, block->next);
}

/* Function used for debugging to print
 * the list of blocks
 */
void printList(void)
{
	printf("Lista\n");
	/* I keep the list head because it's a global variable
	 * and otherwise, it gets lost
	 */
	struct block_meta *block = head_list;

	while (block) {
		printBlock(block);
		block = block->next;
	}
	printf("---------- Lista sfarsit ------\n");
}

/* Function that determines the last block in the heap
 * (which was allocated with brk before)
 */
struct block_meta *lastBlockInHeap(void)
{
	struct block_meta *blockInList = head_list, *lastBlock = NULL;

	while (blockInList) {
		if (blockInList->status != STATUS_MAPPED)
			lastBlock = blockInList;
		blockInList = blockInList->next;
	}
	return lastBlock;
}

/* Function that extends the last free block in the heap
 * modifying the size and status of the block
 */
struct block_meta *extendLastBlock(size_t size)
{
	struct block_meta *lastBlock = lastBlockInHeap();

	if (lastBlock && lastBlock->status == STATUS_FREE && size < MMAP_THRESHOLD) {
		void *pointer = sbrk(size - lastBlock->size);

		if (pointer == (void *)-1)
			return NULL;
		lastBlock->status = STATUS_ALLOC;
		lastBlock->size = size;
		return lastBlock;
	}
	return NULL;
}

/* Function that allocates a block with sbrk and checks
 * if this was successful
 */
struct block_meta *allocSbrk(size_t size)
{
	struct block_meta *block = sbrk(0);
	void *p = sbrk(size + allignEightBytes(sizeof(struct block_meta)));

	if (p == (void *)-1)
		return NULL;
	return block;
}

/* Function that allocates a block with mmap and checks if
 * this was successful
 */
struct block_meta *allocMmap(size_t size)
{
	void *pointer = mmap(NULL, size + allignEightBytes(sizeof(struct block_meta)),
	PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	if (pointer == (void *)-1)
		return NULL;
	struct block_meta *block = (struct block_meta *)pointer;
	return block;
}

// Function that traverses the list where blocks are kept until the last block
struct block_meta *parseForAnyTypeOfAlloc(void)
{
	struct block_meta *pointer = head_list;

	while (pointer && pointer->next)
		pointer = pointer->next;
	return pointer;
}

/* Function that creates a block with sbrk or mmap,
 * updates its characteristics
 * and inserts it in the block list
 */
struct block_meta *createBlockMalloc(size_t size)
{
	if (size < MMAP_THRESHOLD)	{
		struct block_meta *blockSbrk = allocSbrk(size);

		blockSbrk->status = STATUS_ALLOC;
		blockSbrk->size = size;
		blockSbrk->prev = NULL;
		blockSbrk->next = NULL;
		struct block_meta *getBlock = parseForAnyTypeOfAlloc();

		insertRight(blockSbrk, getBlock);
		return blockSbrk;
	}
	
	struct block_meta *blockMmap = allocMmap(size);

	blockMmap->status = STATUS_MAPPED;
	blockMmap->size = size;
	blockMmap->prev = NULL;
	blockMmap->next = NULL;
	struct block_meta *getBlock = parseForAnyTypeOfAlloc();

	insertRight(blockMmap, getBlock);
	return blockMmap;
}

// Function that returns the payload pointer associated with metadata
void *getBlockPointer(struct block_meta *block)
{
	return (char *)block + 32;
}

// Function that returns the metadata pointer associated with a payload
struct block_meta *getPointerBlock(void *ptr)
{
	return (struct block_meta *)((char *)ptr - 32);
}

/* Function that finds the most suitable free block from the list for
 * covering a block of a certain size
 */
struct block_meta *findBestBlock(size_t size)
{
	struct block_meta *index_block = head_list, *block_return = NULL;
	size_t Min = MMAP_THRESHOLD * 10;

	while (index_block) {
		if (index_block->status == STATUS_FREE) {
			if (index_block->size >= size && index_block->size < Min) {
				Min = index_block->size;
				block_return = index_block;
			}
		}
		index_block = index_block->next;
	}
	return block_return;
}

/* Function to merge a block with the one to its right and
 * delete the extra one
 */
void doCaseNextCoalesceBlock(struct block_meta *block)
{
	block->size = block->size + allignEightBytes(sizeof(struct block_meta)) + block->next->size;
	deleteFromList(block->next);
}

/* Function to merge a block with the one to its left and
 * delete the extra one
 */
void doCasePrevCoalesceBlock(struct block_meta *block)
{
	block->prev->size = block->prev->size + allignEightBytes(sizeof(struct block_meta)) + block->size;
	deleteFromList(block);
}

// Merge function that handles the two cases above
void coalesceBlock(struct block_meta *block)
{
	if (block) {
		if (block->next != NULL && block->next->status == STATUS_FREE)
			doCaseNextCoalesceBlock(block);
		if (block->prev != NULL && block->prev->status == STATUS_FREE)
			doCasePrevCoalesceBlock(block);
	}
}

/* Function that splits a block in two only if the size
 * allows this
 */
struct block_meta *splitBlock(struct block_meta *block, size_t size)
{
	block->status = STATUS_ALLOC;
	size_t remainSize = block->size - size - allignEightBytes(sizeof(struct block_meta));

	// Because we have unsigned, so only positive numbers, otherwise for negative values it will do something wrong
	if (size < block->size && block->size - size >= 8 + allignEightBytes(sizeof(struct block_meta))) {
		// If there is still enough memory to create a block of at least minimum size
		block->size = size;
		char *ptr = (char *)block + size + allignEightBytes(sizeof(struct block_meta));
		struct block_meta *another_block = (struct block_meta *)ptr;

		another_block->size = remainSize;
		another_block->status = STATUS_FREE;
		insertRight(another_block, block);
		coalesceBlock(another_block);
	}
	return block;
}

// Function that preallocates the heap for the first time when brk is executed
void preallocateHeap(size_t size)
{
	struct block_meta *block = createBlockMalloc(size - allignEightBytes(sizeof(struct block_meta)));

	block->status = STATUS_FREE;
}

// Case of heap preallocation from malloc
void casePreallocateHeapMalloc(void)
{
	preallocateHeap(MMAP_THRESHOLD);
	numberCallBrk = 0;
}

// Case of split from malloc
void *caseSplitBlock(struct block_meta *block, size_t size)
{
	struct block_meta *splitedBlock = splitBlock(block, size);

	return getBlockPointer(splitedBlock);
}

// Case of extend and create new block malloc
void *caseExtendAndCreate(size_t size)
{
	struct block_meta *lastBlock = extendLastBlock(size);

	if (lastBlock != NULL && size < MMAP_THRESHOLD)
		return getBlockPointer(lastBlock);
	struct block_meta *createdBlock = createBlockMalloc(size);

	return getBlockPointer(createdBlock);
}

// malloc = memory allocation, without memory initialization
void *os_malloc(size_t size)
{
	if (size == 0) // Nothing to allocate
		return NULL;
	// If it's the first time brk needs to be done => the heap is preallocated
	if (size < MMAP_THRESHOLD && numberCallBrk == -1)
		casePreallocateHeapMalloc();

	struct block_meta *block = findBestBlock(allignEightBytes(size));
	/* If I found a free block (which was already allocated, but freed)
	 * of sufficient size to cover the requested size => split
	 */
	if (block != NULL)
		return caseSplitBlock(block, allignEightBytes(size));
	/* If I can extend the last block => extension, otherwise I create a new one
	 */
	return caseExtendAndCreate(allignEightBytes(size));
}

// The free function = freeing allocated memory
void os_free(void *ptr)
{
	if (ptr == NULL)
		return;
	struct block_meta *pointerBlock = getPointerBlock(ptr);
	/* On the heap you cannot deallocate memory because the heap is a continuous memory area
	 * => I mark the block as free and try to merge it with an empty area
	 */
	if (pointerBlock && pointerBlock->status == STATUS_ALLOC) {
		pointerBlock->status = STATUS_FREE;
		coalesceBlock(pointerBlock);
	} else {
		/* If the area was allocated with mmap => I delete it from the list and deallocate its content
		 */
		if (pointerBlock && pointerBlock->status == STATUS_MAPPED) {
			deleteFromList(pointerBlock);
			munmap(pointerBlock, pointerBlock->size + allignEightBytes(sizeof(struct block_meta)));
		} else {
			return; // If the status is free => nothing more needs to be done
		}
	}
}

/* Creating a block: allocating it with brk or mmap,
 * modifying attributes and inserting it in the block list
 */
struct block_meta *createBlockCalloc(size_t size)
{
	if (size + allignEightBytes(sizeof(struct block_meta)) < PAGE_SIZE) {
		struct block_meta *blockSbrk = allocSbrk(size);

		blockSbrk->status = STATUS_ALLOC;
		blockSbrk->size = size;
		blockSbrk->prev = NULL;
		blockSbrk->next = NULL;
		struct block_meta *getBlock = parseForAnyTypeOfAlloc();

		insertRight(blockSbrk, getBlock);
		return blockSbrk;
	}
	
	struct block_meta *blockMmap = allocMmap(size);

	blockMmap->status = STATUS_MAPPED;
	blockMmap->size = size;
	blockMmap->prev = NULL;
	blockMmap->next = NULL;
	struct block_meta *getBlock = parseForAnyTypeOfAlloc();

	insertRight(blockMmap, getBlock);
	return blockMmap;
}

// Case heap preallocation in calloc
void casePreallocateHeapCalloc(void)
{
	preallocateHeap(MMAP_THRESHOLD);
	numberCallBrk = 0;
}

// Case create new block in calloc
void *caseCreateBlockCalloc(size_t size)
{
	struct block_meta *block = createBlockCalloc(size);

	return getBlockPointer(block);
}

// Case split block in calloc
void *caseSplitBlockCalloc(struct block_meta *block, size_t size)
{
	struct block_meta *splitedBlock = splitBlock(block, size);

	return getBlockPointer(splitedBlock);
}

// Case extend/create block calloc
void *caseExtendAndCreateCalloc(size_t size)
{
	struct block_meta *lastBlock = extendLastBlock(size);

	if (lastBlock != NULL)
		return getBlockPointer(lastBlock);
	struct block_meta *createdBlock = createBlockCalloc(size);

	return getBlockPointer(createdBlock);
}

/* Allocate memory for calloc first, similar to malloc,
 * but here the size is nmemb * size
 */
void *osCallocReserveMemory(size_t nmemb, size_t sizee)
{
	if (sizee * nmemb == 0)
		return NULL; // Nothing to allocate
	size_t size = allignEightBytes(sizee * nmemb);

	// First brk call
	if (size + allignEightBytes(sizeof(struct block_meta)) < PAGE_SIZE && numberCallBrk == -1)
		casePreallocateHeapCalloc();
	// A new memory block is created with sbrk or mmap
	if (size + allignEightBytes(sizeof(struct block_meta)) > PAGE_SIZE)
		return caseCreateBlockCalloc(size);
	struct block_meta *block = findBestBlock(size);

	// If I can split, otherwise extend/create another block
	if (block != NULL)
		return caseSplitBlock(block, size);
	return caseExtendAndCreateCalloc(size);
}

/* After memory allocation initializes all memory by setting
 * each bit to 0
 */
void *os_calloc(size_t nmemb, size_t size)
{
	void *memAdress = osCallocReserveMemory(nmemb, size);

	if (memAdress) {
		int index = 0;

		for (index = 0; index < (int)(nmemb * size); index++)
			*(char *)(memAdress + index) = 0;
	}
	return memAdress;
}

/* realloc can extend or shrink a memory block
 * depending on its size and the space next to it
 */

/* Will attempt to shrink the current block according to size
 */
void *truncateBlock(struct block_meta *block, size_t size)
{
	struct block_meta *blockResulted = splitBlock(block, size);

	return getBlockPointer(blockResulted);
}

/* Function that merges two memory blocks for
 * realloc and deletes the extra one
 */
void coalesceBlockRealloc(struct block_meta *block)
{
	if (block && block->prev != NULL) {
		block->prev->size = block->prev->size + allignEightBytes(sizeof(struct block_meta)) + block->size;
		deleteFromList(block);
	}
}

/* Will attempt to extend a block if to the right of it
 * there is enough space
 */

/* Function for realloc that increases the size of a memory block if:
 * there is a free block to the right or if the block is the last block in the heap
 */
struct block_meta *expandBlock(struct block_meta *block, size_t size)
{
	struct block_meta *lastBlock = lastBlockInHeap();

	if (block == lastBlock && size < MMAP_THRESHOLD) {
		lastBlock->status = STATUS_FREE;
		extendLastBlock(size);
		return lastBlock;
	}
	
	if (block->next && block->next->status == STATUS_FREE &&
	(block->next->size + allignEightBytes(sizeof(struct block_meta))) >= size - block->size) {
		struct block_meta *splitedBlock = splitBlock(block->next, size - block->size);

		coalesceBlockRealloc(splitedBlock);
		return block;
	}
	return NULL;
}

/* Block allocated with size > MMAP_THRESHOLD => must be reallocated with mmap and get rid
 * of the previous block
 */
void *reallocMappedBlock(void *ptr, size_t size, struct block_meta *oldBlock)
{
	void *newBlock = os_malloc(allignEightBytes(size));

	if (oldBlock->size < allignEightBytes(size))
		memcpy(newBlock, ptr, oldBlock->size);
	else
		memcpy(newBlock, ptr, allignEightBytes(size));
	os_free(getBlockPointer(oldBlock));
	return newBlock;
}

/* If I'm not in any specific case => I allocate memory and copy
 * the content of the old block, finally freeing the old pointer because I no longer
 * need it
 */
void *noSpecificCaseRealloc(size_t size, void *ptr, struct block_meta *oldBlock)
{
	void *newBlock = os_malloc(allignEightBytes(size));

	memcpy(newBlock, ptr, oldBlock->size);
	os_free(ptr);
	return newBlock;
}

/* The realloc function that handles all possible cases and
 * calls the corresponding functions
 */
void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL)
		return os_malloc(allignEightBytes(size));
	if (size == 0) { // size = 0 => current block freed (doesn't contain anything)
		os_free(ptr);
		return NULL;
	}
	
	struct block_meta *oldBlock = (struct block_meta *)((char *)ptr - 32);

	if (oldBlock->status == STATUS_FREE) // I no longer have access to this block (it's already free)
		return NULL;
	if (allignEightBytes(size) > MMAP_THRESHOLD || oldBlock->status == STATUS_MAPPED)
		return reallocMappedBlock(ptr, allignEightBytes(size), oldBlock);
	if (allignEightBytes(size) <= oldBlock->size)
		return truncateBlock(oldBlock, allignEightBytes(size));

	struct block_meta *expendedBlock = expandBlock(oldBlock, allignEightBytes(size));

	if (expendedBlock)
		return getBlockPointer(expendedBlock);

	return noSpecificCaseRealloc(size, ptr, oldBlock);
}
