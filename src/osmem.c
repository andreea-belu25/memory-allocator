// SPDX-License-Identifier: BSD-3-Clause

#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include "osmem.h"
#include "block_meta.h"

#define MMAP_THRESHOLD (128 * 1024)
#define PAGE_SIZE 4096

struct block_meta *head_list;  //  inceputul heap-ului
int numberCallBrk = -1;

/* functie care gaseste cel mai mic multiplu de
 * 8 mai mare decat size-ul trimis
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

// blocurile sunt puse intr-o lista dublu inlantuita
/* inserarea la dreapta in lista a unui bloc nou,
 * tratand si cazul in care e primul bloc adaugat in lista,
 * precum si cazul in care blocul langa care inserez are un alt
 * bloc la dreapta
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

// stergerea unui bloc din lista
void deleteFromList(struct block_meta *block)
{
	if (block == head_list && block)
		head_list = block->next;
	if (block && block->prev != NULL)
		block->prev->next = block->next;
	if (block && block->next != NULL)
		block->next->prev = block->prev;
}

/* functie folosita la debugging pentru printarea
 * caracteristicilor unui bloc
 */
void printBlock(struct block_meta *block)
{
	if (block)
		printf("address: %p size: %lu status: %d prev: %p next: %p\n",
		block, block->size, block->status, block->prev, block->next);
}

/* functie folosita la debugging pentru printarea
 * listei de blocuri
 */
void printList(void)
{
	printf("Lista\n");
/* retin capul de lista pentru ca e variabila globala
 * si altfel, se pierde
 */
	struct block_meta *block = head_list;

	while (block) {
		printBlock(block);
		block = block->next;
	}
	printf("---------- Lista sfarsit ------\n");
}

/* functie care determina ultimul bloc din heap
 * (care a fost alocat cu brk inainte)
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

/* functie care extinde ultimul bloc liber din heap
 * modificand size-ul si statusul blocului
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

/* functie care face alocarea unui bloc cu sbrk si verifica
 *  daca aceasta a avut succes
 */
struct block_meta *allocSbrk(size_t size)
{
	struct block_meta *block = sbrk(0);
	void *p = sbrk(size + allignEightBytes(sizeof(struct block_meta)));

	if (p == (void *)-1)
		return NULL;
	return block;
}

/* functie care face alocarea unui bloc cu mmap si verifica daca
 * aceasta a avut succes
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

// functie care parcurge lista in care sunt tinute blocurile pana la ultimul bloc
struct block_meta *parseForAnyTypeOfAlloc(void)
{
	struct block_meta *pointer = head_list;

	while (pointer && pointer->next)
		pointer = pointer->next;
	return pointer;
}

/* functie care creeaza un bloc cu sbrk sau mmap,
 * updateaza caracteristicile acestuia
 * si il insereaza in lista de blocuri
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

// functie care returneaza pointerul payload-ului asociat unor metadate
void *getBlockPointer(struct block_meta *block)
{
	return (char *)block + 32;
}

// functie care returneaza pointerul metadatelor asociat unui payload
struct block_meta *getPointerBlock(void *ptr)
{
	return (struct block_meta *)((char *)ptr - 32);
}

/* functie care gaseste blocul liber cel mai potrivit din lista pentru
 *  acoperirea unui bloc de o anumita dimensiune
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

/* functie de lipire a unui bloc cu un cel din dreapta lui si
 * stergerea celui suplimentar
 */
void doCaseNextCoalesceBlock(struct block_meta *block)
{
	block->size = block->size + allignEightBytes(sizeof(struct block_meta)) + block->next->size;
	deleteFromList(block->next);
}

/* functie de lipire a unui bloc cu un cel din stanga lui si
 * stergerea celui suplimentar
 */
void doCasePrevCoalesceBlock(struct block_meta *block)
{
	block->prev->size = block->prev->size + allignEightBytes(sizeof(struct block_meta)) + block->size;
	deleteFromList(block);
}

// functie de lipire care trateaza cele doua cazuri de mai sus
void coalesceBlock(struct block_meta *block)
{
	if (block) {
		if (block->next != NULL && block->next->status == STATUS_FREE)
			doCaseNextCoalesceBlock(block);
		if (block->prev != NULL && block->prev->status == STATUS_FREE)
			doCasePrevCoalesceBlock(block);
	}
}

/* functie care imparte un bloc in doua doar daca dimensiunea
 * permite acest lucru
 */
struct block_meta *splitBlock(struct block_meta *block, size_t size)
{
	block->status = STATUS_ALLOC;
	size_t remainSize = block->size - size - allignEightBytes(sizeof(struct block_meta));

	// pentru ca am unsigned, deci doar numere pozitive, iar altfel, pentru valori negative va face ceva gresit
	if (size < block->size && block->size - size >= 8 + allignEightBytes(sizeof(struct block_meta))) {
	 //  daca mai este suficienta memorie pentru crearea unui bloc de cel putin dimensiunea minima
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

// functie care prealoca heap-ul pentru prima data cand se executa brk
void preallocateHeap(size_t size)
{
	struct block_meta *block = createBlockMalloc(size - allignEightBytes(sizeof(struct block_meta)));

	block->status = STATUS_FREE;
}

//  cazul de prealocare heap din malloc
void casePreallocateHeapMalloc(void)
{
	preallocateHeap(MMAP_THRESHOLD);
	numberCallBrk = 0;
}

//  cazul de split din malloc
void *caseSplitBlock(struct block_meta *block, size_t size)
{
	struct block_meta *splitedBlock = splitBlock(block, size);

	return getBlockPointer(splitedBlock);
}

//  cazul de extindere si creare bloc nou malloc
void *caseExtendAndCreate(size_t size)
{
	struct block_meta *lastBlock = extendLastBlock(size);

	if (lastBlock != NULL && size < MMAP_THRESHOLD)
		return getBlockPointer(lastBlock);
	struct block_meta *createdBlock = createBlockMalloc(size);

	return getBlockPointer(createdBlock);
}

//  malloc = alocare memoriei, fara initializarea memoriei
void *os_malloc(size_t size)
{
	if (size == 0) // nu am ce aloca
		return NULL;
	// daca este prima oara cand trebuie facut brk => se prealoca heap-ul
	if (size < MMAP_THRESHOLD && numberCallBrk == -1)
		casePreallocateHeapMalloc();

	struct block_meta *block = findBestBlock(allignEightBytes(size));
	/* daca am gasit un bloc liber (care a fost deja alocat, dar eliberat)
	 * de dimensiune suficienta cat sa acopere dimensiunea ceruta => split
	 */
	if (block != NULL)
		return caseSplitBlock(block, allignEightBytes(size));
	/* daca pot sa extind ultimul bloc => extindere, altfel creez unul nou
	 */
	return caseExtendAndCreate(allignEightBytes(size));
}

//  functia free = eliberarea memoriei alocate
void os_free(void *ptr)
{
	if (ptr == NULL)
		return;
	struct block_meta *pointerBlock = getPointerBlock(ptr);
	/* pe heap nu se poate dezaloca memorie pentru ca heap-ul e zona de memorie continua
	 * => marchez blocul ca free si se incearca lipirea acestuia la o zona goala
	 */
	if (pointerBlock && pointerBlock->status == STATUS_ALLOC) {
		pointerBlock->status = STATUS_FREE;
		coalesceBlock(pointerBlock);
	} else {
		/* daca zona a fost alocata cu mmap => o sterg din lista si ii dezaloc continutul
		 */
		if (pointerBlock && pointerBlock->status == STATUS_MAPPED) {
			deleteFromList(pointerBlock);
			munmap(pointerBlock, pointerBlock->size + allignEightBytes(sizeof(struct block_meta)));
		} else {
			return; //  daca statusul e free => nu trebuie sa mai faca nimic
		}
	}
}

/* crearea unui bloc: alocarea acestuia cu brk sau mmap,
 * modificarea atributelor si inserarea lui in lista de blocuri
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

//  caz prealocare heap la calloc
void casePreallocateHeapCalloc(void)
{
	preallocateHeap(MMAP_THRESHOLD);
	numberCallBrk = 0;
}

//  caz creare bloc nou la calloc
void *caseCreateBlockCalloc(size_t size)
{
	struct block_meta *block = createBlockCalloc(size);

	return getBlockPointer(block);
}

//  caz split bloc la calloc
void *caseSplitBlockCalloc(struct block_meta *block, size_t size)
{
	struct block_meta *splitedBlock = splitBlock(block, size);

	return getBlockPointer(splitedBlock);
}

// caz extindere/ creare bloc calloc
void *caseExtendAndCreateCalloc(size_t size)
{
	struct block_meta *lastBlock = extendLastBlock(size);

	if (lastBlock != NULL)
		return getBlockPointer(lastBlock);
	struct block_meta *createdBlock = createBlockCalloc(size);

	return getBlockPointer(createdBlock);
}

/* alloc mai intai memorie pentru calloc, asemanator ca la malloc,
 * dar aici dimensiunea este nmemb * size
 */
void *osCallocReserveMemory(size_t nmemb, size_t sizee)
{
	if (sizee * nmemb == 0)
		return NULL; // nu am ce sa aloc
	size_t size = allignEightBytes(sizee * nmemb);

	// primul apel de brk
	if (size + allignEightBytes(sizeof(struct block_meta)) < PAGE_SIZE && numberCallBrk == -1)
		casePreallocateHeapCalloc();
	// se creeaza un nou bloc de memorie cu sbrk sau mmap
	if (size + allignEightBytes(sizeof(struct block_meta)) > PAGE_SIZE)
		return caseCreateBlockCalloc(size);
	struct block_meta *block = findBestBlock(size);

	// daca pot sa fac split, altfel extind/ creez alt bloc
	if (block != NULL)
		return caseSplitBlock(block, size);
	return caseExtendAndCreateCalloc(size);
}

/* dupa alocarea memoriei initializeaza toata memoria prin setarea
 * fiecarui bit la 0
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

/* realloc poate sa extinda sau sa micsoreze un bloc de memorie
 * in functie de size-ul acestuia si de spatiul de langa el
 */

/* se va incerca micsorarea blocului curent in fct de size
 */
void *truncateBlock(struct block_meta *block, size_t size)
{
	struct block_meta *blockResulted = splitBlock(block, size);

	return getBlockPointer(blockResulted);
}

/* functie care lipeste doua blocuri din memorie pentru
 * realloc si il sterge pe cel suplimentar
 */
void coalesceBlockRealloc(struct block_meta *block)
{
	if (block && block->prev != NULL) {
		block->prev->size = block->prev->size + allignEightBytes(sizeof(struct block_meta)) + block->size;
		deleteFromList(block);
	}
}

/* se va incerca extinderea unui bloc daca la dreapta acestuia
 * exista suficient loc
 */

/* functie pentru realloc care mareste dimensiunea unui bloc de memorie daca:
 * exista bloc liber in dreapta sau daca blocul e ultimul bloc din heap
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

/* bloc alocat cu size-ul > MMAP_THRESOLD => trebuie realocat cu mmap si scapat
 * de blocul anterior
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

/* daca nu sunt in niciun caz specific => aloc memorie si copiez
 * continutul blocului vechi, eliberand la final pointer-ul vechi pentru ca nu mai
 *  am nevoie el
 */
void *noSpecificCaseRealloc(size_t size, void *ptr, struct block_meta *oldBlock)
{
	void *newBlock = os_malloc(allignEightBytes(size));

	memcpy(newBlock, ptr, oldBlock->size);
	os_free(ptr);
	return newBlock;
}

/* functia de realloc care trateaza toate cazurile posibile si
 * apeleaza functiile corespunzatoare
 */
void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL)
		return os_malloc(allignEightBytes(size));
	if (size == 0) { // dim = 0 => bloc curent eliberat (nu contine ceva)
		os_free(ptr);
		return NULL;
	}
	struct block_meta *oldBlock = (struct block_meta *)((char *)ptr - 32);

	if (oldBlock->status == STATUS_FREE) // nu mai am acces la blocul acesta (e deja free)
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
