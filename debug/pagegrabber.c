#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#define PAGES 3
#define PAGE_SIZE 4096


int main() {

	size_t *pages = malloc(PAGE_SIZE * PAGES);
	for(size_t i = 0; i < PAGES * PAGE_SIZE / sizeof(*pages); ++i) {
		pages[i] = i;
	}

	printf("Enter to contine\n");
	getchar();

	for(size_t i = 0; i < PAGES; ++i) {
		printf("Page %ld pages[%ld] = %ld\n", i, i*PAGE_SIZE/sizeof(size_t), pages[i*PAGE_SIZE/sizeof(size_t)]);
	}
	
	free(pages);
}
