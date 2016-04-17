#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "image.h"
#include "vma.h"
#include "cr_options.h"
#include "servicefd.h"
#include "page-read.h"

#include "protobuf.h"
#include "protobuf/pagemap.pb-c.h"

#ifndef SEEK_DATA
#define SEEK_DATA	3
#define SEEK_HOLE	4
#endif



void print_mmap_flags(int flag) {
	if (flag & MAP_SHARED) {
		pr_err("MAP_SHARED set\n");
	}
	if (flag & MAP_PRIVATE) {
		pr_err("MAP_PRIVATE set\n");
	}
	if (flag & MAP_32BIT) {
		pr_err("MAP_32BIT set\n");
	}
	if (flag & MAP_ANON) {
		pr_err("MAP_ANON set\n");
	}
	if (flag & MAP_ANONYMOUS) {
		pr_err("MAP_ANONYMOUS set\n");
	}
	if (flag & MAP_DENYWRITE) {
		pr_err("MAP_DENYWRITE set\n");
	}
	if (flag & MAP_EXECUTABLE) {
		pr_err("MAP_EXECUTABLE set\n");
	}
	if (flag & MAP_FILE) {
		pr_err("MAP_FILE set\n");
	}
	if (flag & MAP_FIXED) {
		pr_err("MAP_FIXED set\n");
	}
	if (flag & MAP_GROWSDOWN) {
		pr_err("MAP_GROWSDOWN set\n");
	}
	if (flag & MAP_HUGETLB) {
		pr_err("MAP_HUGETLB set\n");
	}
	/*
	if (flag & MAP_HUGE_2MB) {
		pr_err("MAP_HUGE_2MB set\n");
	}
	if (flag & MAP_HUGE_1GB) {
		pr_err("MAP_HUGE_1GB set\n");
	}
	*/
	if (flag & MAP_LOCKED) {
		pr_err("MAP_LOCKED set\n");
	}
	if (flag & MAP_NONBLOCK) {
		pr_err("MAP_NONBLOCK set\n");
	}
	if (flag & MAP_NORESERVE) {
		pr_err("MAP_NORESERVE set\n");
	}
	if (flag & MAP_POPULATE) {
		pr_err("MAP_POPULATE set\n");
	}
	if (flag & MAP_STACK) {
		pr_err("MAP_STACK set\n");
	}
	/*
	if (flag & MAP_UNINITIALIZED) {
		pr_debug("MAP_UNINITIALIZED set\n");
	}
	*/
}

static int get_page_vaddr(struct page_read *pr, struct iovec *iov)
{
	int ret;
	u64 img_va;

	ret = read_img_eof(pr->pmi, &img_va);
	if (ret <= 0)
		return ret;

	iov->iov_base = (void *)decode_pointer(img_va);
	iov->iov_len = PAGE_SIZE;

	return 1;
}

static int read_page(struct page_read *pr, unsigned long vaddr, int nr, void *buf)
{
	int ret;

	BUG_ON(nr != 1);

	ret = read(img_raw_fd(pr->pmi), buf, PAGE_SIZE);
	if (ret != PAGE_SIZE) {
		pr_err("Can't read mapping page %d\n", ret);
		return -1;
	}

	return 1;
}

void pagemap2iovec(PagemapEntry *pe, struct iovec *iov)
{
	iov->iov_base = decode_pointer(pe->vaddr);
	iov->iov_len = pe->nr_pages * PAGE_SIZE;
}

void iovec2pagemap(struct iovec *iov, PagemapEntry *pe)
{
	pe->vaddr = encode_pointer(iov->iov_base);
	pe->nr_pages = iov->iov_len / PAGE_SIZE;
}

static int get_pagemap(struct page_read *pr, struct iovec *iov)
{
	int ret;
	PagemapEntry *pe;

	ret = pb_read_one_eof(pr->pmi, &pe, PB_PAGEMAP);
	if (ret <= 0)
		return ret;

	pagemap2iovec(pe, iov);

	pr->pe = pe;
	pr->cvaddr = (unsigned long)iov->iov_base;

	if (pe->in_parent && !pr->parent) {
		pr_err("No parent for snapshot pagemap\n");
		return -1;
	}

	return 1;
}

static void put_pagemap(struct page_read *pr)
{
	pagemap_entry__free_unpacked(pr->pe, NULL);
}

static int read_pagemap_page(struct page_read *pr, unsigned long vaddr, int nr, void *buf);

static void skip_pagemap_pages(struct page_read *pr, unsigned long len)
{
	if (!len)
		return;

	pr_debug("\tpr%u Skip %lu bytes from page-dump\n", pr->id, len);
	if (!pr->pe->in_parent)
		lseek(img_raw_fd(pr->pi), len, SEEK_CUR);
	pr->cvaddr += len;
}

int seek_pagemap_page(struct page_read *pr, unsigned long vaddr, bool warn)
{
	int ret;
	struct iovec iov;

	if (pr->pe)
		pagemap2iovec(pr->pe, &iov);
	else
		goto new_pagemap;

	while (1) {
		unsigned long iov_end;

		if (vaddr < pr->cvaddr) {
			if (warn)
				pr_err("Missing %lx in parent pagemap, current iov: base=%lx,len=%zu\n",
					vaddr, (unsigned long)iov.iov_base, iov.iov_len);
			return 0;
		}
		iov_end = (unsigned long)iov.iov_base + iov.iov_len;

		if (iov_end <= vaddr) {
			skip_pagemap_pages(pr, iov_end - pr->cvaddr);
			put_pagemap(pr);
new_pagemap:
			ret = get_pagemap(pr, &iov);
			if (ret <= 0)
				return ret;

			continue;
		}

		skip_pagemap_pages(pr, vaddr - pr->cvaddr);
		return 1;
	}
}

static inline void pagemap_bound_check(PagemapEntry *pe, unsigned long vaddr, int nr)
{
	if (vaddr < pe->vaddr || (vaddr - pe->vaddr) / PAGE_SIZE + nr > pe->nr_pages) {
		pr_err("Page read err %"PRIx64":%u vs %lx:%u\n",
				pe->vaddr, pe->nr_pages, vaddr, nr);
		BUG();
	}
}

/* LITTON: right now I'm exporting this, but ultimately it makes sense
 * to set this on page_read struct appropriately */
int mmap_pagemap_pages(struct page_read *pr, unsigned long vaddr, int nr, void *buf, struct vma_area *vma)
{
	int ret;
	unsigned long len = nr * PAGE_SIZE;
	void *mmap_ret;

	pr_info("pr%u Read %lx %u pages (mmap style)\n", pr->id, vaddr, nr);
	pagemap_bound_check(pr->pe, vaddr, nr);

	if (pr->pe->in_parent) {
		struct page_read *ppr = pr->parent;

		/*
		 * Parent pagemap at this point entry may be shorter
		 * than the current vaddr:nr needs, so we have to
		 * carefully 'split' the vaddr:nr into pieces and go
		 * to parent page-read with the longest requests it
		 * can handle.
		 */

		do {
			int p_nr;

			pr_debug("\tpr%u Read from parent\n", pr->id);
			ret = seek_pagemap_page(ppr, vaddr, true);
			if (ret <= 0)
				return -1;

			/*
			 * This is how many pages we have in the parent
			 * page_read starting from vaddr. Go ahead and
			 * read as much as we can.
			 */
			p_nr = ppr->pe->nr_pages - (vaddr - ppr->pe->vaddr) / PAGE_SIZE;
			pr_info("\tparent has %u pages in\n", p_nr);
			if (p_nr > nr)
				p_nr = nr;

			ret = read_pagemap_page(ppr, vaddr, p_nr, buf);
			if (ret == -1)
				return ret;

			/*
			 * OK, let's see how much data we have left and go
			 * to parent page-read again for the next pagemap
			 * entry.
			 */
			nr -= p_nr;
			vaddr += p_nr * PAGE_SIZE;
			buf += p_nr * PAGE_SIZE;
		} while (nr);

	} else {

		int fd = img_raw_fd(pr->pi);
		/*
		  char out[128];
		  char path[256];
		  sprintf(out, "/proc/self/fd/%d", fd);
		  if (readlink(out, path, 256) < 0) {
		  pr_perror("Could not readlink:");
		*/


		off_t current_vaddr = lseek(fd, 0, SEEK_CUR);
		//pr_debug("-->pr%u mmap page %lx from self %lx/%"PRIx64" with buf value of %"PRIx64" OK\n", pr->id, vaddr, pr->cvaddr, current_vaddr, (unsigned long)buf);

		if (munmap(buf, len) != 0) {
			pr_perror("Could not munmap: %s\n", strerror(errno));
		}


		int new_flags = (vma->e->flags & ~(MAP_ANONYMOUS|MAP_SHARED))
			| MAP_FIXED | MAP_PRIVATE;


		vma->e->status |= VMA_FILE_PRIVATE;
		vma->e->fd = fd;
		mmap_ret = mmap(buf, len, vma->e->prot | PROT_WRITE, new_flags, fd, current_vaddr);
 
		/* This should have shrunk a previous mapping because it would overlap. */

		if (mmap_ret == MAP_FAILED) {
			struct stat sbuf;
			pr_err("can't mmap page %"PRIX64" at vaddr %lx len %lu: %s\n", (unsigned long)buf, vaddr, len, strerror(errno));
			pr_err("flags were %d/%d, fd was %d, offset was %lu\n", new_flags, vma->e->flags, fd, current_vaddr);
			pr_err("New flags: \n");
			print_mmap_flags(new_flags);
			pr_err("Old flags: \n");
			print_mmap_flags(vma->e->flags);

			if (fstat(fd, &sbuf) != 0) {
				pr_err("Could not stat\n");
			} else {
				//pr_err("file size is %lu, in bounds %d\n", sbuf.st_size, current_vaddr + len <= sbuf.st_size);
			}
			return -1;
		}

		assert(buf == mmap_ret);

		
		//uint8_t *intbuf = buf;
		//pr_debug("First 4 bytes: %d %d %d %d\n", intbuf[0], intbuf[1], intbuf[2], intbuf[3]);
		/* This was a debugging aide. Leaving in for now
		//read(fd, buf, PAGE_SIZE);
		pr_debug("AFter read First 4 bytes: %d %d %d %d\n", intbuf[0], intbuf[1], intbuf[2], intbuf[3]);
		*/

#ifdef DO_REGIONS
		struct entry_node *n = xmalloc(sizeof(*n));
		memcpy(&n->e, vma->e, sizeof(n->e));
		n->e.start = (unsigned long) mmap_ret;
		n->e.end = (unsigned long) (mmap_ret) + len;
		n->e.fd = fd;
		n->e.pgoff = current_vaddr;
		n->e.flags = vma->e->flags | MAP_FIXED;
		n->e.flags = vma->e->prot | PROT_WRITE;

		/* Okay, find who we overlap with. Should only be one region. If
		 * we overlap, cut overlapping region off of tail */

		struct entry_node *pos;
		struct entry_node *cur = NULL;
		list_for_each_entry_safe(cur, pos, &vma->entries.list, list) {
			/* cases *bottom one is new mapping,always <= original in size. It should ALWAYS overlap
			   1. 
			   |-------|
			   |---|

			   2.
			   |------|
			   |--|

			   3. 
			   |------|
			     |--|
			*/

			int handled = 1;
			if (cur->e.end == n->e.end) {
				/* cut off from the end */
				cur->e.end = n->e.start;
			} else if (cur->e.start == n->e.start) {
				/* cut off from the front */
				cur->e.start = n->e.end;
			} else if (cur->e.start < n->e.start && cur->e.end > n->e.end) {
				/* in the middle, gotta split up */
				struct entry_node *newt = xmalloc(sizeof(*newt));
				memcpy(&newt->e, &cur->e, sizeof(newt->e));
				cur->e.end = n->e.start;
				newt->e.start = n->e.end;
				assert(vma_entry_len(&cur->e));
				assert(vma_entry_len(&newt->e));
				list_add(&newt->list, &vma->entries.list);
			} else {
				handled = 0;
			}

			if (handled) {
				if (cur->e.end - cur->e.start == 0) {
					list_del(&cur->list);
				}
				break;
			} else {
				assert(vma_entry_len(&cur->e));
			}
		}

		list_add_tail(&n->list, &vma->entries.list);
		list_for_each_entry(n, &vma->entries.list, list) {
			//pr_debug("--->0x%"PRIx64" - 0x%"PRIx64"\n", n->e.start, n->e.end);
		}

#endif
		/* we didn't read, but we decided we're too special to read, so ha ha */
		lseek(fd, current_vaddr + len, SEEK_SET);

		if (opts.auto_dedup) {
			ret = punch_hole(pr, current_vaddr, (unsigned int)len, false);
			if (ret == -1) {
				return -1;
			}
		}
	}

	pr->cvaddr += len;

	return 1;
}


static int read_pagemap_page(struct page_read *pr, unsigned long vaddr, int nr, void *buf)
{
	int ret;
	unsigned long len = nr * PAGE_SIZE;

	pr_info("pr%u Read %lx %u pages\n", pr->id, vaddr, nr);
	pagemap_bound_check(pr->pe, vaddr, nr);

	if (pr->pe->in_parent) {
		struct page_read *ppr = pr->parent;

		/*
		 * Parent pagemap at this point entry may be shorter
		 * than the current vaddr:nr needs, so we have to
		 * carefully 'split' the vaddr:nr into pieces and go
		 * to parent page-read with the longest requests it
		 * can handle.
		 */

		do {
			int p_nr;

			pr_debug("\tpr%u Read from parent\n", pr->id);
			ret = seek_pagemap_page(ppr, vaddr, true);
			if (ret <= 0)
				return -1;

			/*
			 * This is how many pages we have in the parent
			 * page_read starting from vaddr. Go ahead and
			 * read as much as we can.
			 */
			p_nr = ppr->pe->nr_pages - (vaddr - ppr->pe->vaddr) / PAGE_SIZE;
			pr_info("\tparent has %u pages in\n", p_nr);
			if (p_nr > nr)
				p_nr = nr;

			ret = read_pagemap_page(ppr, vaddr, p_nr, buf);
			if (ret == -1)
				return ret;

			/*
			 * OK, let's see how much data we have left and go
			 * to parent page-read again for the next pagemap
			 * entry.
			 */
			nr -= p_nr;
			vaddr += p_nr * PAGE_SIZE;
			buf += p_nr * PAGE_SIZE;
		} while (nr);
	} else {
		int fd = img_raw_fd(pr->pi);
		off_t current_vaddr = lseek(fd, 0, SEEK_CUR);

		pr_debug("\tpr%u Read page from self %lx/%"PRIx64"\n", pr->id, pr->cvaddr, current_vaddr);
		ret = read(fd, buf, len);

		if (ret != len) {
			pr_perror("Can't read mapping page %d", ret);
			return -1;
		}

		if (opts.auto_dedup) {
			ret = punch_hole(pr, current_vaddr, len, false);
			if (ret == -1) {
				return -1;
			}
		}
	}

	pr->cvaddr += len;

	return 1;
}

static void close_page_read(struct page_read *pr)
{
	int ret;

	if (pr->bunch.iov_len > 0) {
		ret = punch_hole(pr, 0, 0, true);
		if (ret == -1)
			return;

		pr->bunch.iov_len = 0;
	}

	if (pr->parent) {
		close_page_read(pr->parent);
		xfree(pr->parent);
	}

	close_image(pr->pmi);
	if (pr->pi)
		close_image(pr->pi);
}

static int try_open_parent(int dfd, int pid, struct page_read *pr, int pr_flags)
{
	int pfd, ret;
	struct page_read *parent = NULL;

	pfd = openat(dfd, CR_PARENT_LINK, O_RDONLY);
	if (pfd < 0 && errno == ENOENT)
		goto out;

	parent = xmalloc(sizeof(*parent));
	if (!parent)
		goto err_cl;

	ret = open_page_read_at(pfd, pid, parent, pr_flags);
	if (ret < 0)
		goto err_free;

	if (!ret) {
		xfree(parent);
		parent = NULL;
	}

	close(pfd);
out:
	pr->parent = parent;
	return 0;

err_free:
	xfree(parent);
err_cl:
	close(pfd);
	return -1;
}

int open_page_read_at(int dfd, int pid, struct page_read *pr, int pr_flags)
{
	int flags, i_typ, i_typ_o;
	static unsigned ids = 1;

	if (opts.auto_dedup)
		pr_flags |= PR_MOD;
	if (pr_flags & PR_MOD)
		flags = O_RDWR;
	else
		flags = O_RSTR;

	switch (pr_flags & PR_TYPE_MASK) {
	case PR_TASK:
		i_typ = CR_FD_PAGEMAP;
		i_typ_o = CR_FD_PAGES_OLD;
		break;
	case PR_SHMEM:
		i_typ = CR_FD_SHMEM_PAGEMAP;
		i_typ_o = CR_FD_SHM_PAGES_OLD;
		break;
	default:
		BUG();
		return -1;
	}

	pr->pe = NULL;
	pr->parent = NULL;
	pr->bunch.iov_len = 0;
	pr->bunch.iov_base = NULL;

	pr->pmi = open_image_at(dfd, i_typ, O_RSTR, (long)pid);
	if (!pr->pmi)
		return -1;

	if (empty_image(pr->pmi)) {
		close_image(pr->pmi);
		goto open_old;
	}

	if ((i_typ != CR_FD_SHMEM_PAGEMAP) && try_open_parent(dfd, pid, pr, pr_flags)) {
		close_image(pr->pmi);
		return -1;
	}

	pr->pi = open_pages_image_at(dfd, flags, pr->pmi);
	if (!pr->pi) {
		close_page_read(pr);
		return -1;
	}

	pr->get_pagemap = get_pagemap;
	pr->put_pagemap = put_pagemap;
	pr->read_pages = read_pagemap_page;
	pr->close = close_page_read;
	pr->id = ids++;

	pr_debug("Opened page read %u (parent %u)\n",
			pr->id, pr->parent ? pr->parent->id : 0);

	return 1;

open_old:
	pr->pmi = open_image_at(dfd, i_typ_o, flags, pid);
	if (!pr->pmi)
		return -1;

	if (empty_image(pr->pmi)) {
		close_image(pr->pmi);
		return 0;
	}

	pr->get_pagemap = get_page_vaddr;
	pr->put_pagemap = NULL;
	pr->read_pages = read_page;
	pr->pi = NULL;
	pr->close = close_page_read;

	return 1;
}

int open_page_read(int pid, struct page_read *pr, int pr_flags)
{
	return open_page_read_at(get_service_fd(IMG_FD_OFF), pid, pr, pr_flags);
}
