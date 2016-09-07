/*
 * ARM64 crashdump.
 *     partly derived from arm implementation
 *
 * Copyright (c) 2014-2016 Linaro Limited
 * Author: AKASHI Takahiro <takahiro.akashi-QSEj5FYQhm4dnm+yROfE0A@public.gmane.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stdlib.h>
#include <linux/elf.h>

#include "kexec.h"
#include "crashdump.h"
#include "crashdump-arm64.h"
#include "iomem.h"
#include "kexec-arm64.h"
#include "kexec-elf.h"
#include "libfdt.h"
#include "mem_regions.h"

/* memory ranges on crashed kernel */
static struct memory_range crash_memory_ranges[CRASH_MAX_MEMORY_RANGES];
struct memory_ranges crash_memory_rgns = {
	.size = 0,
	.max_size = CRASH_MAX_MEMORY_RANGES,
	.ranges = crash_memory_ranges,
};

/* memory range reserved for crashkernel */
struct memory_range crash_reserved_mem;
struct memory_ranges usablemem_rgns = {
	.size = 0,
	.max_size = 1,
	.ranges = &crash_reserved_mem,
};

struct memory_range elfcorehdr_mem;

static struct crash_elf_info elf_info = {
	.class		= ELFCLASS64,
#if (__BYTE_ORDER == __LITTLE_ENDIAN)
	.data		= ELFDATA2LSB,
#else
	.data		= ELFDATA2MSB,
#endif
	.machine	= EM_AARCH64,
};

/*
 * Note: The returned value is correct only if !CONFIG_RANDOMIZE_BASE.
 */
static uint64_t get_kernel_page_offset(void)
{
	int i;

	if (elf_info.kern_vaddr_start == UINT64_MAX)
		return UINT64_MAX;

	/* Current max virtual memory range is 48-bits. */
	for (i = 48; i > 0; i--)
		if (!(elf_info.kern_vaddr_start & (1UL << i)))
			break;

	if (i <= 0)
		return UINT64_MAX;
	else
		return UINT64_MAX << i;
}

/*
 * iomem_range_callback() - callback called for each iomem region
 * @data: not used
 * @nr: not used
 * @str: name of the memory region
 * @base: start address of the memory region
 * @length: size of the memory region
 *
 * This function is called once for each memory region found in /proc/iomem.
 * It locates system RAM and crashkernel reserved memory and places these to
 * variables, respectively, crash_memory_ranges and crash_reserved_mem.
 */

static int iomem_range_callback(void *UNUSED(data), int UNUSED(nr),
				char *str, unsigned long long base,
				unsigned long long length)
{
	if (strncmp(str, CRASH_KERNEL, strlen(CRASH_KERNEL)) == 0)
		return mem_regions_add(&usablemem_rgns,
				       base, length, RANGE_RAM);
	else if (strncmp(str, SYSTEM_RAM, strlen(SYSTEM_RAM)) == 0)
		return mem_regions_add(&crash_memory_rgns,
				       base, length, RANGE_RAM);
	else if (strncmp(str, KERNEL_CODE, strlen(KERNEL_CODE)) == 0)
		elf_info.kern_paddr_start = base;
	else if (strncmp(str, KERNEL_DATA, strlen(KERNEL_DATA)) == 0)
		elf_info.kern_size = base + length - elf_info.kern_paddr_start;

	return 0;
}

int is_crashkernel_mem_reserved(void)
{
	if (!crash_reserved_mem.end)
		kexec_iomem_for_each_line(NULL, iomem_range_callback, NULL);

	return crash_reserved_mem.start != crash_reserved_mem.end;
}

/*
 * crash_get_memory_ranges() - read system physical memory
 *
 * Function reads through system physical memory and stores found memory
 * regions in crash_memory_ranges.
 * Regions are sorted in ascending order.
 *
 * Returns 0 in case of success and -1 otherwise (errno is set).
 */
static int crash_get_memory_ranges(void)
{
	/*
	 * First read all memory regions that can be considered as
	 * system memory including the crash area.
	 */
	if (!usablemem_rgns.size)
		kexec_iomem_for_each_line(NULL, iomem_range_callback, NULL);

	/* allow only a single region for crash dump kernel */
	if (usablemem_rgns.size != 1) {
		errno = EINVAL;
		return -1;
	}

	dbgprint_mem_range("Reserved memory range", &crash_reserved_mem, 1);

	if (mem_regions_exclude(&crash_memory_rgns, &crash_reserved_mem)) {
		fprintf(stderr,
			"Error: Number of crash memory ranges excedeed the max limit\n");
		errno = ENOMEM;
		return -1;
	}

	/*
	 * Make sure that the memory regions are sorted.
	 */
	mem_regions_sort(&crash_memory_rgns);

	dbgprint_mem_range("Coredump memory ranges",
			   crash_memory_rgns.ranges, crash_memory_rgns.size);

	/*
	 * For additional kernel code/data segment.
	 * kern_paddr_start/kern_size are determined in iomem_range_callback
	 */
	elf_info.kern_vaddr_start = get_kernel_sym("_text");
	if (!elf_info.kern_vaddr_start)
		elf_info.kern_vaddr_start = UINT64_MAX;

	return 0;
}

/*
 * load_crashdump_segments() - load the elf core header
 * @info: kexec info structure
 *
 * This function creates and loads an additional segment of elf core header
 : which is used to construct /proc/vmcore on crash dump kernel.
 *
 * Return 0 in case of success and -1 in case of error.
 */

int load_crashdump_segments(struct kexec_info *info)
{
	unsigned long elfcorehdr;
	unsigned long bufsz;
	void *buf;
	int err;

	/*
	 * First fetch all the memory (RAM) ranges that we are going to
	 * pass to the crash dump kernel during panic.
	 */

	err = crash_get_memory_ranges();

	if (err)
		return err;

	elf_info.page_offset = get_kernel_page_offset();
	dbgprintf("%s: page_offset:   %016llx\n", __func__,
			elf_info.page_offset);

	err = crash_create_elf64_headers(info, &elf_info,
			crash_memory_rgns.ranges, crash_memory_rgns.size,
			&buf, &bufsz, ELF_CORE_HEADER_ALIGN);

	if (err)
		return err;

	elfcorehdr = add_buffer_phys_virt(info, buf, bufsz, bufsz, 0,
		crash_reserved_mem.start, crash_reserved_mem.end,
		-1, 0);

	elfcorehdr_mem.start = elfcorehdr;
	elfcorehdr_mem.end = elfcorehdr + bufsz - 1;

	dbgprintf("%s: elfcorehdr 0x%llx-0x%llx\n", __func__,
			elfcorehdr_mem.start, elfcorehdr_mem.end);

	return 0;
}

/*
 * e_entry and p_paddr are actually in virtual address space.
 * Those values will be translated to physcal addresses by
 * using virt_to_phys().
 * So let's get ready for later use so the memory base (phys_offset)
 * will be correctly replaced with crash_reserved_mem.start.
 */
void modify_ehdr_for_crashdump(struct mem_ehdr *ehdr)
{
	struct mem_phdr *phdr;
	int i;

	ehdr->e_entry += - arm64_mem.phys_offset + crash_reserved_mem.start;

	for (i = 0; i < ehdr->e_phnum; i++) {
		phdr = &ehdr->e_phdr[i];
		if (phdr->p_type != PT_LOAD)
			continue;
		phdr->p_paddr +=
			(-arm64_mem.phys_offset + crash_reserved_mem.start);
	}
}

static int dtb_add_reserved_memory(void *dtb_buf)
{
	int nodeoffset, rsvmem_node;
	uint32_t cell_size;
	uint64_t range[2];
	char name[30];
	int i, result = 0;

	rsvmem_node = fdt_path_offset(dtb_buf, "reserved-memory");
	if (rsvmem_node < 0) {
		nodeoffset = fdt_path_offset(dtb_buf, "/");
		rsvmem_node = fdt_add_subnode(dtb_buf, nodeoffset,
						"reserved-memory");
		if (rsvmem_node < 0) {
			result = rsvmem_node;
			goto on_error;
		}

		cell_size = cpu_to_fdt32(2);
		fdt_setprop(dtb_buf, rsvmem_node, "#address-cells",
						&cell_size, sizeof(cell_size));
		fdt_setprop(dtb_buf, rsvmem_node, "#size-cells",
						&cell_size, sizeof(cell_size));
		fdt_setprop(dtb_buf, rsvmem_node, "ranges", NULL, 0);
	}

	for (i = 0; i < crash_memory_rgns.size; i++) {
		sprintf(name, "crash_dump@%llx",
					crash_memory_rgns.ranges[i].start);
		nodeoffset = fdt_add_subnode(dtb_buf, rsvmem_node, name);
		if (nodeoffset < 0) {
			result = nodeoffset;
			goto on_error;
		}

		range[0] = cpu_to_fdt64(crash_memory_rgns.ranges[i].start);
		range[1] = cpu_to_fdt64(crash_memory_rgns.ranges[i].end
					- crash_memory_rgns.ranges[i].start + 1);
		fdt_setprop(dtb_buf, nodeoffset, "reg", &range, sizeof(range));
		fdt_setprop(dtb_buf, nodeoffset, "no-map", NULL, 0);
	}

on_error:
	return result;
}

/*
 * Increased size for extra properties:
 * - linux,elfcorehdr
 *      linux,elfcoredhr = <base, size>;
 * - reserved-memory node
 *      reserved-memory {
 *         #address-cells = <2>;
 *         #size-cells = <2>;
 *         ranges;
 *         crash_dump@xx {
 *            reg = <base, size>;
 *            no-map;
 *         };
 *         ...
 *      }
 */
#define DTB_ELFCOREHDR_PROP_SIZE \
		 (sizeof(struct fdt_property)		\
		+ FDT_TAGALIGN(sizeof(uint64_t) * 2)	\
		+ strlen("linux,elfcorehdr") + 1)
#define DTB_RESVMEM_NODE_SIZE \
		 (sizeof(struct fdt_node_header)	\
		+ strlen("reserved-memory") + 1		\
		+ sizeof(struct fdt_property)		\
		+ FDT_TAGALIGN(sizeof(uint32_t))	\
		+ strlen("#address-cells") + 1		\
		+ sizeof(struct fdt_property)		\
		+ FDT_TAGALIGN(sizeof(uint32_t))	\
		+ strlen("#size-cells") + 1		\
		+ sizeof(struct fdt_property)		\
		+ strlen("ranges") + 1)
#define DTB_RESVMEM_SUBNODE_SIZE \
		 (sizeof(struct fdt_node_header)	\
		+ strlen("crash_dump@xxxxxxxxxxxxxxxx") + 1	\
		+ sizeof(struct fdt_property)		\
		+ FDT_TAGALIGN(sizeof(uint64_t) * 2)	\
		+ strlen("reg") + 1			\
		+ sizeof(struct fdt_property)	\
		+ strlen("no-map") + 1)

void *fixup_memory_properties(void *dtb_buf)
{
	char *new_buf;
	int new_size;
	uint64_t range[2];
	int nodeoffset;
	int result;

	new_size = fdt_totalsize(dtb_buf)
		   + DTB_ELFCOREHDR_PROP_SIZE
		   + DTB_RESVMEM_NODE_SIZE
		   + DTB_RESVMEM_SUBNODE_SIZE * crash_memory_rgns.size;

	new_buf = xmalloc(new_size);
	result = fdt_open_into(dtb_buf, new_buf, new_size);
	if (result) {
		dbgprintf("%s: fdt_open_into failed: %s\n", __func__,
						fdt_strerror(result));
		result = -EFAILED;
		goto on_error;
	}

	range[0] = cpu_to_fdt64(elfcorehdr_mem.start);
	range[1] = cpu_to_fdt64(elfcorehdr_mem.end - elfcorehdr_mem.start + 1);
	nodeoffset = fdt_path_offset(new_buf, "/chosen");
	result = fdt_setprop(new_buf, nodeoffset, "linux,elfcorehdr",
						(void *)range, sizeof(range));
	if (result) {
		dbgprintf("%s: fdt_setprop failed: %s\n", __func__,
						fdt_strerror(result));
		goto on_error;
	}

	result = dtb_add_reserved_memory(new_buf);
	if (result) {
		dbgprintf("%s: adding reserved-memory failed: %s\n", __func__,
						fdt_strerror(result));
		result = -EFAILED;
		goto on_error;
	}

	fdt_pack(new_buf);

	return new_buf;

on_error:
	if (new_buf)
		free(new_buf);
	return NULL;
}
