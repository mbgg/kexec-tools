#include <stdio.h>
#include <string.h>
#include "kexec.h"

/* Retrieve kernel symbol virtual address from /proc/kallsyms */
unsigned long long get_kernel_sym(const char *text)
{
	const char *kallsyms = "/proc/kallsyms";
	char sym[128];
	char line[128];
	FILE *fp;
	unsigned long long vaddr = 0;
	char type;

	fp = fopen(kallsyms, "r");
	if (!fp) {
		fprintf(stderr, "Cannot open %s\n", kallsyms);
		return 0;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		unsigned long long addr;

		if (sscanf(line, "%Lx %c %s", &addr, &type, sym) != 3)
			continue;

		if (strcmp(sym, text) == 0) {
			dbgprintf("kernel symbol %s vaddr = %#llx\n",
								text, addr);
			vaddr = addr;
			break;
		}
	}

	fclose(fp);

	if (vaddr == 0)
		fprintf(stderr, "Cannot get kernel %s symbol address\n", text);

	return vaddr;
}
