// SPDX-License-Identifier: MIT

/*
 * Disable the HC15xx hardware watchdog from an init script.
 *
 * The loader arms a watchdog before it jumps into the kernel, and the
 * project's own init clears it as soon as userspace is alive
 * (early_watchdog_disable() in userspace/sf2000-init.c).  A boot driven by
 * BusyBox init - or by any other init that only runs the /etc/init.d scripts -
 * has no equivalent step, so the board resets while the console session is
 * still up.
 *
 * This mirrors init's register contract exactly: clear the counter first, then
 * the configuration byte.  Services that arm a watchdog of their own, such as
 * the display service, keep managing and petting it themselves.
 */

#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define WDT_BASE_PHYS 0x18818000u
#define WDT_MAP_SIZE 0x1000u
#define WDT_REG_OFF 0x500u
#define WDT_COUNT_OFF 0x00u
#define WDT_CONF_OFF 0x04u
#define KSEG1ADDR(x) ((volatile uint8_t *)((uintptr_t)(x) | 0xa0000000u))

static volatile uint8_t *wdt_map(void)
{
	volatile uint8_t *base;
	int fd;

	/*
	 * CONFIG_DEVMEM is disabled in the shipped kernel, so this normally
	 * falls through to the uncached alias.  Init keeps the same fallback.
	 */
	fd = open("/dev/mem", O_RDWR);
	if (fd < 0)
		return KSEG1ADDR(WDT_BASE_PHYS);

	base = mmap(NULL, WDT_MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
		    fd, WDT_BASE_PHYS);
	close(fd);
	if (base == MAP_FAILED)
		return KSEG1ADDR(WDT_BASE_PHYS);
	return base;
}

int main(int argc, char **argv)
{
	volatile uint8_t *wdt;

	if (argc > 1 && strcmp(argv[1], "disable") != 0) {
		static const char usage[] = "usage: sf2000-wdt [disable]\n";

		(void)write(2, usage, sizeof(usage) - 1u);
		return 2;
	}

	wdt = wdt_map();
	*(volatile uint32_t *)(wdt + WDT_REG_OFF + WDT_COUNT_OFF) = 0u;
	*(volatile uint8_t *)(wdt + WDT_REG_OFF + WDT_CONF_OFF) = 0u;
	return 0;
}
