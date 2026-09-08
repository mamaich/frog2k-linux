# NOMMU /proc process access hang

<!-- SPDX-License-Identifier: MIT -->

Reading another process's command line froze the board until the watchdog reset
it. `ps` does that for every entry it lists, so the whole tool was unusable and
took the system down with it.

## Symptom

With `/proc` mounted, from a console shell:

```text
~ # ps
  PID USER       VSZ STAT COMMAND
<no further output, the machine stops responding, watchdog reset follows>
```

`ps` printed its header and hung on the first process. Narrowing it down by
reading the files by hand shows the exact one:

```text
~ # cat /proc/1/cmdline
<hangs>
```

## Root cause

`get_mm_cmdline()` reaches into the target process with
`access_remote_vm()`. The NOMMU implementation in `mm/nommu.c` copies straight
through the target mapping, so it has no `struct page` to hand over and passes
`NULL`:

```c
copy_from_user_page(vma, NULL, addr, buf, (void *) addr, len);
```

Both MIPS helpers in `arch/mips/mm/init.c` open with `page_folio(page)` and
then work on that folio. With a NULL page that walks a `struct page` at a
small fixed offset from address zero, which on this NOMMU board is ordinary
RAM rather than a fault, so the result is a plausible-looking garbage folio
that the cache-alias path then follows.

Instrumenting `get_mm_cmdline()` shows the read never returns:

```text
CMDDBG arg=8267cf8b-8267cfa1 env=8267cfa1-8267cfd6
CMDDBG probing last argv byte at 8267cfa0
<nothing further>
```

The values themselves are fine - that range is the argv area the ELF loader
built inside init's image - so the defect is in the copy helper, not in what
the loader recorded.

Upstream never hits this because MIPS has no NOMMU support there, so the
combination of `mm/nommu.c` and `arch/mips/mm/init.c` does not exist.

## Fix

`patches/linux-7.1.4/0034-sf2000-nommu-user-page-copy.patch` gives both helpers
a NULL-page path that copies by address. There is no page cache to keep
coherent in that case; `copy_to_user_page()` still flushes the icache by range
for executable mappings, which is what the ptrace and uprobe callers need.

## Verification

```text
~ # cat /proc/1/cmdline
/usr/sbin/sf2000-init
~ # ps
  PID USER       VSZ STAT COMMAND
    1 root       244 S    /usr/sbin/sf2000-init
    2 root         0 SW   [kthreadd]
    ...
```

The shell survives, the application keeps running, and the series applies to a
freshly extracted tree. `make check` and `make ROOTFS=full smoke-linux-full-asd`
pass.

Rollback: delete the patch file; nothing else depends on it.
