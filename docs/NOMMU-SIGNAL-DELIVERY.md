# NOMMU signal delivery incident

<!-- SPDX-License-Identifier: MIT -->

Signals were never delivered to any user process on this port. The defect was
introduced with the original NOMMU bring-up patch and stayed invisible because
the shipped services poll instead of relying on signal handlers. It surfaces
immediately as soon as a program installs a handler, most visibly in a BusyBox
shell: the shell exits the moment one of its children terminates.

## Symptom

Boot a full-rootfs image with a shell on the console, then run any external
command:

```text
~ # echo A; /bin/busybox true; echo B
A
<shell exits, getty respawns login>
```

`echo A` runs, the child runs and prints its own output, and then the shell is
gone with the exit status of the last command. `sleep 10 &` gives the clearest
reading: the shell survives exactly ten seconds, i.e. until the child exits.
No signal reaches the process, `atexit()` handlers do not run, an `EXIT` trap
does not fire, and the kernel logs nothing.

## Root cause

NOMMU user images execute in kernel mode, so `KU_USER` in the saved status word
cannot distinguish a return to userspace from a return to the kernel. The
bring-up patch replaced that test in `arch/mips/kernel/entry.S` with a fixed
address window:

```asm
	LONG_L	t0, PT_EPC(sp)
	li	t1, 0xfc000000
	and	t0, t1
	li	t1, 0x84000000
	bne	t0, t1, resume_kernel
```

The window describes the optional fixed ET_EXEC application window only. The
default userspace is static PIE, and `binfmt_elf_nommu` places those images
wherever `vm_mmap()` finds room. Measured on a 128 MiB board:

```text
ELFDBG init:  maddr=82600000 bias=82600000 entry=826039e0
ELFDBG mount: maddr=82700000 bias=82700000 entry=827039e0
RETDBG comm=mount epc=82707be8 status=00008c03 range=02700000-027cb000
```

No process ever satisfied the test, so every exception frame was classified as
a kernel return, `work_pending` was skipped, and `do_notify_resume()` — and
with it `get_signal()` — never ran.

The consequences follow from that one branch:

- signals are queued and never dequeued, so `signal_pending()` stays true for
  the lifetime of the process;
- every interruptible syscall then returns `-ERESTARTSYS`, which nothing ever
  restarts, so the process silently loses its I/O;
- a shell whose console read fails exits with the status of the last command,
  which is why the failure looked like a shell bug rather than a kernel one.

Instrumentation used to establish this: a print in `send_signal_locked()` shows
signals being queued (`send sig=18 -> comm=sh`), while prints in `get_signal()`
and `do_notify_resume()` never fire for the whole boot.

## Fix

`patches/linux-7.1.4/0033-sf2000-nommu-signal-delivery.patch`:

- `struct thread_info` gains `user_start` and `user_end`, with matching entries
  in `arch/mips/kernel/asm-offsets.c`;
- `fs/binfmt_elf_nommu.c` publishes the physical range of the image it just
  placed before handing off to `start_thread()` — the `vm_mmap()` allocation
  for static PIE, the fixed window for ET_EXEC;
- both sites in `arch/mips/kernel/entry.S` compare `EPC & 0x1fffffff` against
  that range instead of the fixed window.

Masking the address makes the KSEG0, KSEG1 and identity aliases of one image
compare equal, which matters because the loader hands off through
`CPHYSADDR()` while exception frames record the KSEG0 form. Kernel text lies
outside every user range, and a task that never ran a user image keeps a zero
range that no address can fall into, so kernel threads stay classified as
kernel returns.

The NOMMU signal trampoline (`install_nommu_sigtramp()`, written into the
`sf_pad`/`rs_pad` words of the frame) was already correct; tracing shows the
complete `deliver -> frame -> sigreturn` cycle once delivery happens at all.

## Verification

Guest probes (sources kept out of tree, described here so they can be
recreated):

- a static-PIE program that installs a handler and calls `raise()` dies before
  the handler runs on the unfixed kernel, and completes both the plain and the
  `SA_SIGINFO` handler on the fixed one;
- `sleep 10 &` followed by shell commands at 0 s and 14 s: the shell stays
  alive and reports the job as `Done`;
- external commands, pipelines, `mount`, `uname` and `/proc` reads run
  repeatedly in one shell session.

Project gates, all on the fixed kernel:

- `make check` — pass;
- `make ROOTFS=full smoke-linux-full-asd` — pass;
- full series applies to a freshly extracted tree, kernel builds clean;
- normal product path (`init=/init`) boots to `sf2000-mount: mount ok`,
  `sf2000-powerd: frontend launch`, `sf2000-browser: ready`, and launches a
  libretro core with a correct first frame.

Rollback point: dropping the patch file restores the previous behaviour
exactly; nothing outside the patch was changed.

## Ruled out during the investigation

Recorded so the same ground is not covered twice. None of these reproduce the
failure, each was tested in the guest:

- `vfork()`/`execve()`/`waitpid()` in isolation, including the exact shape of
  BusyBox `libbb/spawn()` and the `waitpid(-1, WUNTRACED)` flavour;
- job control in the child (`setpgid()` plus `tcsetpgrp()`);
- allocations by the child on the shared NOMMU heap, and a parent holding many
  separate allocations;
- parent image size, and a child that execs the same file as its parent;
- BusyBox compiler flags (`-Oz`, `-fomit-frame-pointer`) and
  `CONFIG_BUSYBOX_EXEC_PATH`;
- `CONFIG_HUSH_JOB`, and replacing hush's `vfork()` with `clone()` on a private
  stack, both with and without `CLONE_VFORK`.

BusyBox `init` never showed the failure because it does not install signal
handlers; the project's own init spawns services with a raw `clone()` and polls
for their state, so it never depended on signal delivery either.

## Storage service under BusyBox init

`userspace/rootfs-overlay/etc/init.d/S05sf2000-storage` used to run
`exec /usr/sbin/sf2000-mount`, which never returns because the mount service is
an endless hotplug loop; under BusyBox `init` that blocked `rcS` forever. It
never showed before because the shell running `rcS` was killed by the defect
above, which let `init` continue to `getty`. The script now backgrounds the
service and gained the `stop` case the neighbouring scripts have, so both entry
points work: the project's own init still spawns the binary itself, and `rcS`
reaches `sf2000_rcS: done` with the card mounted at `/mnt/sd`.

## Watchdog handling for init implementations other than our own

The loader arms a 20-second watchdog before entering the kernel, and the
project's own init clears it from `early_watchdog_disable()` as soon as
userspace is alive. An init that only runs the `/etc/init.d` scripts has no
equivalent step, so the board used to reset in the middle of a console
session.

`userspace/sf2000-wdt.c` is a ~70-line static-PIE utility installed as
`/usr/sbin/sf2000-wdt`. It writes the same two registers in the same order as
init - clear the counter at `0x18818500`, then the configuration byte at
`0x18818504` - and falls back to the uncached KSEG1 alias exactly like init
does when `/dev/mem` is unavailable, which it always is because
`CONFIG_DEVMEM` is off. `S00sf2000` calls it before anything else starts, so
any init that runs the scripts in the usual way gets the same guarantee and
BusyBox itself needs no patching.

Services that arm a watchdog of their own are untouched by this: the display
service keeps arming, petting and disarming its 8-second runtime watchdog
around its draw loop and its pause handshake.

Verified with BusyBox init: `sf2000_rcS: done`, a single loader start after 90
seconds of idle console (previously the log showed repeated restarts), and a
shell session that still runs external commands afterwards. The normal
`init=/init` image is unchanged and keeps logging
`sf2000_userspace: early watchdog disabled`.
