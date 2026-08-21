/*
 * SF2000 QEMU diagnostic cache model.
 *
 * This is deliberately a measurement plugin, not a replacement for the
 * machine's CP0 cache description.  QEMU's TCG wall clock measures host
 * translation speed and does not model the HC15xx pipeline, so this plugin
 * records target-like instruction and L1 cache costs while the same guest
 * workload is running.  Results are flushed to a file periodically so a
 * benchmark stopped with the QEMU monitor still leaves usable samples.
 */

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* Bump this whenever the machine-readable report fields change.  The report
 * checker in tools/qemu/check-cache-model-report.awk deliberately accepts only
 * this schema so a positional printf edit cannot silently poison comparisons. */
#define CACHE_MODEL_REPORT_VERSION 14

typedef struct {
    uint64_t *tags;
    uint32_t *ages;
    unsigned char *valid;
    size_t sets;
    size_t ways;
    unsigned int line_shift;
    unsigned int set_shift;
    uint64_t tick;
} Cache;

typedef struct {
    uint64_t pc;
    uint32_t opcode;
    unsigned char class_id;
    uint64_t executions;
    uint64_t i_misses;
    uint64_t d_accesses;
    uint64_t d_misses;
    uint64_t first_d_miss_address;
    uint64_t last_d_miss_address;
    uint64_t first_d_miss_vaddr;
    uint64_t last_d_miss_vaddr;
} HotspotEntry;

enum InsnClass {
    INSN_OTHER,
    INSN_BRANCH,
    INSN_JUMP,
    INSN_LOAD,
    INSN_STORE,
    INSN_MULDIV,
    INSN_COP2,
    INSN_CLASS_COUNT
};

/* The QPSX static GTE implementation is one of the few large, repeatedly
 * entered helper islands in the core text.  COP2 is not visible to this
 * plugin: the dynarec calls these C functions directly, so the guest COP2
 * opcode counter is zero even though the GTE is busy.
 *
 * The entries are populated only by an explicit gtemap= file.  In particular,
 * do not put linker addresses in this source: a GTE specialization changes
 * the complete downstream layout and would otherwise make the oracle count
 * unrelated code while appearing healthy.  The map header records the exact
 * core base/size and a SHA-256 of coreelf=; installation rejects a mismatch.
 * This is intentionally a diagnostic map, not a guessed replacement for the
 * target's cycle counter.
 */
enum GteOp {
    GTE_RTPS,
    GTE_RTPT,
    GTE_MVMVA,
    GTE_NCLIP,
    GTE_AVSZ3,
    GTE_AVSZ4,
    GTE_SQR,
    GTE_NCCS,
    GTE_NCCT,
    GTE_NCDS,
    GTE_NCDT,
    GTE_OP,
    GTE_DCPL,
    GTE_GPF,
    GTE_GPL,
    GTE_DPCS,
    GTE_DPCT,
    GTE_NCS,
    GTE_NCT,
    GTE_CC,
    GTE_INTPL,
    GTE_CDP,
    GTE_OP_COUNT
};

typedef struct {
    uint32_t offset;
    uint32_t size;
    unsigned char work;
    const char *name;
} GteSite;

typedef struct {
    uint32_t offset;
    uint32_t size;
    unsigned char operation;
    unsigned char work;
} GteRange;

/* Work is a relative operation-unit metric.  RTPT/NCCT/NCDT/NCT/DPCT are
 * three-vector operations; the remaining weights deliberately stay at one.
 * Do not add this uncalibrated quantity to est_cycles: static instructions
 * and cache costs already account for their actual emitted code. */
static const GteSite gte_operations[GTE_OP_COUNT] = {
    { 0, 0, 1, "rtps" }, { 0, 0, 3, "rtpt" },
    { 0, 0, 1, "mvmva" }, { 0, 0, 1, "nclip" },
    { 0, 0, 1, "avsz3" }, { 0, 0, 1, "avsz4" },
    { 0, 0, 1, "sqr" }, { 0, 0, 1, "nccs" },
    { 0, 0, 3, "ncct" }, { 0, 0, 1, "ncds" },
    { 0, 0, 3, "ncdt" }, { 0, 0, 1, "op" },
    { 0, 0, 1, "dcpl" }, { 0, 0, 1, "gpf" },
    { 0, 0, 1, "gpl" }, { 0, 0, 1, "dpcs" },
    { 0, 0, 3, "dpct" }, { 0, 0, 1, "ncs" },
    { 0, 0, 3, "nct" }, { 0, 0, 1, "cc" },
    { 0, 0, 1, "intpl" }, { 0, 0, 1, "cdp" }
};

#define GTE_MAX_RANGES 127
static GteRange gte_ranges[GTE_MAX_RANGES];
static size_t gte_range_count;

/* Zero means no GTE body; the low seven bits otherwise contain op + 1.  The
 * high bit marks an exact function entry, allowing one byte per TB instruction
 * to represent both call counts and body instruction/cache costs.  The low
 * bits identify a range (not an operation), so multiple specialized ranges
 * can aggregate into one architectural operation. */
#define GTE_ID_NONE 0
#define GTE_ID_ENTRY 0x80

typedef struct MemData MemData;
typedef struct TranslationBlock TranslationBlock;

struct TranslationBlock {
    uint64_t *pc;
    unsigned char *class_id;
    unsigned char *gte_id;
    HotspotEntry **hot;
    MemData **mem;
    size_t count;
    size_t rec_count;
    TranslationBlock *next;
};

struct MemData {
    HotspotEntry *hot;
    uint64_t pc;
    unsigned char gte_id;
};

typedef struct {
    Cache icache;
    Cache dcache;
    FILE *out;
    char label[96];
    uint64_t instructions;
    uint64_t i_accesses;
    uint64_t i_misses;
    uint64_t d_accesses;
    uint64_t d_lines;
    uint64_t d_bytes;
    uint64_t d_size_counts[4];
    uint64_t d_misses;
    uint64_t i_invalidations;
    uint64_t rec_i_invalidations;
    uint64_t stores;
    uint64_t mmio;
    uint64_t sample;
    uint64_t next_sample;
    uint64_t sample_no;
    uint64_t previous_instructions;
    uint64_t previous_i_misses;
    uint64_t previous_d_misses;
    uint64_t previous_estimated_cycles;
    uint64_t instruction_penalty;
    uint64_t data_penalty;
    uint64_t insn_classes[INSN_CLASS_COUNT];
    uint64_t rec_base;
    uint64_t rec_end;
    uint64_t rec_configured_base;
    uint64_t rec_base_evidence_pc;
    uint64_t core_base;
    uint64_t core_end;
    int rec_base_auto;
    int rec_base_was_auto;
    int rec_base_discovered;
    int rec_base_mismatch;
    int gte_enabled;
    uint64_t gte_map_hits;
    uint64_t gte_entries;
    uint64_t gte_map_entries;
    char gte_map_path[PATH_MAX];
    char gte_core_elf[PATH_MAX];
    char gte_core_sha256[65];
    uint64_t gte_instructions;
    uint64_t gte_i_misses;
    uint64_t gte_d_accesses;
    uint64_t gte_d_lines;
    uint64_t gte_d_misses;
    uint64_t gte_counts[GTE_OP_COUNT];
    uint64_t gte_work;
    int core_only;
    int emu_only;
    uint64_t rec_i_accesses;
    uint64_t rec_i_misses;
    uint64_t rec_d_accesses;
    uint64_t rec_d_lines;
    uint64_t rec_d_bytes;
    uint64_t rec_d_size_counts[4];
    uint64_t rec_d_misses;
    uint64_t rec_insn_classes[INSN_CLASS_COUNT];
    uint64_t rec_tb_execs;
    uint64_t rec_unique_lines;
    uint64_t rec_pc_low;
    uint64_t rec_pc_high;
    unsigned char *rec_line_bits;
    size_t rec_line_count;
    int d_vipt;
    int i_vipt;
    int rec_only;
    int phase_rec;
    int phase_active;
    uint32_t frame_opcode;
    uint64_t frame_number;
    uint64_t frame_report_period;
    uint64_t frame_stop;
    uint64_t frame_previous_cycles;
    uint64_t frame_cycle_sum;
    uint64_t frame_cycle_values[4096];
    uint64_t frame_gte_work_sum;
    uint64_t frame_gte_work_values[4096];
    uint64_t frame_previous_gte_work;
    size_t frame_cycle_count;
    int frame_have_previous;
    int frame_frozen;
    int have_previous;
    HotspotEntry *hot_table;
    size_t hot_capacity;
    char hot_path[PATH_MAX];
    TranslationBlock *translation_blocks;
    uint64_t translation_block_count;
    uint64_t memdata_count;
} Model;

static Model model;

static enum InsnClass classify_mips32(uint32_t opcode)
{
    unsigned int major = opcode >> 26;
    unsigned int funct = opcode & 0x3f;

    if (major == 0) {
        switch (funct) {
        case 0x08: /* JR */
        case 0x09: /* JALR */
            return INSN_JUMP;
        case 0x18: /* MULT */
        case 0x19: /* MULTU */
        case 0x1a: /* DIV */
        case 0x1b: /* DIVU */
        case 0x10: /* MFHI */
        case 0x11: /* MTHI */
        case 0x12: /* MFLO */
        case 0x13: /* MTLO */
            return INSN_MULDIV;
        default:
            return INSN_OTHER;
        }
    }
    if (major == 1 || (major >= 4 && major <= 7)) {
        return INSN_BRANCH;
    }
    if (major == 2 || major == 3) {
        return INSN_JUMP;
    }
    if (major == 0x12) {
        return INSN_COP2;
    }
    if ((major >= 0x20 && major <= 0x27) ||
        (major >= 0x30 && major <= 0x37)) {
        return INSN_LOAD;
    }
    if ((major >= 0x28 && major <= 0x2f) ||
        (major >= 0x38 && major <= 0x3f)) {
        return INSN_STORE;
    }
    return INSN_OTHER;
}

static uint64_t ratio_ppm(uint64_t numerator, uint64_t denominator)
{
    if (!denominator) {
        return 0;
    }
    /* The counters are below 2^63 for the workloads of interest.  Divide
     * first for very large synthetic runs so diagnostics cannot overflow. */
    if (numerator > UINT64_MAX / 1000000) {
        return (numerator / denominator) * 1000000 +
               ((numerator % denominator) * 1000000) / denominator;
    }
    return (numerator * 1000000) / denominator;
}

static int pc_is_rec_code(uint64_t pc)
{
    return pc >= model.rec_base && pc < model.rec_end;
}

/* The QPSX core is loaded as a fixed-base NOMMU PIE by the frontend.  Its
 * executable PT_LOAD is below the generated recRAM window (0x832xxxxx), so a
 * core-only pass can measure the static emulator/raster code without paying
 * for every Linux/helper instruction.  Keep this predicate separate from
 * pc_is_rec_code(): generated PSX blocks and the core's C/assembly text are
 * two different optimization surfaces. */
static int pc_is_core_code(uint64_t pc)
{
    return pc >= model.core_base && pc < model.core_end;
}

static unsigned char gte_id_for_pc(uint64_t pc)
{
    uint64_t offset;
    size_t index;

    if (!model.gte_enabled || !pc_is_core_code(pc) ||
        pc < model.core_base) {
        return GTE_ID_NONE;
    }
    offset = pc - model.core_base;
    for (index = 0; index < gte_range_count; index++) {
        const GteRange *range = &gte_ranges[index];

        if (offset >= range->offset &&
            offset < (uint64_t)range->offset + range->size) {
            unsigned char id = (unsigned char)(index + 1);

            if (offset == range->offset) {
                id |= GTE_ID_ENTRY;
            }
            return id;
        }
    }
    return GTE_ID_NONE;
}

static int pc_is_selected(uint64_t pc)
{
    if (model.emu_only) {
        return pc_is_core_code(pc) || pc_is_rec_code(pc);
    }
    if (model.core_only) {
        return pc_is_core_code(pc);
    }
    if (model.rec_only) {
        return pc_is_rec_code(pc);
    }
    return 1;
}

static const char *scope_label(void)
{
    if (model.emu_only) {
        return "emu";
    }
    if (model.core_only) {
        return "core";
    }
    return model.rec_only ? "rec" : "all";
}

static const char *coverage_label(void)
{
    if (model.emu_only) {
        return model.phase_rec ? "core+rec-post-rec" : "core+rec";
    }
    if (model.core_only) {
        return "core-text";
    }
    if (!model.phase_rec) {
        return "full";
    }
    return model.rec_only ? "rec-only" : "post-rec-late";
}

static const char *rec_base_status(void)
{
    if (model.rec_base_mismatch) {
        return "mismatch";
    }
    if (!model.rec_base_evidence_pc) {
        return "no-evidence";
    }
    if (model.rec_base_was_auto) {
        return "auto-first-rec-tb";
    }
    return "configured-validated";
}

static void rec_base_mismatch(const char *reason, uint64_t pc)
{
    if (!model.rec_base_mismatch) {
        fprintf(stderr,
                "sf2000-cache-model: recbase mismatch (%s) pc=0x%016" PRIx64
                " configured=0x%016" PRIx64 " size=0x%016" PRIx64 "\n",
                reason, pc, model.rec_base,
                model.rec_end - model.rec_base);
    }
    model.rec_base_mismatch = 1;
}

/* The QPSX Linux recompiler initializes recMem to the first emitted block and
 * then executes that block.  In auto mode the first executable TB in the
 * dedicated 0x832xxxxx allocator window is therefore stronger runtime
 * evidence than a guessed 1 MiB alignment.  Keep the broad window only as a
 * discovery guard; after the first TB, classify using the exact observed PC.
 * Explicit recbase= values remain authoritative and are checked against the
 * same runtime evidence. */
#define REC_DISCOVERY_BASE UINT64_C(0x83200000)
#define REC_DISCOVERY_END  UINT64_C(0x84000000)

static void rec_base_observe(uint64_t pc)
{
    if (!model.rec_base_evidence_pc) {
        model.rec_base_evidence_pc = pc;
        model.rec_base_discovered = 1;
        if (model.rec_base_was_auto) {
            uint64_t size = model.rec_end - model.rec_base;

            if ((pc & UINT64_C(3)) != 0 ||
                pc < REC_DISCOVERY_BASE || pc >= REC_DISCOVERY_END ||
                pc > UINT64_MAX - size) {
                rec_base_mismatch("invalid first executable TB", pc);
            } else {
                model.rec_base = pc;
                model.rec_end = pc + size;
                model.rec_base_auto = 0;
            }
        } else if (pc < model.rec_base || pc >= model.rec_end) {
            rec_base_mismatch("first executable TB outside configured range",
                              pc);
        }
    } else if (pc < model.rec_base || pc >= model.rec_end) {
        rec_base_mismatch("executable TB outside selected range", pc);
    }
}

static uint64_t first_rec_candidate(struct qemu_plugin_tb *tb)
{
    size_t index;

    for (index = 0; index < qemu_plugin_tb_n_insns(tb); index++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, index);
        uint64_t pc = qemu_plugin_insn_vaddr(insn);

        if (pc >= REC_DISCOVERY_BASE && pc < REC_DISCOVERY_END) {
            return pc;
        }
    }
    return 0;
}

static const char *gte_map_status(void)
{
    if (!model.gte_enabled) {
        return "disabled";
    }
    if (!model.gte_map_hits) {
        return "zero-hit";
    }
    if (!model.gte_entries) {
        return "body-only";
    }
    return "ok";
}

/* Keep a compact footprint of generated-code instruction lines.  The target
 * has a 16-byte VIPT I-cache and an 8 MiB recRAM window, so the default bitmap
 * is only 64 KiB.  This is deliberately separate from the cache tags: a line
 * can be evicted and reloaded many times, while this counter answers the
 * different question “how much generated code did the scene touch at all?”. */
static void rec_code_observe(uint64_t pc)
{
    uint64_t line;
    size_t byte;
    unsigned char mask;

    if (!pc_is_rec_code(pc)) {
        return;
    }
    rec_base_observe(pc);
    if (model.rec_pc_low == UINT64_MAX || pc < model.rec_pc_low) {
        model.rec_pc_low = pc;
    }
    if (pc + 4 > model.rec_pc_high) {
        model.rec_pc_high = pc + 4;
    }
    if (!model.rec_line_bits || model.rec_line_count == 0) {
        return;
    }
    line = (pc - model.rec_base) >> model.icache.line_shift;
    if (line >= model.rec_line_count) {
        return;
    }
    byte = (size_t)(line >> 3);
    mask = (unsigned char)(1u << (line & 7));
    if (!(model.rec_line_bits[byte] & mask)) {
        model.rec_line_bits[byte] |= mask;
        model.rec_unique_lines++;
    }
}

static int cache_access(Cache *cache, uint64_t address);
static int cache_access_indexed(Cache *cache, uint64_t tag_address,
                                uint64_t index_address);
static void clear_hotspot_counts(void);

/* A MIPS dynarec patches branch targets and emits new blocks with ordinary
 * stores, followed by a small instruction-cache flush.  QEMU's plugin API
 * does not expose the target cache instruction, but invalidating a matching
 * I-cache line for a store into recMem is the conservative equivalent.  It
 * prevents the model from crediting a stale native block after a backpatch. */
static void cache_invalidate_indexed(Cache *cache, uint64_t tag_address,
                                     uint64_t index_address)
{
    uint64_t tag_line = tag_address >> cache->line_shift;
    uint64_t index_line = index_address >> cache->line_shift;
    size_t set = (size_t)(index_line & (cache->sets - 1));
    uint64_t tag = tag_line >> cache->set_shift;
    size_t base = set * cache->ways;
    size_t way;

    for (way = 0; way < cache->ways; way++) {
        size_t index = base + way;

        if (cache->valid[index] && cache->tags[index] == tag) {
            cache->valid[index] = 0;
            cache->ages[index] = 0;
        }
    }
}

/* The guest plugin sees the Linux process' MIPS virtual addresses.  KSEG0
 * and KSEG1 are direct physical aliases on this NOMMU target.  QEMU normally
 * supplies a physical address for data callbacks, but instruction callbacks
 * only expose the virtual PC, so normalize the direct segments explicitly. */
static uint64_t mips_direct_phys(uint64_t address)
{
    uint32_t value = (uint32_t)address;

    if ((value & UINT32_C(0xe0000000)) == UINT32_C(0x80000000) ||
        (value & UINT32_C(0xe0000000)) == UINT32_C(0xa0000000)) {
        return (uint64_t)(value & UINT32_C(0x1fffffff));
    }
    return (uint64_t)value;
}

static int sf2000_mmio_phys(uint64_t address)
{
    /* This is the board model's broad uncached peripheral window.  The
     * separate 0x1fc00000 boot-ROM window is intentionally not included. */
    return address >= UINT64_C(0x10000000) &&
           address < UINT64_C(0x1fc00000);
}

static int cache_access_instruction(Cache *cache, uint64_t pc)
{
    uint64_t physical = mips_direct_phys(pc);

    if (model.i_vipt) {
        return cache_access_indexed(cache, physical, pc);
    }
    return cache_access(cache, physical);
}

static int is_power_of_two(uint64_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

static unsigned int log2_u64(uint64_t value)
{
    unsigned int result = 0;

    while (value > 1) {
        value >>= 1;
        result++;
    }
    return result;
}

static void cache_destroy(Cache *cache)
{
    free(cache->tags);
    free(cache->ages);
    free(cache->valid);
    memset(cache, 0, sizeof(*cache));
}

static int cache_init(Cache *cache, uint64_t size, uint64_t line,
                      uint64_t ways)
{
    uint64_t sets;
    size_t entries;

    if (!is_power_of_two(size) || !is_power_of_two(line) ||
        !is_power_of_two(ways) || line < 4 || ways == 0 ||
        size < line * ways) {
        return -1;
    }
    sets = size / (line * ways);
    if (!is_power_of_two(sets) || sets > SIZE_MAX / ways) {
        return -1;
    }
    entries = (size_t)(sets * ways);
    cache->tags = calloc(entries, sizeof(*cache->tags));
    cache->ages = calloc(entries, sizeof(*cache->ages));
    cache->valid = calloc(entries, sizeof(*cache->valid));
    if (!cache->tags || !cache->ages || !cache->valid) {
        cache_destroy(cache);
        return -1;
    }
    cache->sets = (size_t)sets;
    cache->ways = (size_t)ways;
    cache->line_shift = log2_u64(line);
    cache->set_shift = log2_u64(sets);
    return 0;
}

/* Return true on a hit and update the set's exact LRU state. */
static int cache_access(Cache *cache, uint64_t address)
{
    return cache_access_indexed(cache, address, address);
}

/* VIPT L1s use the virtual line for the set index and the physical line for
 * the tag.  This matters on the SF2000 because KSEG0/KSEG1 aliases can map
 * the same RAM line to different virtual indexes (Linux reports "cache
 * aliases" for the data cache). */
static int cache_access_indexed(Cache *cache, uint64_t tag_address,
                                uint64_t index_address)
{
    uint64_t tag_line = tag_address >> cache->line_shift;
    uint64_t index_line = index_address >> cache->line_shift;
    size_t set = (size_t)(index_line & (cache->sets - 1));
    uint64_t tag = tag_line >> cache->set_shift;
    size_t base = set * cache->ways;
    size_t victim = 0;
    uint32_t oldest = UINT32_MAX;
    size_t way;

    /* Ages are relative only within a set; this avoids a global sort. */
    cache->tick++;
    if (cache->tick == 0) {
        memset(cache->ages, 0, cache->sets * cache->ways * sizeof(*cache->ages));
        cache->tick = 1;
    }
    for (way = 0; way < cache->ways; way++) {
        size_t index = base + way;
        if (cache->valid[index] && cache->tags[index] == tag) {
            cache->ages[index] = (uint32_t)cache->tick;
            return 1;
        }
        if (!cache->valid[index]) {
            victim = way;
            oldest = 0;
            break;
        }
        if (cache->ages[index] < oldest) {
            oldest = cache->ages[index];
            victim = way;
        }
    }
    victim += base;
    cache->tags[victim] = tag;
    cache->ages[victim] = (uint32_t)cache->tick;
    cache->valid[victim] = 1;
    return 0;
}

static void cache_reset(Cache *cache)
{
    size_t entries = cache->sets * cache->ways;

    memset(cache->tags, 0, entries * sizeof(*cache->tags));
    memset(cache->ages, 0, entries * sizeof(*cache->ages));
    memset(cache->valid, 0, entries * sizeof(*cache->valid));
    cache->tick = 0;
}

/* A rec-phase report is intended to answer “what does the game cost?” rather
 * than “what did Linux boot cost?”.  Keep the cache geometry and allocation
 * intact, but clear all counters and hotspot accumulators at the first
 * generated-code PC. */
static void reset_measurement(void)
{
    cache_reset(&model.icache);
    cache_reset(&model.dcache);
    model.instructions = 0;
    model.i_accesses = 0;
    model.i_misses = 0;
    model.d_accesses = 0;
    model.d_lines = 0;
    model.d_bytes = 0;
    memset(model.d_size_counts, 0, sizeof(model.d_size_counts));
    model.d_misses = 0;
    model.i_invalidations = 0;
    model.rec_i_invalidations = 0;
    model.stores = 0;
    model.mmio = 0;
    model.sample_no = 0;
    model.next_sample = model.sample;
    model.previous_instructions = 0;
    model.previous_i_misses = 0;
    model.previous_d_misses = 0;
    model.previous_estimated_cycles = 0;
    model.have_previous = 0;
    memset(model.insn_classes, 0, sizeof(model.insn_classes));
    model.gte_instructions = 0;
    model.gte_i_misses = 0;
    model.gte_d_accesses = 0;
    model.gte_d_lines = 0;
    model.gte_d_misses = 0;
    memset(model.gte_counts, 0, sizeof(model.gte_counts));
    model.gte_work = 0;
    model.gte_map_hits = 0;
    model.gte_entries = 0;
    model.rec_i_accesses = 0;
    model.rec_i_misses = 0;
    model.rec_d_accesses = 0;
    model.rec_d_lines = 0;
    model.rec_d_bytes = 0;
    memset(model.rec_d_size_counts, 0, sizeof(model.rec_d_size_counts));
    model.rec_d_misses = 0;
    memset(model.rec_insn_classes, 0, sizeof(model.rec_insn_classes));
    model.rec_tb_execs = 0;
    model.rec_unique_lines = 0;
    model.rec_pc_low = UINT64_MAX;
    model.rec_pc_high = 0;
    if (model.rec_line_bits && model.rec_line_count) {
        memset(model.rec_line_bits, 0,
               (model.rec_line_count + 7) / 8);
    }
    model.frame_previous_cycles = 0;
    model.frame_cycle_sum = 0;
    model.frame_cycle_count = 0;
    model.frame_gte_work_sum = 0;
    model.frame_previous_gte_work = 0;
    model.frame_have_previous = 0;
    clear_hotspot_counts();
}

static uint64_t parse_u64(const char *text, uint64_t fallback)
{
    char *end;
    unsigned long long value;

    errno = 0;
    value = strtoull(text, &end, 0);
    if (errno || end == text || *end != '\0') {
        return fallback;
    }
    return (uint64_t)value;
}

/* A GTE map is generated beside the exact QPSX ELF by the build workflow.
 * Verify its fingerprint here as well as in the Makefile so a manually
 * invoked QEMU run cannot silently profile a different core.  sha256sum is a
 * normal host utility already required by this repository's build/tests; it
 * is run once at plugin installation, never in the emulation hot path. */
static int verify_file_sha256(const char *path, const char *expected)
{
    char command[PATH_MAX + 32];
    char line[256];
    FILE *pipe;
    int status;

    /* The path comes from QEMU_PLUGIN_ARGS.  Refuse shell metacharacters
     * rather than turning a diagnostic option into command execution. */
    if (!path[0] || strchr(path, '\'') || strchr(path, '\n') ||
        strchr(path, '\r') ||
        snprintf(command, sizeof(command), "/usr/bin/sha256sum '%s'", path)
            >= (int)sizeof(command)) {
        return -1;
    }
    pipe = popen(command, "r");
    if (!pipe || !fgets(line, sizeof(line), pipe)) {
        if (pipe) {
            pclose(pipe);
        }
        return -1;
    }
    status = pclose(pipe);
    if (status != 0 || strlen(line) < 64) {
        return -1;
    }
    line[64] = '\0';
    return strcasecmp(line, expected) == 0 ? 0 : -1;
}

static int gte_site_index(const char *name)
{
    size_t index;

    for (index = 0; index < GTE_OP_COUNT; index++) {
        if (strcmp(name, gte_operations[index].name) == 0) {
            return (int)index;
        }
    }
    /* Optimized GTE builds may split one architectural command into several
     * entry points (for example gteINTPL_LM_*).  The operation histogram must
     * aggregate those entry points rather than dropping them. */
    if (strncmp(name, "intpl_", 6) == 0) {
        return GTE_INTPL;
    }
    return -1;
}

/* Load a map in the intentionally boring, reviewable format:
 *
 *   # sf2000-gte-map version=1 corebase=0x83000000 coresize=0x120000 \
 *       core_sha256=<sha256 of exact ELF>
 *   gte rtps 0x54448 0x7c8 1
 *   ...
 *
 * Addresses are offsets from corebase, and the final column is only a
 * relative work-unit weight for comparing scenes.  Every architectural
 * operation must appear at least once; several ranges may map to one
 * operation (the specialized INTPL entry points are the usual example).
 * Ranges must be inside the core and non-overlapping. */
static int load_gte_map(const char *path)
{
    FILE *map;
    char line[256];
    char base_text[32];
    char size_text[32];
    char hash_text[65];
    uint64_t map_base;
    uint64_t map_size;
    unsigned char seen[GTE_OP_COUNT] = { 0 };
    size_t index;
    int have_header = 0;

    gte_range_count = 0;
    memset(gte_ranges, 0, sizeof(gte_ranges));
    map = fopen(path, "r");
    if (!map) {
        fprintf(stderr, "sf2000-cache-model: cannot open gtemap %s: %s\n",
                path, strerror(errno));
        return -1;
    }
    memset(hash_text, 0, sizeof(hash_text));
    while (fgets(line, sizeof(line), map)) {
        char name[32];
        char offset_text[32];
        char function_size_text[32];
        char work_text[32];
        int operation;
        uint64_t offset;
        uint64_t function_size;
        uint64_t work;

        if (line[0] == '#') {
            if (sscanf(line,
                       "# sf2000-gte-map version=1 corebase=%31s "
                       "coresize=%31s core_sha256=%64s",
                       base_text, size_text, hash_text) == 3) {
                map_base = parse_u64(base_text, UINT64_MAX);
                map_size = parse_u64(size_text, UINT64_MAX);
                if (map_base == UINT64_MAX || map_size == UINT64_MAX ||
                    strlen(hash_text) != 64) {
                    fprintf(stderr,
                            "sf2000-cache-model: malformed gtemap header\n");
                    fclose(map);
                    return -1;
                }
                have_header = 1;
            }
            continue;
        }
        if (sscanf(line, "gte %31s %31s %31s %31s", name, offset_text,
                   function_size_text, work_text) != 4) {
            continue;
        }
        operation = gte_site_index(name);
        offset = parse_u64(offset_text, UINT64_MAX);
        function_size = parse_u64(function_size_text, UINT64_MAX);
        work = parse_u64(work_text, UINT64_MAX);
        if (operation < 0 || offset == UINT64_MAX ||
            function_size == UINT64_MAX || function_size == 0 || work == 0 ||
            work > UCHAR_MAX || offset > UINT32_MAX ||
            function_size > UINT32_MAX || offset > UINT64_MAX - function_size ||
            gte_range_count >= GTE_MAX_RANGES) {
            fprintf(stderr, "sf2000-cache-model: invalid gtemap entry: %s",
                    line);
            fclose(map);
            return -1;
        }
        gte_ranges[gte_range_count].offset = (uint32_t)offset;
        gte_ranges[gte_range_count].size = (uint32_t)function_size;
        gte_ranges[gte_range_count].operation = (unsigned char)operation;
        gte_ranges[gte_range_count].work = (unsigned char)work;
        gte_range_count++;
        seen[operation] = 1;
    }
    fclose(map);
    if (!have_header || map_base != model.core_base ||
        map_size != model.core_end - model.core_base || !hash_text[0]) {
        fprintf(stderr,
                "sf2000-cache-model: gtemap core layout/fingerprint header "
                "does not match corebase=0x%016" PRIx64 " size=0x%016" PRIx64 "\n",
                model.core_base, model.core_end - model.core_base);
        return -1;
    }
    if (!model.gte_core_sha256[0]) {
        snprintf(model.gte_core_sha256, sizeof(model.gte_core_sha256),
                 "%s", hash_text);
    } else if (strcasecmp(model.gte_core_sha256, hash_text) != 0) {
        fprintf(stderr, "sf2000-cache-model: gtemap/coreelf hash mismatch\n");
        return -1;
    }
    if (!model.gte_core_elf[0] ||
        verify_file_sha256(model.gte_core_elf, model.gte_core_sha256) != 0) {
        fprintf(stderr,
                "sf2000-cache-model: gtemap requires matching coreelf=\n");
        return -1;
    }
    for (index = 0; index < GTE_OP_COUNT; index++) {
        if (!seen[index]) {
            fprintf(stderr,
                    "sf2000-cache-model: gtemap is missing %s\n",
                    gte_operations[index].name);
            return -1;
        }
    }
    for (index = 0; index < gte_range_count; index++) {
        size_t prior;

        if (gte_ranges[index].offset > model.core_end - model.core_base ||
            gte_ranges[index].size > model.core_end - model.core_base -
                                      gte_ranges[index].offset) {
            fprintf(stderr,
                    "sf2000-cache-model: gtemap range outside core\n");
            return -1;
        }
        for (prior = 0; prior < index; prior++) {
            uint64_t left_end = (uint64_t)gte_ranges[prior].offset +
                                gte_ranges[prior].size;

            if (gte_ranges[index].offset < left_end &&
                gte_ranges[prior].offset <
                (uint64_t)gte_ranges[index].offset +
                gte_ranges[index].size) {
                fprintf(stderr,
                        "sf2000-cache-model: overlapping gtemap entries\n");
                return -1;
            }
        }
    }
    model.gte_map_entries = gte_range_count;
    model.gte_enabled = 1;
    return 0;
}

static HotspotEntry *hotspot_lookup(uint64_t pc)
{
    size_t index;
    size_t probes;

    if (!model.hot_table) {
        return NULL;
    }
    index = (size_t)((pc ^ (pc >> 17) ^ (pc >> 31)) &
                     (model.hot_capacity - 1));
    for (probes = 0; probes < model.hot_capacity; probes++) {
        HotspotEntry *entry = &model.hot_table[index];

        if (entry->pc == pc) {
            return entry;
        }
        if (entry->pc == 0) {
            entry->pc = pc;
            return entry;
        }
        index = (index + 1) & (model.hot_capacity - 1);
    }
    return NULL;
}

static uint64_t hotspot_penalty(const HotspotEntry *entry)
{
    return entry->i_misses * model.instruction_penalty +
           entry->d_misses * model.data_penalty;
}

static uint64_t estimated_cycles_now(void)
{
    return model.instructions +
           model.i_misses * model.instruction_penalty +
           model.d_misses * model.data_penalty;
}

static int compare_u64(const void *left, const void *right)
{
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;

    return a < b ? -1 : a > b;
}

static uint64_t array_percentile(const uint64_t *values, size_t count,
                                 unsigned int permille)
{
    uint64_t rank;

    if (count == 0) {
        return 0;
    }
    rank = ((uint64_t)count * permille + 999) / 1000;
    if (rank == 0) {
        rank = 1;
    }
    if (rank > count) {
        rank = count;
    }
    return values[rank - 1];
}

static uint64_t frame_percentile(unsigned int permille)
{
    return array_percentile(model.frame_cycle_values,
                            model.frame_cycle_count, permille);
}

static void clear_hotspot_counts(void)
{
    size_t index;

    if (!model.hot_table) {
        return;
    }
    for (index = 0; index < model.hot_capacity; index++) {
        model.hot_table[index].executions = 0;
        model.hot_table[index].i_misses = 0;
        model.hot_table[index].d_accesses = 0;
        model.hot_table[index].d_misses = 0;
        model.hot_table[index].first_d_miss_address = 0;
        model.hot_table[index].last_d_miss_address = 0;
        model.hot_table[index].first_d_miss_vaddr = 0;
        model.hot_table[index].last_d_miss_vaddr = 0;
    }
}

/* QEMU keeps plugin callback userdata live for the lifetime of the translated
 * block.  The atexit callback is invoked after execution has stopped, so this
 * is the first point at which it is safe to reclaim TranslationBlock and
 * MemData records.  Never free these records during TB translation or flush:
 * QEMU may still have callback references to them. */
static void free_translation_blocks(void)
{
    TranslationBlock *block = model.translation_blocks;
    uint64_t expected_blocks = model.translation_block_count;
    uint64_t expected_memdata = model.memdata_count;
    uint64_t freed_blocks = 0;
    uint64_t freed_memdata = 0;

    while (block) {
        TranslationBlock *next = block->next;
        size_t index;

        if (block->mem) {
            for (index = 0; index < block->count; index++) {
                if (block->mem[index]) {
                    free(block->mem[index]);
                    freed_memdata++;
                }
            }
        }
        free(block->mem);
        free(block->pc);
        free(block->class_id);
        free(block->gte_id);
        free(block->hot);
        free(block);
        block = next;
        freed_blocks++;
    }
    model.translation_blocks = NULL;
    model.translation_block_count = 0;
    model.memdata_count = 0;
    if (freed_blocks != expected_blocks || freed_memdata != expected_memdata) {
        fprintf(stderr,
                "sf2000-cache-model: translation userdata cleanup mismatch "
                "blocks=%" PRIu64 "/%" PRIu64 " memdata=%" PRIu64 "/%" PRIu64
                "\n",
                freed_blocks, expected_blocks, freed_memdata,
                expected_memdata);
    }
    fprintf(stderr,
            "sf2000-cache-model: released translation userdata blocks=%" PRIu64
            " memdata=%" PRIu64 "\n", freed_blocks, freed_memdata);
}

static void write_hotspots(const char *kind)
{
    HotspotEntry *top[32] = { 0 };
    FILE *out;
    size_t index;
    size_t rank;

    if (!model.hot_table || !model.hot_path[0]) {
        return;
    }
    for (index = 0; index < model.hot_capacity; index++) {
        HotspotEntry *entry = &model.hot_table[index];
        uint64_t score;
        size_t position;

        if (entry->pc == 0) {
            continue;
        }
        score = hotspot_penalty(entry);
        if (score == 0) {
            continue;
        }
        position = 0;
        while (position < sizeof(top) / sizeof(top[0]) && top[position] &&
               hotspot_penalty(top[position]) >= score) {
            position++;
        }
        if (position >= sizeof(top) / sizeof(top[0])) {
            continue;
        }
        for (rank = sizeof(top) / sizeof(top[0]) - 1; rank > position; rank--) {
            top[rank] = top[rank - 1];
        }
        top[position] = entry;
    }
    out = fopen(model.hot_path, "a");
    if (!out) {
        return;
    }
    fprintf(out,
            "# sf2000-cache-model hotspots version=%d sample=%" PRIu64
            " kind=%s instructions=%" PRIu64 " scope=%s coverage=%s"
            " frame=%" PRIu64 " label=%s\n",
            CACHE_MODEL_REPORT_VERSION, model.sample_no, kind, model.instructions,
            scope_label(),
            coverage_label(), model.frame_number, model.label);
    for (rank = 0; rank < sizeof(top) / sizeof(top[0]); rank++) {
        HotspotEntry *entry = top[rank];

        if (!entry) {
            break;
        }
        fprintf(out,
                "hotspot sample=%" PRIu64 " rank=%zu pc=0x%016" PRIx64
                " opcode=0x%08" PRIx32 " class=%u"
                " executions=%" PRIu64 " i_misses=%" PRIu64
                " d_accesses=%" PRIu64 " d_misses=%" PRIu64
                " first_d_miss=0x%016" PRIx64 "/0x%016" PRIx64
                " last_d_miss=0x%016" PRIx64 "/0x%016" PRIx64
                " penalty=%" PRIu64 "\n",
                model.sample_no, rank + 1, entry->pc, entry->opcode,
                (unsigned)entry->class_id, entry->executions,
                entry->i_misses,
                entry->d_accesses, entry->d_misses,
                entry->first_d_miss_address, entry->first_d_miss_vaddr,
                entry->last_d_miss_address, entry->last_d_miss_vaddr,
                hotspot_penalty(entry));
    }
    fflush(out);
    fclose(out);
}

static void write_report(const char *kind)
{
    size_t index;
    uint64_t estimated_cycles;
    uint64_t i_miss_ppm;
    uint64_t d_miss_ppm;
    uint64_t rec_i_ppm;
    uint64_t rec_d_ppm;
    uint64_t rec_i_miss_ppm;
    uint64_t rec_d_miss_ppm;
    uint64_t rec_i_miss_share_ppm;
    uint64_t rec_d_miss_share_ppm;
    uint64_t rec_d_line_miss_ppm;
    uint64_t rec_cf_ppm;
    uint64_t rec_code_span;
    uint64_t delta_instructions;
    uint64_t delta_i_misses;
    uint64_t delta_d_misses;
    uint64_t delta_estimated_cycles;
    uint64_t frame_average_cycles;
    uint64_t frame_p95_cycles;
    uint64_t frame_p98_cycles;
    uint64_t frame_p99_cycles;
    uint64_t frame_p999_cycles;
    uint64_t frame_max_cycles;
    uint64_t frame_gte_work_average;
    uint64_t frame_gte_work_p95;
    uint64_t frame_gte_work_p98;
    uint64_t frame_gte_work_p99;
    uint64_t frame_gte_work_p999;
    uint64_t frame_gte_work_max;
    uint64_t helper_i_accesses;
    uint64_t helper_i_misses;
    uint64_t helper_d_accesses;
    uint64_t helper_d_lines;
    uint64_t helper_d_bytes;
    uint64_t helper_d_misses;
    uint64_t helper_instructions;
    uint64_t helper_d_size_counts[4];

    if (!model.out) {
        return;
    }
    estimated_cycles = estimated_cycles_now();
    frame_average_cycles = model.frame_cycle_count ?
        model.frame_cycle_sum / model.frame_cycle_count : 0;
    if (model.frame_cycle_count) {
        qsort(model.frame_cycle_values, model.frame_cycle_count,
              sizeof(model.frame_cycle_values[0]), compare_u64);
        qsort(model.frame_gte_work_values, model.frame_cycle_count,
              sizeof(model.frame_gte_work_values[0]), compare_u64);
    }
    frame_p95_cycles = frame_percentile(950);
    frame_p98_cycles = frame_percentile(980);
    frame_p99_cycles = frame_percentile(990);
    frame_p999_cycles = frame_percentile(999);
    frame_max_cycles = frame_percentile(1000);
    frame_gte_work_average = model.frame_cycle_count ?
        model.frame_gte_work_sum / model.frame_cycle_count : 0;
    frame_gte_work_p95 = array_percentile(model.frame_gte_work_values,
                                           model.frame_cycle_count, 950);
    frame_gte_work_p98 = array_percentile(model.frame_gte_work_values,
                                           model.frame_cycle_count, 980);
    frame_gte_work_p99 = array_percentile(model.frame_gte_work_values,
                                           model.frame_cycle_count, 990);
    frame_gte_work_p999 = array_percentile(model.frame_gte_work_values,
                                            model.frame_cycle_count, 999);
    frame_gte_work_max = array_percentile(model.frame_gte_work_values,
                                           model.frame_cycle_count, 1000);
    i_miss_ppm = ratio_ppm(model.i_misses, model.i_accesses);
    d_miss_ppm = ratio_ppm(model.d_misses, model.d_lines);
    rec_i_ppm = ratio_ppm(model.rec_i_accesses, model.i_accesses);
    rec_d_ppm = ratio_ppm(model.rec_d_accesses, model.d_accesses);
    rec_i_miss_ppm = ratio_ppm(model.rec_i_misses, model.rec_i_accesses);
    rec_d_miss_ppm = ratio_ppm(model.rec_d_misses, model.rec_d_accesses);
    rec_i_miss_share_ppm = ratio_ppm(model.rec_i_misses, model.i_misses);
    rec_d_miss_share_ppm = ratio_ppm(model.rec_d_misses, model.d_misses);
    rec_d_line_miss_ppm = ratio_ppm(model.rec_d_misses, model.rec_d_lines);
    helper_i_accesses = model.i_accesses >= model.rec_i_accesses ?
                        model.i_accesses - model.rec_i_accesses : 0;
    helper_i_misses = model.i_misses >= model.rec_i_misses ?
                      model.i_misses - model.rec_i_misses : 0;
    helper_d_accesses = model.d_accesses >= model.rec_d_accesses ?
                        model.d_accesses - model.rec_d_accesses : 0;
    helper_d_lines = model.d_lines >= model.rec_d_lines ?
                     model.d_lines - model.rec_d_lines : 0;
    helper_d_bytes = model.d_bytes >= model.rec_d_bytes ?
                     model.d_bytes - model.rec_d_bytes : 0;
    helper_d_misses = model.d_misses >= model.rec_d_misses ?
                      model.d_misses - model.rec_d_misses : 0;
    helper_instructions = model.instructions >= model.rec_i_accesses ?
                          model.instructions - model.rec_i_accesses : 0;
    for (index = 0; index < sizeof(helper_d_size_counts) /
                         sizeof(helper_d_size_counts[0]); index++) {
        helper_d_size_counts[index] =
            model.d_size_counts[index] >= model.rec_d_size_counts[index] ?
            model.d_size_counts[index] - model.rec_d_size_counts[index] : 0;
    }
    rec_cf_ppm = ratio_ppm(model.rec_insn_classes[INSN_BRANCH] +
                           model.rec_insn_classes[INSN_JUMP],
                           model.rec_i_accesses);
    rec_code_span = model.rec_pc_low == UINT64_MAX ||
                    model.rec_pc_high < model.rec_pc_low ? 0 :
                    model.rec_pc_high - model.rec_pc_low;
    if (model.have_previous) {
        delta_instructions = model.instructions - model.previous_instructions;
        delta_i_misses = model.i_misses - model.previous_i_misses;
        delta_d_misses = model.d_misses - model.previous_d_misses;
        delta_estimated_cycles = estimated_cycles -
                                 model.previous_estimated_cycles;
    } else {
        delta_instructions = model.instructions;
        delta_i_misses = model.i_misses;
        delta_d_misses = model.d_misses;
        delta_estimated_cycles = estimated_cycles;
    }
    model.sample_no++;
    fprintf(model.out,
            "sample=%" PRIu64 " kind=%s label=%s instructions=%" PRIu64
            " scope=%s coverage=%s recbase=0x%016" PRIx64
            " recbase_configured=0x%016" PRIx64
            " recbase_status=%s recbase_evidence_pc=0x%016" PRIx64
            " frame=%" PRIu64 " frame_samples=%zu"
            " frame_avg_cycles=%" PRIu64
            " frame_p95_cycles=%" PRIu64
            " frame_p98_cycles=%" PRIu64
            " frame_p99_cycles=%" PRIu64
            " frame_p999_cycles=%" PRIu64
            " frame_max_cycles=%" PRIu64
            " gte_instructions=%" PRIu64
            " gte_i_misses=%" PRIu64
            " gte_d_accesses=%" PRIu64
            " gte_d_lines=%" PRIu64
            " gte_d_misses=%" PRIu64
            " gte_work=%" PRIu64
            " frame_gte_work_avg=%" PRIu64
            " frame_gte_work_p95=%" PRIu64
            " frame_gte_work_p98=%" PRIu64
            " frame_gte_work_p99=%" PRIu64
            " frame_gte_work_p999=%" PRIu64
            " frame_gte_work_max=%" PRIu64
            " gte_map_enabled=%d gte_map_entries=%" PRIu64
            " gte_map_hits=%" PRIu64 " gte_entries=%" PRIu64
            " i_accesses=%" PRIu64 " i_misses=%" PRIu64
            " i_invalidations=%" PRIu64
            " d_accesses=%" PRIu64 " d_lines=%" PRIu64
            " d_bytes=%" PRIu64 " d_size1=%" PRIu64
            " d_size2=%" PRIu64 " d_size4=%" PRIu64
            " d_size8p=%" PRIu64
            " d_misses=%" PRIu64 " stores=%" PRIu64 " mmio=%" PRIu64
            " i_miss_ppm=%" PRIu64 " d_miss_ppm=%" PRIu64
            " rec_i_ppm=%" PRIu64 " rec_d_ppm=%" PRIu64
            " rec_i_miss_ppm=%" PRIu64 " rec_d_miss_ppm=%" PRIu64
            " rec_i_miss_share_ppm=%" PRIu64
            " rec_d_miss_share_ppm=%" PRIu64
            " rec_d_lines=%" PRIu64 " rec_d_line_miss_ppm=%" PRIu64
            " rec_cf_ppm=%" PRIu64 " rec_unique_lines=%" PRIu64
            " rec_code_span=%" PRIu64 " rec_pc_low=0x%016" PRIx64
            " rec_pc_high=0x%016" PRIx64 " rec_tb_execs=%" PRIu64
            " branches=%" PRIu64 " jumps=%" PRIu64
            " loads=%" PRIu64 " store_insns=%" PRIu64
            " muldiv=%" PRIu64 " cop2=%" PRIu64
            " rec_branches=%" PRIu64 " rec_jumps=%" PRIu64
            " rec_loads=%" PRIu64 " rec_store_insns=%" PRIu64
            " rec_muldiv=%" PRIu64 " rec_cop2=%" PRIu64
            " rec_i_accesses=%" PRIu64 " rec_i_misses=%" PRIu64
            " rec_i_invalidations=%" PRIu64
            " rec_d_accesses=%" PRIu64 " rec_d_bytes=%" PRIu64
            " rec_d_size1=%" PRIu64 " rec_d_size2=%" PRIu64
            " rec_d_size4=%" PRIu64 " rec_d_size8p=%" PRIu64
            " rec_d_misses=%" PRIu64
            " helper_instructions=%" PRIu64
            " helper_i_accesses=%" PRIu64 " helper_i_misses=%" PRIu64
            " helper_i_miss_ppm=%" PRIu64 " helper_i_miss_share_ppm=%" PRIu64
            " helper_d_accesses=%" PRIu64 " helper_d_lines=%" PRIu64
            " helper_d_bytes=%" PRIu64 " helper_d_size1=%" PRIu64
            " helper_d_size2=%" PRIu64 " helper_d_size4=%" PRIu64
            " helper_d_size8p=%" PRIu64 " helper_d_misses=%" PRIu64
            " helper_d_miss_ppm=%" PRIu64
            " helper_d_miss_share_ppm=%" PRIu64
            " est_cycles=%" PRIu64 " delta_instructions=%" PRIu64
            " delta_i_misses=%" PRIu64 " delta_d_misses=%" PRIu64
            " delta_est_cycles=%" PRIu64 "\n",
            model.sample_no, kind, model.label, model.instructions,
            scope_label(),
            coverage_label(), model.rec_base, model.rec_configured_base,
            rec_base_status(), model.rec_base_evidence_pc,
            model.frame_number, model.frame_cycle_count,
            frame_average_cycles, frame_p95_cycles, frame_p98_cycles,
            frame_p99_cycles, frame_p999_cycles, frame_max_cycles,
            model.gte_instructions, model.gte_i_misses,
            model.gte_d_accesses, model.gte_d_lines, model.gte_d_misses,
            model.gte_work, frame_gte_work_average, frame_gte_work_p95,
            frame_gte_work_p98, frame_gte_work_p99, frame_gte_work_p999,
            frame_gte_work_max, model.gte_enabled, model.gte_map_entries,
            model.gte_map_hits, model.gte_entries,
            model.i_accesses, model.i_misses, model.i_invalidations,
            model.d_accesses,
            model.d_lines, model.d_bytes, model.d_size_counts[0],
            model.d_size_counts[1], model.d_size_counts[2],
            model.d_size_counts[3], model.d_misses, model.stores,
            model.mmio,
            i_miss_ppm, d_miss_ppm, rec_i_ppm, rec_d_ppm,
            rec_i_miss_ppm, rec_d_miss_ppm,
            rec_i_miss_share_ppm, rec_d_miss_share_ppm,
            model.rec_d_lines, rec_d_line_miss_ppm, rec_cf_ppm,
            model.rec_unique_lines, rec_code_span,
            model.rec_pc_low == UINT64_MAX ? 0 : model.rec_pc_low,
            model.rec_pc_high, model.rec_tb_execs,
            model.insn_classes[INSN_BRANCH], model.insn_classes[INSN_JUMP],
            model.insn_classes[INSN_LOAD], model.insn_classes[INSN_STORE],
            model.insn_classes[INSN_MULDIV], model.insn_classes[INSN_COP2],
            model.rec_insn_classes[INSN_BRANCH],
            model.rec_insn_classes[INSN_JUMP],
            model.rec_insn_classes[INSN_LOAD],
            model.rec_insn_classes[INSN_STORE],
            model.rec_insn_classes[INSN_MULDIV],
            model.rec_insn_classes[INSN_COP2],
            model.rec_i_accesses, model.rec_i_misses,
            model.rec_i_invalidations,
            model.rec_d_accesses, model.rec_d_bytes,
            model.rec_d_size_counts[0], model.rec_d_size_counts[1],
            model.rec_d_size_counts[2], model.rec_d_size_counts[3],
            model.rec_d_misses,
            helper_instructions,
            helper_i_accesses, helper_i_misses,
            ratio_ppm(helper_i_misses, helper_i_accesses),
            ratio_ppm(helper_i_misses, model.i_misses),
            helper_d_accesses, helper_d_lines, helper_d_bytes,
            helper_d_size_counts[0], helper_d_size_counts[1],
            helper_d_size_counts[2], helper_d_size_counts[3], helper_d_misses,
            ratio_ppm(helper_d_misses, helper_d_lines),
            ratio_ppm(helper_d_misses, model.d_misses),
            estimated_cycles, delta_instructions, delta_i_misses,
            delta_d_misses, delta_estimated_cycles);
    fprintf(model.out,
            "gte sample=%" PRIu64 " kind=%s label=%s frame=%" PRIu64
            " frame_samples=%zu base=0x%016" PRIx64
            " map_enabled=%d map_entries=%" PRIu64
            " map_hits=%" PRIu64 " entries=%" PRIu64
            " map_status=%s"
            " rtps=%" PRIu64 " rtpt=%" PRIu64
            " mvmva=%" PRIu64 " nclip=%" PRIu64
            " avsz3=%" PRIu64 " avsz4=%" PRIu64
            " sqr=%" PRIu64 " nccs=%" PRIu64
            " ncct=%" PRIu64 " ncds=%" PRIu64
            " ncdt=%" PRIu64 " op=%" PRIu64
            " dcpl=%" PRIu64 " gpf=%" PRIu64
            " gpl=%" PRIu64 " dpcs=%" PRIu64
            " dpct=%" PRIu64 " ncs=%" PRIu64
            " nct=%" PRIu64 " cc=%" PRIu64
            " intpl=%" PRIu64 " cdp=%" PRIu64
            " instructions=%" PRIu64 " i_misses=%" PRIu64
            " d_accesses=%" PRIu64 " d_lines=%" PRIu64
            " d_misses=%" PRIu64 " work=%" PRIu64
            " frame_work_avg=%" PRIu64 " frame_work_p95=%" PRIu64
            " frame_work_p98=%" PRIu64 " frame_work_p99=%" PRIu64
            " frame_work_p999=%" PRIu64 " frame_work_max=%" PRIu64 "\n",
            model.sample_no, kind, model.label, model.frame_number,
            model.frame_cycle_count, model.core_base, model.gte_enabled,
            model.gte_map_entries, model.gte_map_hits, model.gte_entries,
            gte_map_status(),
            model.gte_counts[GTE_RTPS], model.gte_counts[GTE_RTPT],
            model.gte_counts[GTE_MVMVA], model.gte_counts[GTE_NCLIP],
            model.gte_counts[GTE_AVSZ3], model.gte_counts[GTE_AVSZ4],
            model.gte_counts[GTE_SQR], model.gte_counts[GTE_NCCS],
            model.gte_counts[GTE_NCCT], model.gte_counts[GTE_NCDS],
            model.gte_counts[GTE_NCDT], model.gte_counts[GTE_OP],
            model.gte_counts[GTE_DCPL], model.gte_counts[GTE_GPF],
            model.gte_counts[GTE_GPL], model.gte_counts[GTE_DPCS],
            model.gte_counts[GTE_DPCT], model.gte_counts[GTE_NCS],
            model.gte_counts[GTE_NCT], model.gte_counts[GTE_CC],
            model.gte_counts[GTE_INTPL], model.gte_counts[GTE_CDP],
            model.gte_instructions, model.gte_i_misses,
            model.gte_d_accesses, model.gte_d_lines, model.gte_d_misses,
            model.gte_work, frame_gte_work_average, frame_gte_work_p95,
            frame_gte_work_p98, frame_gte_work_p99, frame_gte_work_p999,
            frame_gte_work_max);
    fflush(model.out);
    model.previous_instructions = model.instructions;
    model.previous_i_misses = model.i_misses;
    model.previous_d_misses = model.d_misses;
    model.previous_estimated_cycles = estimated_cycles;
    model.have_previous = 1;
    write_hotspots(kind);
}

static void maybe_report(void)
{
    if (model.frame_opcode || model.sample == 0 ||
        model.instructions < model.next_sample) {
        return;
    }
    do {
        model.next_sample += model.sample;
    } while (model.next_sample <= model.instructions);
    write_report("periodic");
}

static void frame_marker_exec(unsigned int vcpu_index, void *userdata)
{
    uint64_t cycles;
    uint64_t frame_cycles;
    uint64_t frame_gte_work;
    int report_now;

    (void)vcpu_index;
    (void)userdata;
    if (model.frame_frozen) {
        return;
    }
    model.frame_number++;
    if (model.phase_rec && !model.phase_active) {
        return;
    }
    cycles = estimated_cycles_now();
    frame_gte_work = model.gte_work - model.frame_previous_gte_work;
    if (model.frame_have_previous) {
        frame_cycles = cycles - model.frame_previous_cycles;
        if (model.frame_cycle_count <
            sizeof(model.frame_cycle_values) /
            sizeof(model.frame_cycle_values[0])) {
            model.frame_cycle_values[model.frame_cycle_count++] = frame_cycles;
            model.frame_cycle_sum += frame_cycles;
            model.frame_gte_work_values[model.frame_cycle_count - 1] =
                frame_gte_work;
            model.frame_gte_work_sum += frame_gte_work;
        }
    }
    model.frame_previous_cycles = cycles;
    model.frame_previous_gte_work = model.gte_work;
    model.frame_have_previous = 1;

    report_now = model.frame_report_period &&
                 model.frame_number % model.frame_report_period == 0;
    if (model.frame_stop && model.frame_number >= model.frame_stop) {
        report_now = 1;
    }
    if (report_now) {
        write_report("frame");
        model.frame_cycle_sum = 0;
        model.frame_gte_work_sum = 0;
        model.frame_cycle_count = 0;
        clear_hotspot_counts();
    }
    if (model.frame_stop && model.frame_number >= model.frame_stop) {
        model.frame_frozen = 1;
    }
}

static void tb_exec(unsigned int vcpu_index, void *userdata)
{
    TranslationBlock *tb = userdata;
    size_t index;
    int rec_tb_seen = 0;

    (void)vcpu_index;
    if (model.frame_frozen) {
        return;
    }
    /* During rec-phase setup, most TBs are kernel/loader code.  The previous
     * implementation checked every instruction in each of those TBs, which
     * made the diagnostic plugin slow the boot so much that it never reached
     * QPSX.  Translation-time rec_count gives us an O(1) rejection path. */
    if (model.phase_rec && !model.phase_active) {
        if (tb->rec_count == 0) {
            return;
        }
        reset_measurement();
        model.phase_active = 1;
    }
    for (index = 0; index < tb->count; index++) {
        unsigned char gte_id = GTE_ID_NONE;

        if (!pc_is_selected(tb->pc[index])) {
            continue;
        }
        model.instructions++;
        model.i_accesses++;
        model.insn_classes[tb->class_id[index]]++;
        if (pc_is_rec_code(tb->pc[index])) {
            model.rec_i_accesses++;
            model.rec_insn_classes[tb->class_id[index]]++;
            rec_tb_seen = 1;
            rec_code_observe(tb->pc[index]);
        }
        if (tb->gte_id) {
            gte_id = tb->gte_id[index];
        }
        if (gte_id != GTE_ID_NONE) {
            unsigned int range = (gte_id & ~GTE_ID_ENTRY) - 1;
            unsigned int operation = gte_ranges[range].operation;

            model.gte_map_hits++;
            model.gte_instructions++;
            if (gte_id & GTE_ID_ENTRY) {
                model.gte_entries++;
                model.gte_counts[operation]++;
                model.gte_work += gte_ranges[range].work;
            }
        }
        if (tb->hot && tb->hot[index]) {
            tb->hot[index]->executions++;
        }
        if (!cache_access_instruction(&model.icache, tb->pc[index])) {
            model.i_misses++;
            if (gte_id != GTE_ID_NONE) {
                model.gte_i_misses++;
            }
            if (pc_is_rec_code(tb->pc[index])) {
                model.rec_i_misses++;
            }
            if (tb->hot && tb->hot[index]) {
                tb->hot[index]->i_misses++;
            }
        }
    }
    if (rec_tb_seen) {
        model.rec_tb_execs++;
    }
    maybe_report();
}

static void mem_access(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                       uint64_t vaddr, void *userdata)
{
    struct qemu_plugin_hwaddr *hwaddr;
    HotspotEntry *hot = NULL;
    uint64_t pc = 0;
    uint64_t address;
    uint64_t index_address;
    uint64_t last_index_address;
    uint64_t last_address;
    uint64_t last_vaddr;
    unsigned int size_shift;
    int rec_code_store;
    unsigned char gte_id = GTE_ID_NONE;

    (void)vcpu_index;
    if (model.frame_frozen) {
        return;
    }
    if (model.phase_rec && !model.phase_active) {
        return;
    }
    if (userdata != &model) {
        MemData *mem = userdata;

        hot = mem->hot;
        pc = mem->pc;
        gte_id = mem->gte_id;
    }
    if (!pc_is_selected(pc)) {
        return;
    }
    hwaddr = qemu_plugin_get_hwaddr(info, vaddr);
    if (hwaddr && qemu_plugin_hwaddr_is_io(hwaddr)) {
        model.mmio++;
        return;
    }
    address = hwaddr ? qemu_plugin_hwaddr_phys_addr(hwaddr) :
                       mips_direct_phys(vaddr);
    if (!hwaddr && sf2000_mmio_phys(address)) {
        model.mmio++;
        return;
    }
    size_shift = qemu_plugin_mem_size_shift(info);
    if (size_shift > 20) {
        size_shift = 20;
    }
    {
        unsigned int size_class = size_shift < 3 ? size_shift : 3;
        uint64_t access_bytes = UINT64_C(1) << size_shift;

        model.d_bytes += access_bytes;
        model.d_size_counts[size_class]++;
        if (pc_is_rec_code(pc)) {
            model.rec_d_bytes += access_bytes;
            model.rec_d_size_counts[size_class]++;
        }
    }
    rec_code_store = qemu_plugin_mem_is_store(info) &&
                     pc_is_rec_code(vaddr);
    last_address = address + ((UINT64_C(1) << size_shift) - 1);
    last_vaddr = vaddr + ((UINT64_C(1) << size_shift) - 1);
    index_address = model.d_vipt ? vaddr : address;
    last_index_address = model.d_vipt ? last_vaddr : last_address;
    model.d_accesses++;
    if (pc_is_rec_code(pc)) {
        model.rec_d_accesses++;
    }
    if (hot) {
        hot->d_accesses++;
    }
    if (qemu_plugin_mem_is_store(info)) {
        model.stores++;
    }
    model.d_lines++;
    if (gte_id != GTE_ID_NONE) {
        model.gte_d_accesses++;
        model.gte_d_lines++;
    }
    if (pc_is_rec_code(pc)) {
        model.rec_d_lines++;
    }
    if (!cache_access_indexed(&model.dcache, address, index_address)) {
        model.d_misses++;
        if (gte_id != GTE_ID_NONE) {
            model.gte_d_misses++;
        }
        if (pc_is_rec_code(pc)) {
            model.rec_d_misses++;
        }
        if (hot) {
            hot->d_misses++;
            if (!hot->first_d_miss_address) {
                hot->first_d_miss_address = address;
                hot->first_d_miss_vaddr = vaddr;
            }
            hot->last_d_miss_address = address;
            hot->last_d_miss_vaddr = vaddr;
        }
    }
    if ((last_address >> model.dcache.line_shift) !=
        (address >> model.dcache.line_shift)) {
        model.d_lines++;
        if (gte_id != GTE_ID_NONE) {
            model.gte_d_lines++;
        }
        if (pc_is_rec_code(pc)) {
            model.rec_d_lines++;
        }
        if (!cache_access_indexed(&model.dcache, last_address,
                                  last_index_address)) {
            model.d_misses++;
            if (gte_id != GTE_ID_NONE) {
                model.gte_d_misses++;
            }
            if (pc_is_rec_code(pc)) {
                model.rec_d_misses++;
            }
            if (hot) {
                hot->d_misses++;
                if (!hot->first_d_miss_address) {
                    hot->first_d_miss_address = last_address;
                    hot->first_d_miss_vaddr = last_vaddr;
                }
                hot->last_d_miss_address = last_address;
                hot->last_d_miss_vaddr = last_vaddr;
            }
        }
    }
    if (rec_code_store) {
        cache_invalidate_indexed(&model.icache, address, index_address);
        model.i_invalidations++;
        if (pc_is_rec_code(vaddr))
            model.rec_i_invalidations++;
        if ((last_address >> model.dcache.line_shift) !=
            (address >> model.dcache.line_shift)) {
            cache_invalidate_indexed(&model.icache, last_address,
                                     last_index_address);
            model.i_invalidations++;
            if (pc_is_rec_code(last_vaddr))
                model.rec_i_invalidations++;
        }
    }
}

static void tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    TranslationBlock *data;
    size_t index;
    size_t rec_count = 0;
    size_t core_count = 0;

    /* Before the first rec TB, validate the configured range against runtime
     * executable evidence.  Auto mode adopts the exact first TB address; an
     * explicit range must contain it.  A mismatch is retained in the report
     * and printed to stderr, rather than silently attributing unrelated text
     * to recRAM. */
    if (model.phase_rec && !model.phase_active) {
        uint64_t candidate = first_rec_candidate(tb);

        if (candidate) {
            if (model.rec_base_was_auto) {
                rec_base_observe(candidate);
            } else if (candidate < model.rec_base ||
                       candidate >= model.rec_end) {
                model.rec_base_evidence_pc = candidate;
                model.rec_base_discovered = 1;
                rec_base_mismatch("first executable TB outside configured range",
                                  candidate);
            } else {
                rec_base_observe(candidate);
            }
        }
    }

    /* In rec-only mode the diagnostic is deliberately a generated-code
     * microscope.  Do not install a callback for every kernel/loader TB:
     * QEMU still translates those TBs, but the plugin no longer adds a
     * per-TB execution callback and per-load/store callbacks before QPSX
     * starts.  This makes a rec-phase run reach the game instead of spending
     * its entire budget instrumenting Linux boot.
     *
     * The same early rejection is useful for a post-rec (scope=all) pass.
     * A memory callback that merely returns while phase_active is false is
     * still expensive enough to trip the guest watchdog during Linux boot.
     * Skip those pre-rec TBs entirely; helpers translated after the first
     * recRAM block are still measured, and the generated-code microscope is
     * unchanged.  The report labels this as phase=rec so callers do not
     * mistake it for a boot-inclusive profile. */
    if (model.emu_only) {
        for (index = 0; index < qemu_plugin_tb_n_insns(tb); index++) {
            struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, index);
            uint64_t pc = qemu_plugin_insn_vaddr(insn);

            if (pc_is_core_code(pc)) {
                core_count++;
            }
            if (pc_is_rec_code(pc)) {
                rec_count++;
            }
        }
        if (core_count == 0 && rec_count == 0) {
            return;
        }
    } else if (model.core_only) {
        for (index = 0; index < qemu_plugin_tb_n_insns(tb); index++) {
            struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, index);

            if (pc_is_core_code(qemu_plugin_insn_vaddr(insn))) {
                core_count++;
            }
        }
        if (core_count == 0) {
            return;
        }
    } else if (model.rec_only) {
        for (index = 0; index < qemu_plugin_tb_n_insns(tb); index++) {
            struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, index);

            if (pc_is_rec_code(qemu_plugin_insn_vaddr(insn))) {
                rec_count++;
            }
        }
        if (rec_count == 0) {
            return;
        }
    } else if (model.phase_rec) {
        for (index = 0; index < qemu_plugin_tb_n_insns(tb); index++) {
            struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, index);

            if (pc_is_rec_code(qemu_plugin_insn_vaddr(insn))) {
                rec_count++;
            }
        }
        if (!model.phase_active && rec_count == 0) {
            return;
        }
    }

    data = calloc(1, sizeof(*data));
    if (!data) {
        return;
    }
    data->count = qemu_plugin_tb_n_insns(tb);
    data->rec_count = 0;
    data->pc = calloc(data->count, sizeof(*data->pc));
    data->class_id = calloc(data->count, sizeof(*data->class_id));
    data->gte_id = calloc(data->count, sizeof(*data->gte_id));
    if (!data->pc || !data->class_id || !data->gte_id) {
        free(data->pc);
        free(data->class_id);
        free(data->gte_id);
        free(data);
        return;
    }
    if (model.hot_table) {
        data->hot = calloc(data->count, sizeof(*data->hot));
        if (!data->hot) {
            free(data->pc);
            free(data->class_id);
            free(data->gte_id);
            free(data);
            return;
        }
    }
    data->mem = calloc(data->count, sizeof(*data->mem));
    if (!data->mem) {
        free(data->hot);
        free(data->pc);
        free(data->class_id);
        free(data->gte_id);
        free(data);
        return;
    }
    for (index = 0; index < data->count; index++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, index);
        void *mem_userdata = &model;
        uint32_t opcode = 0;

        data->pc[index] = qemu_plugin_insn_vaddr(insn);
        data->gte_id[index] = gte_id_for_pc(data->pc[index]);
        if (pc_is_rec_code(data->pc[index])) {
            data->rec_count++;
        }
        {
            unsigned char bytes[4] = { 0, 0, 0, 0 };

            if (qemu_plugin_insn_data(insn, bytes, sizeof(bytes)) ==
                sizeof(bytes)) {
                opcode = (uint32_t)bytes[0] |
                         ((uint32_t)bytes[1] << 8) |
                         ((uint32_t)bytes[2] << 16) |
                         ((uint32_t)bytes[3] << 24);
            }
            data->class_id[index] = (unsigned char)classify_mips32(opcode);
        }
        {
            MemData *mem = calloc(1, sizeof(*mem));

            if (mem && pc_is_selected(data->pc[index])) {
                mem->pc = data->pc[index];
                mem->gte_id = data->gte_id[index];
                if (data->hot) {
                    data->hot[index] = hotspot_lookup(data->pc[index]);
                    if (data->hot[index]) {
                        data->hot[index]->opcode = opcode;
                        data->hot[index]->class_id = data->class_id[index];
                    }
                    mem->hot = data->hot[index];
                }
                data->mem[index] = mem;
                model.memdata_count++;
                mem_userdata = mem;
            } else if (mem) {
                free(mem);
            }
        }
        if (pc_is_selected(data->pc[index])) {
            qemu_plugin_register_vcpu_mem_cb(insn, mem_access,
                                             QEMU_PLUGIN_CB_NO_REGS,
                                             QEMU_PLUGIN_MEM_RW, mem_userdata);
        }
        if (model.frame_opcode && opcode == model.frame_opcode &&
            pc_is_core_code(data->pc[index])) {
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, frame_marker_exec, QEMU_PLUGIN_CB_NO_REGS, NULL);
        }
    }
    data->next = model.translation_blocks;
    model.translation_blocks = data;
    model.translation_block_count++;
    qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS, data);
    (void)id;
}

static void plugin_exit(qemu_plugin_id_t id, void *userdata)
{
    (void)id;
    (void)userdata;
    if (!model.frame_frozen) {
        write_report("exit");
    }
    if (model.gte_enabled && !model.gte_entries) {
        fprintf(stderr,
                "sf2000-cache-model: gtemap matched no GTE entries "
                "(stale layout or workload did not enter GTE)\n");
    }
    cache_destroy(&model.icache);
    cache_destroy(&model.dcache);
    free(model.rec_line_bits);
    model.rec_line_bits = NULL;
    model.rec_line_count = 0;
    free(model.hot_table);
    model.hot_table = NULL;
    if (model.out) {
        fclose(model.out);
        model.out = NULL;
    }
    free_translation_blocks();
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    uint64_t size = 16384;
    uint64_t line = 16;
    uint64_t ways = 2;
    /* QPSX's Linux NOMMU PIE currently reports this recMem address in its
     * startup fingerprint.  The old 0x80800000 default overlapped kernel
     * text, producing convincing but completely wrong “rec” samples. */
    /* Static recMem is linked in the executable's .bss.  Small source/flag
     * changes move it by a few hundred bytes, while generated code remains
     * in the otherwise-unused 0x832xxxxx window.  'auto' uses a conservative
     * 8.5 MiB window so cache A/B runs do not silently classify the first
     * block as helper code whenever the core layout changes. */
    uint64_t rec_base = UINT64_C(0x83200000);
    uint64_t rec_size = UINT64_C(0x00880000);
    uint64_t core_base = UINT64_C(0x83000000);
    uint64_t core_size = UINT64_C(0x00120000);
    int rec_base_auto = 1;
    int index;
    const char *out_path = NULL;

    model.sample = UINT64_C(10000000);
    model.instruction_penalty = 8;
    model.data_penalty = 12;
    model.d_vipt = 1;
    model.i_vipt = 1;
    model.rec_only = 0;
    model.core_only = 0;
    model.emu_only = 0;
    model.phase_rec = 0;
    model.phase_active = 1;
    snprintf(model.label, sizeof(model.label), "sf2000");
    for (index = 0; index < argc; index++) {
        char *equals = strchr(argv[index], '=');
        const char *key = argv[index];
        const char *value = equals ? equals + 1 : "";
        size_t key_length = equals ? (size_t)(equals - argv[index]) :
                                     strlen(argv[index]);

        if (key_length == 4 && strncmp(key, "size", key_length) == 0) {
            size = parse_u64(value, size);
        } else if (key_length == 4 && strncmp(key, "line", key_length) == 0) {
            line = parse_u64(value, line);
        } else if (key_length == 4 && strncmp(key, "ways", key_length) == 0) {
            ways = parse_u64(value, ways);
        } else if (key_length == 6 && strncmp(key, "sample", key_length) == 0) {
            model.sample = parse_u64(value, model.sample);
        } else if (key_length == 8 && strncmp(key, "ipenalty", key_length) == 0) {
            model.instruction_penalty = parse_u64(value, model.instruction_penalty);
        } else if (key_length == 8 && strncmp(key, "dpenalty", key_length) == 0) {
            model.data_penalty = parse_u64(value, model.data_penalty);
        } else if (key_length == 5 && strncmp(key, "dmode", key_length) == 0) {
            if (strcmp(value, "vipt") == 0) {
                model.d_vipt = 1;
            } else if (strcmp(value, "pipt") == 0) {
                model.d_vipt = 0;
            } else {
                fprintf(stderr, "sf2000-cache-model: dmode must be vipt or pipt\n");
                return -1;
            }
        } else if (key_length == 5 && strncmp(key, "imode", key_length) == 0) {
            if (strcmp(value, "vipt") == 0) {
                model.i_vipt = 1;
            } else if (strcmp(value, "pipt") == 0) {
                model.i_vipt = 0;
            } else {
                fprintf(stderr, "sf2000-cache-model: imode must be vipt or pipt\n");
                return -1;
            }
        } else if (key_length == 5 && strncmp(key, "phase", key_length) == 0) {
            if (strcmp(value, "boot") == 0) {
                model.phase_rec = 0;
                model.phase_active = 1;
            } else if (strcmp(value, "rec") == 0) {
                model.phase_rec = 1;
                model.phase_active = 0;
            } else {
                fprintf(stderr, "sf2000-cache-model: phase must be boot or rec\n");
                return -1;
            }
        } else if (key_length == 5 && strncmp(key, "scope", key_length) == 0) {
            if (strcmp(value, "all") == 0) {
                model.rec_only = 0;
                model.core_only = 0;
                model.emu_only = 0;
            } else if (strcmp(value, "rec") == 0) {
                model.rec_only = 1;
                model.core_only = 0;
                model.emu_only = 0;
            } else if (strcmp(value, "core") == 0) {
                model.rec_only = 0;
                model.core_only = 1;
                model.emu_only = 0;
            } else if (strcmp(value, "emu") == 0) {
                model.rec_only = 0;
                model.core_only = 0;
                model.emu_only = 1;
            } else {
                fprintf(stderr,
                        "sf2000-cache-model: scope must be all, rec, core or emu\n");
                return -1;
            }
        } else if (key_length == 3 && strncmp(key, "out", key_length) == 0) {
            out_path = value;
        } else if (key_length == 5 && strncmp(key, "label", key_length) == 0) {
            snprintf(model.label, sizeof(model.label), "%s", value);
        } else if (key_length == 8 && strncmp(key, "hotspots", key_length) == 0) {
            snprintf(model.hot_path, sizeof(model.hot_path), "%s", value);
        } else if (key_length == 6 && strncmp(key, "gtemap", key_length) == 0) {
            snprintf(model.gte_map_path, sizeof(model.gte_map_path), "%s",
                     value);
        } else if (key_length == 7 && strncmp(key, "coreelf", key_length) == 0) {
            snprintf(model.gte_core_elf, sizeof(model.gte_core_elf), "%s",
                     value);
        } else if (key_length == 7 && strncmp(key, "recbase", key_length) == 0) {
            if (strcmp(value, "auto") == 0) {
                rec_base = UINT64_C(0x83200000);
                rec_base_auto = 1;
            } else {
                rec_base = parse_u64(value, rec_base);
                rec_base_auto = 0;
            }
        } else if (key_length == 7 && strncmp(key, "recsize", key_length) == 0) {
            rec_size = parse_u64(value, rec_size);
        } else if (key_length == 8 && strncmp(key, "corebase", key_length) == 0) {
            core_base = parse_u64(value, core_base);
        } else if (key_length == 8 && strncmp(key, "coresize", key_length) == 0) {
            core_size = parse_u64(value, core_size);
        } else if (key_length == 11 && strncmp(key, "frameopcode", key_length) == 0) {
            model.frame_opcode = (uint32_t)parse_u64(value, 0);
        } else if (key_length == 11 && strncmp(key, "framereport", key_length) == 0) {
            model.frame_report_period = parse_u64(value, 0);
        } else if (key_length == 9 && strncmp(key, "framestop", key_length) == 0) {
            model.frame_stop = parse_u64(value, 0);
        } else {
            fprintf(stderr, "sf2000-cache-model: unknown option '%s'\n",
                    argv[index]);
            return -1;
        }
    }
    if (!out_path || !*out_path || model.sample == 0 || rec_size == 0 ||
        rec_base > UINT64_MAX - rec_size ||
        core_size == 0 || core_base > UINT64_MAX - core_size ||
        cache_init(&model.icache, size, line, ways) != 0 ||
        cache_init(&model.dcache, size, line, ways) != 0) {
        fprintf(stderr,
                "sf2000-cache-model: invalid profile or missing out= path "
                "(size=%" PRIu64 " line=%" PRIu64 " ways=%" PRIu64 ")\n",
                size, line, ways);
        cache_destroy(&model.icache);
        cache_destroy(&model.dcache);
        return -1;
    }
    model.rec_base = rec_base;
    model.rec_end = rec_base + rec_size;
    model.rec_configured_base = rec_base;
    model.core_base = core_base;
    model.core_end = core_base + core_size;
    model.rec_base_auto = rec_base_auto;
    model.rec_base_was_auto = rec_base_auto;
    model.rec_base_discovered = 0;
    model.rec_base_mismatch = 0;
    model.rec_base_evidence_pc = 0;
    if (model.gte_map_path[0] && load_gte_map(model.gte_map_path) != 0) {
        cache_destroy(&model.icache);
        cache_destroy(&model.dcache);
        return -1;
    }
    /* A core-only run is deliberately boot-inclusive for the selected text:
     * waiting for a recRAM block would skip the static executable TBs that we
     * want to measure. */
    if (model.core_only) {
        model.phase_rec = 0;
        model.phase_active = 1;
    }
    model.rec_line_count = (size_t)((rec_size + line - 1) / line);
    if (model.rec_line_count > SIZE_MAX - 7 ||
        !(model.rec_line_bits = calloc((model.rec_line_count + 7) / 8, 1))) {
        fprintf(stderr, "sf2000-cache-model: rec footprint allocation failed\n");
        cache_destroy(&model.icache);
        cache_destroy(&model.dcache);
        return -1;
    }
    model.rec_pc_low = UINT64_MAX;
    if (model.hot_path[0]) {
        model.hot_capacity = 65536;
        model.hot_table = calloc(model.hot_capacity, sizeof(*model.hot_table));
        if (!model.hot_table) {
            fprintf(stderr, "sf2000-cache-model: hotspot table allocation failed\n");
            cache_destroy(&model.icache);
            cache_destroy(&model.dcache);
            free(model.rec_line_bits);
            model.rec_line_bits = NULL;
            model.rec_line_count = 0;
            return -1;
        }
    }
    model.out = fopen(out_path, "w");
    if (!model.out) {
        fprintf(stderr, "sf2000-cache-model: cannot open %s: %s\n", out_path,
                strerror(errno));
        cache_destroy(&model.icache);
        cache_destroy(&model.dcache);
        free(model.rec_line_bits);
        model.rec_line_bits = NULL;
        model.rec_line_count = 0;
        return -1;
    }
    fprintf(model.out,
            "# sf2000-cache-model version=%d target=%s profile=size=%" PRIu64
            ",line=%" PRIu64 ",ways=%" PRIu64 " sample=%" PRIu64
            " ipenalty=%" PRIu64 " dpenalty=%" PRIu64
            " dmode=%s address=i-vaddr,d=%s recbase=0x%016" PRIx64
            " recbase_configured=0x%016" PRIx64
            " recbase_mode=%s recsize=0x%016" PRIx64
            " imode=%s phase=%s scope=%s corebase=0x%016" PRIx64
            " coresize=0x%016" PRIx64
            " frameopcode=0x%08" PRIx32
            " framereport=%" PRIu64 " framestop=%" PRIu64
            " coverage=%s gte_map=%s gte_map_entries=%" PRIu64
            " gte_core_sha256=%s\n",
            CACHE_MODEL_REPORT_VERSION,
            info->target_name ? info->target_name : "unknown", size, line,
            ways, model.sample, model.instruction_penalty, model.data_penalty,
            model.d_vipt ? "vipt" : "pipt", model.d_vipt ? "vipt" : "phys",
            rec_base, model.rec_configured_base,
            rec_base_auto ? "auto-first-rec-tb" : "configured", rec_size,
            model.i_vipt ? "vipt" : "pipt",
            model.phase_rec ? "rec" : "boot", scope_label(),
            model.core_base, model.core_end - model.core_base,
            model.frame_opcode, model.frame_report_period, model.frame_stop,
            coverage_label(), model.gte_enabled ? model.gte_map_path : "off",
            model.gte_map_entries,
            model.gte_enabled ? model.gte_core_sha256 : "none");
    fflush(model.out);
    model.next_sample = model.sample;
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
