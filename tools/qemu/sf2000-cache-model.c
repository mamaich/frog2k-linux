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

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

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
    uint64_t executions;
    uint64_t i_misses;
    uint64_t d_accesses;
    uint64_t d_misses;
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

typedef struct {
    uint64_t *pc;
    unsigned char *class_id;
    HotspotEntry **hot;
    size_t count;
} TranslationBlock;

typedef struct {
    HotspotEntry *hot;
    uint64_t pc;
} MemData;

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
    uint64_t d_misses;
    uint64_t stores;
    uint64_t mmio;
    uint64_t sample;
    uint64_t next_sample;
    uint64_t sample_no;
    uint64_t previous_instructions;
    uint64_t previous_i_misses;
    uint64_t previous_d_misses;
    uint64_t instruction_penalty;
    uint64_t data_penalty;
    uint64_t insn_classes[INSN_CLASS_COUNT];
    uint64_t rec_base;
    uint64_t rec_end;
    uint64_t rec_i_accesses;
    uint64_t rec_i_misses;
    uint64_t rec_d_accesses;
    uint64_t rec_d_misses;
    int d_vipt;
    int i_vipt;
    int phase_rec;
    int phase_active;
    int have_previous;
    HotspotEntry *hot_table;
    size_t hot_capacity;
    char hot_path[PATH_MAX];
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

static int cache_access(Cache *cache, uint64_t address);
static int cache_access_indexed(Cache *cache, uint64_t tag_address,
                                uint64_t index_address);

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
    size_t index;

    cache_reset(&model.icache);
    cache_reset(&model.dcache);
    model.instructions = 0;
    model.i_accesses = 0;
    model.i_misses = 0;
    model.d_accesses = 0;
    model.d_lines = 0;
    model.d_misses = 0;
    model.stores = 0;
    model.mmio = 0;
    model.sample_no = 0;
    model.next_sample = model.sample;
    model.previous_instructions = 0;
    model.previous_i_misses = 0;
    model.previous_d_misses = 0;
    model.have_previous = 0;
    memset(model.insn_classes, 0, sizeof(model.insn_classes));
    model.rec_i_accesses = 0;
    model.rec_i_misses = 0;
    model.rec_d_accesses = 0;
    model.rec_d_misses = 0;
    if (model.hot_table) {
        for (index = 0; index < model.hot_capacity; index++) {
            model.hot_table[index].executions = 0;
            model.hot_table[index].i_misses = 0;
            model.hot_table[index].d_accesses = 0;
            model.hot_table[index].d_misses = 0;
        }
    }
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
            "# sf2000-cache-model hotspots version=3 sample=%" PRIu64
            " kind=%s instructions=%" PRIu64 " label=%s\n",
            model.sample_no, kind, model.instructions, model.label);
    for (rank = 0; rank < sizeof(top) / sizeof(top[0]); rank++) {
        HotspotEntry *entry = top[rank];

        if (!entry) {
            break;
        }
        fprintf(out,
                "hotspot sample=%" PRIu64 " rank=%zu pc=0x%016" PRIx64
                " executions=%" PRIu64 " i_misses=%" PRIu64
                " d_accesses=%" PRIu64 " d_misses=%" PRIu64
                " penalty=%" PRIu64 "\n",
                model.sample_no, rank + 1, entry->pc, entry->executions,
                entry->i_misses,
                entry->d_accesses, entry->d_misses, hotspot_penalty(entry));
    }
    fflush(out);
    fclose(out);
}

static void write_report(const char *kind)
{
    uint64_t estimated_cycles;
    uint64_t i_miss_ppm;
    uint64_t d_miss_ppm;
    uint64_t rec_i_ppm;
    uint64_t rec_d_ppm;
    uint64_t rec_i_miss_ppm;
    uint64_t rec_d_miss_ppm;
    uint64_t delta_instructions;
    uint64_t delta_i_misses;
    uint64_t delta_d_misses;

    if (!model.out) {
        return;
    }
    estimated_cycles = model.instructions +
        model.i_misses * model.instruction_penalty +
        model.d_misses * model.data_penalty;
    i_miss_ppm = ratio_ppm(model.i_misses, model.i_accesses);
    d_miss_ppm = ratio_ppm(model.d_misses, model.d_lines);
    rec_i_ppm = ratio_ppm(model.rec_i_accesses, model.i_accesses);
    rec_d_ppm = ratio_ppm(model.rec_d_accesses, model.d_accesses);
    rec_i_miss_ppm = ratio_ppm(model.rec_i_misses, model.rec_i_accesses);
    rec_d_miss_ppm = ratio_ppm(model.rec_d_misses, model.rec_d_accesses);
    if (model.have_previous) {
        delta_instructions = model.instructions - model.previous_instructions;
        delta_i_misses = model.i_misses - model.previous_i_misses;
        delta_d_misses = model.d_misses - model.previous_d_misses;
    } else {
        delta_instructions = model.instructions;
        delta_i_misses = model.i_misses;
        delta_d_misses = model.d_misses;
    }
    model.sample_no++;
    fprintf(model.out,
            "sample=%" PRIu64 " kind=%s label=%s instructions=%" PRIu64
            " i_accesses=%" PRIu64 " i_misses=%" PRIu64
            " d_accesses=%" PRIu64 " d_lines=%" PRIu64
            " d_misses=%" PRIu64 " stores=%" PRIu64 " mmio=%" PRIu64
            " i_miss_ppm=%" PRIu64 " d_miss_ppm=%" PRIu64
            " rec_i_ppm=%" PRIu64 " rec_d_ppm=%" PRIu64
            " rec_i_miss_ppm=%" PRIu64 " rec_d_miss_ppm=%" PRIu64
            " branches=%" PRIu64 " jumps=%" PRIu64
            " loads=%" PRIu64 " store_insns=%" PRIu64
            " muldiv=%" PRIu64 " cop2=%" PRIu64
            " rec_i_accesses=%" PRIu64 " rec_i_misses=%" PRIu64
            " rec_d_accesses=%" PRIu64 " rec_d_misses=%" PRIu64
            " est_cycles=%" PRIu64 " delta_instructions=%" PRIu64
            " delta_i_misses=%" PRIu64 " delta_d_misses=%" PRIu64 "\n",
            model.sample_no, kind, model.label, model.instructions,
            model.i_accesses, model.i_misses, model.d_accesses,
            model.d_lines, model.d_misses, model.stores, model.mmio,
            i_miss_ppm, d_miss_ppm, rec_i_ppm, rec_d_ppm,
            rec_i_miss_ppm, rec_d_miss_ppm,
            model.insn_classes[INSN_BRANCH], model.insn_classes[INSN_JUMP],
            model.insn_classes[INSN_LOAD], model.insn_classes[INSN_STORE],
            model.insn_classes[INSN_MULDIV], model.insn_classes[INSN_COP2],
            model.rec_i_accesses, model.rec_i_misses,
            model.rec_d_accesses, model.rec_d_misses,
            estimated_cycles, delta_instructions, delta_i_misses,
            delta_d_misses);
    fflush(model.out);
    model.previous_instructions = model.instructions;
    model.previous_i_misses = model.i_misses;
    model.previous_d_misses = model.d_misses;
    model.have_previous = 1;
    write_hotspots(kind);
}

static void maybe_report(void)
{
    if (model.sample == 0 || model.instructions < model.next_sample) {
        return;
    }
    do {
        model.next_sample += model.sample;
    } while (model.next_sample <= model.instructions);
    write_report("periodic");
}

static void tb_exec(unsigned int vcpu_index, void *userdata)
{
    TranslationBlock *tb = userdata;
    size_t index;

    (void)vcpu_index;
    for (index = 0; index < tb->count; index++) {
        if (model.phase_rec && !model.phase_active) {
            if (pc_is_rec_code(tb->pc[index])) {
                reset_measurement();
                model.phase_active = 1;
            } else {
                continue;
            }
        }
        model.instructions++;
        model.i_accesses++;
        model.insn_classes[tb->class_id[index]]++;
        if (pc_is_rec_code(tb->pc[index])) {
            model.rec_i_accesses++;
        }
        if (tb->hot && tb->hot[index]) {
            tb->hot[index]->executions++;
        }
        if (!cache_access_instruction(&model.icache, tb->pc[index])) {
            model.i_misses++;
            if (pc_is_rec_code(tb->pc[index])) {
                model.rec_i_misses++;
            }
            if (tb->hot && tb->hot[index]) {
                tb->hot[index]->i_misses++;
            }
        }
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

    (void)vcpu_index;
    if (model.phase_rec && !model.phase_active) {
        return;
    }
    if (userdata != &model) {
        MemData *mem = userdata;

        hot = mem->hot;
        pc = mem->pc;
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
    if (!cache_access_indexed(&model.dcache, address, index_address)) {
        model.d_misses++;
        if (pc_is_rec_code(pc)) {
            model.rec_d_misses++;
        }
        if (hot) {
            hot->d_misses++;
        }
    }
    if ((last_address >> model.dcache.line_shift) !=
        (address >> model.dcache.line_shift)) {
        model.d_lines++;
        if (!cache_access_indexed(&model.dcache, last_address,
                                  last_index_address)) {
            model.d_misses++;
            if (pc_is_rec_code(pc)) {
                model.rec_d_misses++;
            }
            if (hot) {
                hot->d_misses++;
            }
        }
    }
}

static void tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    TranslationBlock *data;
    size_t index;

    data = calloc(1, sizeof(*data));
    if (!data) {
        return;
    }
    data->count = qemu_plugin_tb_n_insns(tb);
    data->pc = calloc(data->count, sizeof(*data->pc));
    data->class_id = calloc(data->count, sizeof(*data->class_id));
    if (!data->pc || !data->class_id) {
        free(data->pc);
        free(data->class_id);
        free(data);
        return;
    }
    if (model.hot_table) {
        data->hot = calloc(data->count, sizeof(*data->hot));
        if (!data->hot) {
            free(data->pc);
            free(data->class_id);
            free(data);
            return;
        }
    }
    for (index = 0; index < data->count; index++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, index);
        void *mem_userdata = &model;

        data->pc[index] = qemu_plugin_insn_vaddr(insn);
        {
            unsigned char bytes[4] = { 0, 0, 0, 0 };
            uint32_t opcode = 0;

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

            if (mem) {
                mem->pc = data->pc[index];
                if (data->hot) {
                    data->hot[index] = hotspot_lookup(data->pc[index]);
                    mem->hot = data->hot[index];
                }
                mem_userdata = mem;
            }
        }
        qemu_plugin_register_vcpu_mem_cb(insn, mem_access,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW, mem_userdata);
    }
    qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS, data);
    (void)id;
}

static void plugin_exit(qemu_plugin_id_t id, void *userdata)
{
    (void)id;
    (void)userdata;
    write_report("exit");
    cache_destroy(&model.icache);
    cache_destroy(&model.dcache);
    free(model.hot_table);
    model.hot_table = NULL;
    if (model.out) {
        fclose(model.out);
        model.out = NULL;
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    uint64_t size = 16384;
    uint64_t line = 16;
    uint64_t ways = 2;
    uint64_t rec_base = UINT64_C(0x80800000);
    uint64_t rec_size = UINT64_C(0x00800000);
    int index;
    const char *out_path = NULL;

    model.sample = UINT64_C(10000000);
    model.instruction_penalty = 8;
    model.data_penalty = 12;
    model.d_vipt = 1;
    model.i_vipt = 1;
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
        } else if (key_length == 3 && strncmp(key, "out", key_length) == 0) {
            out_path = value;
        } else if (key_length == 5 && strncmp(key, "label", key_length) == 0) {
            snprintf(model.label, sizeof(model.label), "%s", value);
        } else if (key_length == 8 && strncmp(key, "hotspots", key_length) == 0) {
            snprintf(model.hot_path, sizeof(model.hot_path), "%s", value);
        } else if (key_length == 7 && strncmp(key, "recbase", key_length) == 0) {
            rec_base = parse_u64(value, rec_base);
        } else if (key_length == 7 && strncmp(key, "recsize", key_length) == 0) {
            rec_size = parse_u64(value, rec_size);
        } else {
            fprintf(stderr, "sf2000-cache-model: unknown option '%s'\n",
                    argv[index]);
            return -1;
        }
    }
    if (!out_path || !*out_path || model.sample == 0 || rec_size == 0 ||
        rec_base > UINT64_MAX - rec_size ||
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
    if (model.hot_path[0]) {
        model.hot_capacity = 65536;
        model.hot_table = calloc(model.hot_capacity, sizeof(*model.hot_table));
        if (!model.hot_table) {
            fprintf(stderr, "sf2000-cache-model: hotspot table allocation failed\n");
            cache_destroy(&model.icache);
            cache_destroy(&model.dcache);
            return -1;
        }
    }
    model.out = fopen(out_path, "w");
    if (!model.out) {
        fprintf(stderr, "sf2000-cache-model: cannot open %s: %s\n", out_path,
                strerror(errno));
        cache_destroy(&model.icache);
        cache_destroy(&model.dcache);
        return -1;
    }
    fprintf(model.out,
            "# sf2000-cache-model version=3 target=%s profile=size=%" PRIu64
            ",line=%" PRIu64 ",ways=%" PRIu64 " sample=%" PRIu64
            " ipenalty=%" PRIu64 " dpenalty=%" PRIu64
            " dmode=%s address=i-vaddr,d=%s recbase=0x%016" PRIx64
            " recsize=0x%016" PRIx64 " imode=%s phase=%s\n",
            info->target_name ? info->target_name : "unknown", size, line,
            ways, model.sample, model.instruction_penalty, model.data_penalty,
            model.d_vipt ? "vipt" : "pipt", model.d_vipt ? "vipt" : "phys",
            rec_base, rec_size, model.i_vipt ? "vipt" : "pipt",
            model.phase_rec ? "rec" : "boot");
    fflush(model.out);
    model.next_sample = model.sample;
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
