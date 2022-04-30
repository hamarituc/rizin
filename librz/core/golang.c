// 

#include <rz_core.h>

#define GO_1_2 (12)
#define GO_1_16 (116)
#define GO_1_18 (118)

#define IS_GOPCLNTAB_1_2_LE(x) (x[0] == 0xfb && x[1] == 0xff && x[2] == 0xff && x[3] == 0xff)
#define IS_GOPCLNTAB_1_2_BE(x) (x[3] == 0xfb && x[2] == 0xff && x[1] == 0xff && x[0] == 0xff)
#define IS_GOPCLNTAB_1_16_LE(x) (x[0] == 0xfa && x[1] == 0xff && x[2] == 0xff && x[3] == 0xff)
#define IS_GOPCLNTAB_1_16_BE(x) (x[3] == 0xfa && x[2] == 0xff && x[1] == 0xff && x[0] == 0xff)
#define IS_GOPCLNTAB_1_18_LE(x) (x[0] == 0xf0 && x[1] == 0xff && x[2] == 0xff && x[3] == 0xff)
#define IS_GOPCLNTAB_1_18_BE(x) (x[3] == 0xf0 && x[2] == 0xff && x[1] == 0xff && x[0] == 0xff)

typedef struct go_pc_line_table_t {
	RzIO *io;
	ut64 vaddr;
	ut32 size;
	ut16 version;
	bool big_endian;
	// quantum is the minimal unit for a program counter (1 on x86, 4 on most other systems).
	// i386: 1, amd64: 1, arm: 4, arm64: 4, mips: 4, mips: 4, ppc: 4, riscv: 4, s390x: 2, wasm: 1
	ut32 quantum;
	ut32 ptrsize;
	ut32 nfunctab;
	ut32 nfiletab;
	ut32 functabsize;
	// data offsets
	ut64 funcnametab;
	ut64 cutab;
	ut64 filetab;
	ut64 pctab;
	ut64 funcdata;
	ut64 functab;
} GoPcLnTab;

ut32 go_func_tab_field_size(GoPcLnTab *pclntab) {
	if (pclntab->version >= GO_1_18) {
		return 4;
	}
	return pclntab->ptrsize;
}

ut64 go_uintptr(GoPcLnTab *pclntab, ut8 *bytes) {
	if (pclntab->ptrsize == 4) {
		return rz_read_ble32(bytes, pclntab->big_endian);
	}
	return rz_read_ble64(bytes, pclntab->big_endian);
}

ut64 go_offset(GoPcLnTab *pclntab, ut32 n_word) {
	ut8 bytes[8];
	ut64 location = pclntab->vaddr + 8 + (n_word * pclntab->ptrsize);
	if (!rz_io_nread_at(pclntab->io, location, bytes, sizeof(bytes))) {
		return UT64_MAX;
	}
	return go_uintptr(pclntab, bytes);
}

ut64 go_data(GoPcLnTab *pclntab, ut32 n_word) {
	ut64 offset = go_offset(pclntab, n_word);
	if (offset == UT64_MAX) {
		return UT64_MAX;
	}
	return pclntab->vaddr + offset;
}

#define is_addr_outside(x) ((x) <= begin || (x) >= end)
static bool is_pclntab_valid(GoPcLnTab *pclntab) {
	ut64 begin = pclntab->vaddr + 8;
	ut64 end = pclntab->vaddr + pclntab->size;

	if (pclntab->version > GO_1_2) {
		if (is_addr_outside(pclntab->funcnametab)) {
			rz_warn_if_reached();
			return false;
		} else if (is_addr_outside(pclntab->cutab)) {
			rz_warn_if_reached();
			return false;
		} else if (is_addr_outside(pclntab->pctab)) {
		rz_warn_if_reached();
		return false;
		} else if (is_addr_outside(pclntab->funcdata)) {
			rz_warn_if_reached();
			return false;
		}
	}

	if (is_addr_outside(pclntab->filetab)) {
		rz_warn_if_reached();
		return false;
	} else if (is_addr_outside(pclntab->functab)) {
		rz_warn_if_reached();
		return false;
	} else if (pclntab->functabsize >= (pclntab->size - 8)) {
		rz_warn_if_reached();
		return false;
	}

	return true;
}
#undef is_addr_outside

static void add_new_func_symbol(RzCore *core, const char *name, ut64 vaddr) {
	RzBinFile *bf = rz_bin_cur(core->bin);
	if (!bf || !bf->o || !bf->o->symbols) {
		return;
	}
	ut64 paddr = rz_io_v2p(core->io, vaddr);
	RzBinSymbol *symbol = rz_bin_symbol_new(name, paddr, vaddr);
	if (!symbol) {
		RZ_LOG_ERROR("Failed allocate new go symbol\n");
		return;
	}

	symbol->bind = RZ_BIN_BIND_GLOBAL_STR;
	symbol->type = RZ_BIN_TYPE_FUNC_STR;
	if (!rz_list_append(bf->o->symbols, symbol)) {
		RZ_LOG_ERROR("Failed append new go symbol to symbols list\n");
		rz_bin_symbol_free(symbol);
	}
}

static void debug_pclntab(RzCore *core, GoPcLnTab *pclntab) {
	rz_core_notify_error(core, "---- location             0x%" PFMT64x, pclntab->vaddr);
	rz_core_notify_error(core, "---- size                 0x%x", pclntab->size);
	rz_core_notify_error(core, "---- pc quantum           %u", pclntab->quantum);
	rz_core_notify_error(core, "---- pointer size         %u", pclntab->ptrsize);
	rz_core_notify_error(core, "---- pclntab->nfunctab    %u", pclntab->nfunctab);
	rz_core_notify_error(core, "---- pclntab->nfiletab    %u", pclntab->nfiletab);
	rz_core_notify_error(core, "---- pclntab->funcnametab 0x%" PFMT64x, pclntab->funcnametab);
	rz_core_notify_error(core, "---- pclntab->cutab       0x%" PFMT64x, pclntab->cutab);
	rz_core_notify_error(core, "---- pclntab->filetab     0x%" PFMT64x, pclntab->filetab);
	rz_core_notify_error(core, "---- pclntab->pctab       0x%" PFMT64x, pclntab->pctab);
	rz_core_notify_error(core, "---- pclntab->funcdata    0x%" PFMT64x, pclntab->funcdata);
	rz_core_notify_error(core, "---- pclntab->functab     0x%" PFMT64x, pclntab->functab);
	rz_core_notify_error(core, "---- pclntab->functabsize 0x%x", pclntab->functabsize);
}

static ut32 core_autoname_all_golang_functions_go_1_18(RzCore *core, GoPcLnTab *pclntab) {
	rz_core_notify_done(core, "Found go 1.18 pclntab section.");
	ut8 tmp8[8];
	char name[256];
	char *flag = NULL;
	ut32 num_syms = 0;
	ut64 func_ptr = 0, func_off = 0, name_ptr = 0, name_off = 0;

	pclntab->nfunctab = (ut32)go_offset(pclntab, 0);
	pclntab->nfiletab = (ut32)go_offset(pclntab, 1);
	pclntab->funcnametab = go_data(pclntab, 3);
	pclntab->cutab = go_data(pclntab, 4);
	pclntab->filetab = go_data(pclntab, 5);
	pclntab->pctab = go_data(pclntab, 6);
	pclntab->funcdata = go_data(pclntab, 7);
	pclntab->functab = go_data(pclntab, 7);
	pclntab->functabsize = ((pclntab->nfunctab * 2) + 1) * go_func_tab_field_size(pclntab);

	if (!is_pclntab_valid(pclntab)) {
		rz_core_notify_error(core, "Invalid go pclntab (invalid table).");
		return 0;
	}
	debug_pclntab(core, pclntab);

	rz_flag_space_push(core->flags, RZ_FLAGS_FS_SYMBOLS);
	for (ut32 i = 0, ptr = 0; i < pclntab->nfunctab; ++i, ptr += (pclntab->ptrsize * 2)) {
		ut64 offset = pclntab->functab + ptr;

		// reads the value of the function pointer
		rz_core_notify_error(core, "Reading at 0x%08" PFMT64x "", offset);
		if (!rz_io_nread_at(pclntab->io, offset, tmp8, sizeof(tmp8))) {
			RZ_LOG_ERROR("Failed to read go function address at 0x%08" PFMT64x "\n", offset);
			break;
		}
		func_ptr = go_uintptr(pclntab, tmp8);
		rz_core_notify_error(core, "func_ptr 0x%08x", func_ptr);

		// reads the value of the function data offset
		rz_core_notify_error(core, "Reading at 0x%08" PFMT64x "", offset + pclntab->ptrsize);
		if (!rz_io_nread_at(pclntab->io, offset + pclntab->ptrsize, tmp8, sizeof(tmp8))) {
			RZ_LOG_ERROR("Failed to read go function data address at 0x%08" PFMT64x "\n", offset);
			break;
		}
		func_off = rz_read_ble32(tmp8, pclntab->big_endian);
		rz_core_notify_error(core, "func_off 0x%08x", func_off);
		
		name_ptr = pclntab->functab + func_off + pclntab->ptrsize;
		rz_core_notify_error(core, "Reading at 0x%08" PFMT64x "", name_ptr);
		// reads the location of the function name within funcnametab
		if (!rz_io_nread_at(pclntab->io, name_ptr, tmp8, sizeof(ut32))) {
			RZ_LOG_ERROR("Failed to read go function name address at 0x%08" PFMT64x "\n", offset);
			break;
		}

		rz_core_notify_error(core, "name_off 0x%08x", name_off);
		name_off = pclntab->funcnametab + rz_read_ble32(tmp8, pclntab->big_endian);

		// ignore failures, we can always create a new name.
		memset(name, 0, sizeof(name));
		(void)rz_io_nread_at(pclntab->io, name_off, (ut8 *)name, sizeof(name));
		name[sizeof(name) - 1] = 0;
		RZ_LOG_INFO("Recovered symbol at 0x%08" PFMT64x " with name '%s'\n", func_ptr, name);
		rz_core_notify_error(core, "Recovered symbol at 0x%08" PFMT64x " with name '%s'", func_ptr, name);

		if (strlen(name) > 0) {
			// always add it before filtering the name.
			add_new_func_symbol(core, name, func_ptr);
			rz_name_filter(name, 0, true);
		} else {
			rz_strf(name, "fcn.pclntab.unknown.%08" PFMT64x, func_ptr);
			add_new_func_symbol(core, name, func_ptr);
		}

		flag = rz_str_newf("sym.go.%s", name);
		rz_flag_set(core->flags, flag, func_ptr, 1);
		free(flag);

		num_syms++;
		break;
	}
	rz_flag_space_pop(core->flags);

	return num_syms;
}

static ut32 core_autoname_all_golang_functions_go_1_16(RzCore *core, GoPcLnTab *pclntab) {
	rz_core_notify_done(core, "Found go 1.16 pclntab section.");
	ut8 tmp8[8];
	char name[256];
	char *flag = NULL;
	ut32 num_syms = 0;
	ut64 func_ptr = 0, func_off = 0, name_ptr = 0, name_off = 0;

	pclntab->nfunctab = (ut32)go_offset(pclntab, 0);
	pclntab->nfiletab = (ut32)go_offset(pclntab, 1);
	pclntab->funcnametab = go_data(pclntab, 2);
	pclntab->cutab = go_data(pclntab, 3);
	pclntab->filetab = go_data(pclntab, 4);
	pclntab->pctab = go_data(pclntab, 5);
	pclntab->funcdata = go_data(pclntab, 6);
	pclntab->functab = go_data(pclntab, 6);
	pclntab->functabsize = ((pclntab->nfunctab * 2) + 1) * go_func_tab_field_size(pclntab);

	if (!is_pclntab_valid(pclntab)) {
		rz_core_notify_error(core, "Invalid go pclntab (invalid table).");
		return 0;
	}

	debug_pclntab(core, pclntab);

	rz_flag_space_push(core->flags, RZ_FLAGS_FS_SYMBOLS);
	for (ut32 i = 0, ptr = 0; i < pclntab->nfunctab; ++i, ptr += (pclntab->ptrsize * 2)) {
		ut64 offset = pclntab->functab + ptr;

		// reads the value of the function pointer
		if (!rz_io_nread_at(pclntab->io, offset, tmp8, sizeof(tmp8))) {
			RZ_LOG_ERROR("Failed to read go function address at 0x%08" PFMT64x "\n", offset);
			break;
		}
		func_ptr = go_uintptr(pclntab, tmp8);

		// reads the value of the function data offset
		if (!rz_io_nread_at(pclntab->io, offset + pclntab->ptrsize, tmp8, sizeof(tmp8))) {
			RZ_LOG_ERROR("Failed to read go function data address at 0x%08" PFMT64x "\n", offset);
			break;
		}
		func_off = go_uintptr(pclntab, tmp8);
		
		name_ptr = pclntab->functab + func_off + pclntab->ptrsize;
		// reads the location of the function name within funcnametab
		if (!rz_io_nread_at(pclntab->io, name_ptr, tmp8, sizeof(ut32))) {
			RZ_LOG_ERROR("Failed to read go function name address at 0x%08" PFMT64x "\n", offset);
			break;
		}

		name_off = pclntab->funcnametab + rz_read_ble32(tmp8, pclntab->big_endian);

		// ignore failures, we can always create a new name.
		memset(name, 0, sizeof(name));
		(void)rz_io_nread_at(pclntab->io, name_off, (ut8 *)name, sizeof(name));
		name[sizeof(name) - 1] = 0;
		RZ_LOG_INFO("Recovered symbol at 0x%08" PFMT64x " with name '%s'\n", func_ptr, name);

		if (strlen(name) > 0) {
			// always add it before filtering the name.
			add_new_func_symbol(core, name, func_ptr);
			rz_name_filter(name, 0, true);
		} else {
			rz_strf(name, "fcn.pclntab.unknown.%08" PFMT64x, func_ptr);
			add_new_func_symbol(core, name, func_ptr);
		}

		flag = rz_str_newf("sym.go.%s", name);
		rz_flag_set(core->flags, flag, func_ptr, 1);
		free(flag);

		num_syms++;
	}
	rz_flag_space_pop(core->flags);

	return num_syms;
}

// Valid for golang 1.2 -> 1.15
static ut32 core_autoname_all_golang_functions_go_1_2(RzCore *core, GoPcLnTab *pclntab) {
	rz_core_notify_done(core, "Found go 1.12 pclntab section.");
	ut8 tmp8[8];
	char name[256];
	char *flag = NULL;
	ut32 num_syms = 0;
	ut64 func_ptr = 0, func_off = 0, name_ptr = 0, name_off = 0;

	if (!rz_io_nread_at(pclntab->io, pclntab->vaddr + 8, tmp8, sizeof(tmp8))) {
		return 0;
	}

	pclntab->nfunctab = (ut32)go_uintptr(pclntab, tmp8);
	pclntab->functab = pclntab->vaddr + 8 + pclntab->ptrsize;
	pclntab->functabsize = ((pclntab->nfunctab * 2) + 1) * go_func_tab_field_size(pclntab);

	if (!rz_io_nread_at(pclntab->io, pclntab->functab + pclntab->functabsize, tmp8, sizeof(ut32))) {
		RZ_LOG_ERROR("Failed to read go functab at 0x%08" PFMT64x "\n", pclntab->functab);
		return 0;
	}

	pclntab->filetab = pclntab->vaddr + rz_read_ble32(tmp8, pclntab->big_endian);
	if (!rz_io_nread_at(pclntab->io, pclntab->filetab, tmp8, sizeof(ut32))) {
		RZ_LOG_ERROR("Failed to read go filetab at 0x%08" PFMT64x "\n", pclntab->filetab);
		return 0;
	}
	pclntab->nfiletab = rz_read_ble32(tmp8, pclntab->big_endian);

	debug_pclntab(core, pclntab);
	if (!is_pclntab_valid(pclntab)) {
		rz_core_notify_error(core, "Invalid go pclntab (invalid table).");
		return 0;
	}

	rz_flag_space_push(core->flags, RZ_FLAGS_FS_SYMBOLS);
	for (ut32 i = 0, ptr = 0; i < pclntab->nfunctab; ++i, ptr += (pclntab->ptrsize * 2)) {
		ut64 offset = pclntab->functab + ptr;

		// reads the value of the function pointer
		if (!rz_io_nread_at(pclntab->io, offset, tmp8, sizeof(tmp8))) {
			RZ_LOG_ERROR("Failed to read go function address at 0x%08" PFMT64x "\n", offset);
			break;
		}
		func_ptr = go_uintptr(pclntab, tmp8);

		// reads the value of the function data offset
		if (!rz_io_nread_at(pclntab->io, offset + pclntab->ptrsize, tmp8, sizeof(tmp8))) {
			RZ_LOG_ERROR("Failed to read go function address data at 0x%08" PFMT64x "\n", offset);
			break;
		}
		func_off = go_uintptr(pclntab, tmp8);
		
		name_ptr = pclntab->vaddr + func_off + pclntab->ptrsize;
		// reads the location of the function name within funcnametab
		if (!rz_io_nread_at(pclntab->io, name_ptr, tmp8, sizeof(ut32))) {
			RZ_LOG_ERROR("Failed to read go function name address at 0x%08" PFMT64x "\n", offset);
			break;
		}

		name_off = pclntab->vaddr + rz_read_ble32(tmp8, pclntab->big_endian);

		// ignore failures, we can always create a new name.
		memset(name, 0, sizeof(name));
		(void)rz_io_nread_at(pclntab->io, name_off, (ut8 *)name, sizeof(name));
		name[sizeof(name) - 1] = 0;
		RZ_LOG_INFO("Recovered symbol at 0x%08" PFMT64x " with name '%s'\n", func_ptr, name);

		if (strlen(name) > 0) {
			// always add it before filtering the name.
			add_new_func_symbol(core, name, func_ptr);
			rz_name_filter(name, 0, true);
		} else {
			rz_strf(name, "fcn.pclntab.unknown.%08" PFMT64x, func_ptr);
			add_new_func_symbol(core, name, func_ptr);
		}

		flag = rz_str_newf("sym.go.%s", name);
		rz_flag_set(core->flags, flag, func_ptr, 1);
		free(flag);

		num_syms++;
	}
	rz_flag_space_pop(core->flags);

	return num_syms;
}

/**
 * \brief      reads pclntab section in go binaries to recover function names and adds them as sym.go.* flags
 * Follows the code https://github.com/golang/go/blob/master/src/debug/gosym/pclntab.go#L188
 * \param      core  The RzCore to use
 */
RZ_API void rz_core_analysis_autoname_all_golang_fcns(RzCore *core) {
	RzList *section_list = rz_bin_get_sections(core->bin);
	RzListIter *iter;
	RzBinSection *section;
	ut32 num_syms = 0;
	GoPcLnTab pclntab = { 0 };
	ut8 header[8] = { 0 };

	rz_list_foreach (section_list, iter, section) {
		// on ELF files the pclntab sections is named .gopclntab, but on macho is __gopclntab
		if (section->vsize >= 16 && strstr(section->name, "gopclntab")) {
			pclntab.vaddr = section->vaddr;
			pclntab.size = section->vsize;
			break;
		}
	}

	if (!pclntab.vaddr) {
		rz_core_notify_done(core, "Could not find go pclntab section");
		return;
	} else if (!rz_io_nread_at(core->io, pclntab.vaddr, header, sizeof(header))) {
		RZ_LOG_ERROR("Failed to read gopclntab at address %" PFMT64x "\n", pclntab.vaddr);
		return;
	} else if (header[4] != 0 || header[5] != 0 ||
		(header[6] != 1 && header[6] != 2 && header[6] != 4) || // pc quantum
		(header[7] != 4 && header[7] != 8)) { // pointer size
		rz_core_notify_error(core, "Invalid go pclntab (invalid pc quantum or pointer size).");
		return;
	}

	pclntab.io = core->io;
	pclntab.quantum = header[6];
	pclntab.ptrsize = header[7];

	if (IS_GOPCLNTAB_1_18_BE(header) || IS_GOPCLNTAB_1_18_LE(header)) {
		pclntab.version = GO_1_18;
		pclntab.big_endian = IS_GOPCLNTAB_1_18_BE(header);
		num_syms = core_autoname_all_golang_functions_go_1_18(core, &pclntab);
	} else if (IS_GOPCLNTAB_1_16_BE(header) || IS_GOPCLNTAB_1_16_LE(header)) {
		pclntab.version = GO_1_16;
		pclntab.big_endian = IS_GOPCLNTAB_1_16_BE(header);
		num_syms = core_autoname_all_golang_functions_go_1_16(core, &pclntab);
	} else if (IS_GOPCLNTAB_1_2_BE(header) || IS_GOPCLNTAB_1_2_LE(header)) {
		pclntab.version = GO_1_2;
		pclntab.big_endian = IS_GOPCLNTAB_1_2_BE(header);
		num_syms = core_autoname_all_golang_functions_go_1_2(core, &pclntab);
	} else {
		ut32 magic = rz_read_be32(header);
		rz_core_notify_error(core, "Invalid go pclntab (unknown version: 0x%x).", magic);
		return;
	}

	if (num_syms) {
		rz_core_notify_done(core, "Found %d symbols and saved them at sym.go.*", num_syms);
	} else {
		rz_core_notify_error(core, "No sym.go.* symbols found.");
	}
}
