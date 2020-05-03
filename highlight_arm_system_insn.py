# -*- coding: utf-8 -*-
#
# Script to highlight low-level instructions in ARM code.
# Automatically comment coprocessor accesses (MRC*/MCR*) with documentation.
#
# Support up to ARMv7-A / ARMv8 processors.
#
# Author: Guillaume Delugré.
#

from idc import *
from idautils import *

global current_arch

SYSTEM_INSN = (
    # CPSR access
    "MSR", "MRS", "CPSIE", "CPSID",

    # CP access
    "MRC", "MRC2", "MRRC", "MRRC2", "MCR", "MCR2", "MCRR", "MCRR2", "LDC", "LDC2", "STC", "STC2", "CDP", "CDP2",

    # System (AArch64)
    "SYS", "SYSL", "IC", "DC", "AT", "TLBI",

    # Barriers,
    "DSB", "DMB", "ISB", "CLREX",

    # Misc
    "SRS", "VMRS", "VMSR", "DBG", "DCPS1", "DCPS2", "DCPS3", "DRPS",

    # Hints
    "YIELD", "WFE", "WFI", "SEV", "SEVL", "HINT"

    # Exceptions generating
    "BKPT", # AArch32
    "BRK",  # AArch64
    "SVC", "SWI", "SMC", "SMI", "HVC",

    # Special modes
    "ENTERX", "LEAVEX", "BXJ"

    # Return from exception
    "RFE",  # Aarch32
    "ERET", # Aarch64

    # Pointer authentication
    "PACDA", "PACDZA", "PACDB", "PACDZB", "PACGA",
    "PACIA", "PACIA1716", "PACIASP", "PACIAZ", "PACIZA",
    "PACIB", "PACIB1716", "PACIBSP", "PACIBZ", "PACIZB",
    "AUTDA", "AUTDZA", "AUTDB", "AUTDZB",
    "AUTIA", "AUTIA1716", "AUTIASP", "AUTIAZ", "AUTIZA",
    "AUTIB", "AUTIB1716", "AUTIBSP", "AUTIBZ", "AUTIZB",
)

# 64 bits registers accessible from AArch32.
# Extracted from the 00bet4 XML specifications for ARMv8.3.
COPROC_REGISTERS_64 = {
        # MMU registers
        ( "p15", 0, "c2"  )           : ( "TTBR0", "Translation Table Base Register 0" ),
        ( "p15", 1, "c2"  )           : ( "TTBR1", "Translation Table Base Register 1" ),
        ( "p15", 6, "c2"  )           : ( "VTTBR", "Virtualization Translation Table Base Register" ),
        ( "p15", 4, "c2"  )           : ( "HTTBR", "Hyp Translation Table Base Register" ),
        ( "p15", 0, "c7"  )           : ( "PAR", "Physical Address Register" ),

        # Counters
        ( "p15", 0, "c9"  )           : ( "PMCCNTR", "Performance Monitors Cycle Count Register" ),
        ( "p15", 0, "c14" )           : ( "CNTPCT", "Counter-timer Physical Count register" ),
        ( "p15", 1, "c14" )           : ( "CNTVCT", "Counter-timer Virtual Count register" ),
        ( "p15", 2, "c14" )           : ( "CNTP_CVAL", "Counter-timer Physical Timer CompareValue register",
                                          "CNTHP_CVAL", "Counter-timer Hyp Physical CompareValue register" ),
        ( "p15", 3, "c14" )           : ( "CNTV_CVAL", "Counter-timer Virtual Timer CompareValue register",
                                          "CNTHV_CVAL", "Counter-timer Virtual Timer CompareValue register (EL2)" ),
        ( "p15", 4, "c14" )           : ( "CNTVOFF", "Counter-timer Virtual Offset register" ),
        ( "p15", 6, "c14" )           : ( "CNTHP_CVAL", "Counter-timer Hyp Physical CompareValue register" ),

        # CPU control/status registers.
        ( "p15", 0, "c15" )           : ( "CPUACTLR", "CPU Auxiliary Control Register" ),
        ( "p15", 1, "c15" )           : ( "CPUECTLR", "CPU Extended Control Register" ),
        ( "p15", 2, "c15" )           : ( "CPUMERRSR", "CPU Memory Error Syndrome Register" ),
        ( "p15", 3, "c15" )           : ( "L2MERRSR", "L2 Memory Error Syndrome Register" ),

        # Interrupts
        ( "p15", 0, "c12" )           : ( "ICC_SGI1R", "Interrupt Controller Software Generated Interrupt Group 1 Register" ),
        ( "p15", 1, "c12" )           : ( "ICC_ASGI1R", "Interrupt Controller Alias Software Generated Interrupt Group 1 Register" ),
        ( "p15", 2, "c12" )           : ( "ICC_SGI0R", "Interrupt Controller Software Generated Interrupt Group 0 Register" ),

        # Preload Engine operations
        ( "p15", 0, "c11" )           : ( "N/A", "Preload Engine Program New Channel operation" ),

        # Debug registers
        ( "p14", 0, "c1"  )           : ( "DBGDRAR", "Debug ROM Address Register" ),
        ( "p14", 0, "c2"  )           : ( "DBGDSAR", "Debug Self Address Register" ),
}

# Extracted from the 00bet4 XML specifications for ARMv8.3 and older manuals .
COPROC_REGISTERS = {
        ( "p15", "c0", 0, "c0", 0 )   : ( "MIDR", "Main ID Register" ),
        ( "p15", "c0", 0, "c0", 1 )   : ( "CTR", "Cache Type Register" ),
        ( "p15", "c0", 0, "c0", 2 )   : ( "TCMTR", "TCM Type Register" ),
        ( "p15", "c0", 0, "c0", 3 )   : ( "TLBTR", "TLB Type Register" ),
        ( "p15", "c0", 0, "c0", 5 )   : ( "MPIDR", "Multiprocessor Affinity Register" ),
        ( "p15", "c0", 0, "c0", 6 )   : ( "REVIDR", "Revision ID Register" ),

        # Aliases
        ( "p15", "c0", 0, "c0", 4 )   : ( "MIDR", "Main ID Register" ),
        ( "p15", "c0", 0, "c0", 7 )   : ( "MIDR", "Main ID Register" ),

        # CPUID registers
        ( "p15", "c0", 0, "c1", 0 )   : ( "ID_PFR0", "Processor Feature Register 0" ),
        ( "p15", "c0", 0, "c1", 1 )   : ( "ID_PFR1", "Processor Feature Register 1" ),
        ( "p15", "c0", 0, "c1", 2 )   : ( "ID_DFR0", "Debug Feature Register 0" ),
        ( "p15", "c0", 0, "c1", 3 )   : ( "ID_AFR0", "Auxiliary Feature Register 0" ),
        ( "p15", "c0", 0, "c1", 4 )   : ( "ID_MMFR0", "Memory Model Feature Register 0" ),
        ( "p15", "c0", 0, "c1", 5 )   : ( "ID_MMFR1", "Memory Model Feature Register 1" ),
        ( "p15", "c0", 0, "c1", 6 )   : ( "ID_MMFR2", "Memory Model Feature Register 2" ),
        ( "p15", "c0", 0, "c1", 7 )   : ( "ID_MMFR3", "Memory Model Feature Register 3" ),
        ( "p15", "c0", 0, "c2", 6 )   : ( "ID_MMFR4", "Memory Model Feature Register 4" ),
        ( "p15", "c0", 0, "c2", 0 )   : ( "ID_ISAR0", "Instruction Set Attribute Register 0" ),
        ( "p15", "c0", 0, "c2", 1 )   : ( "ID_ISAR1", "Instruction Set Attribute Register 1" ),
        ( "p15", "c0", 0, "c2", 2 )   : ( "ID_ISAR2", "Instruction Set Attribute Register 2" ),
        ( "p15", "c0", 0, "c2", 3 )   : ( "ID_ISAR3", "Instruction Set Attribute Register 3" ),
        ( "p15", "c0", 0, "c2", 4 )   : ( "ID_ISAR4", "Instruction Set Attribute Register 4" ),
        ( "p15", "c0", 0, "c2", 5 )   : ( "ID_ISAR5", "Instruction Set Attribute Register 5" ),
        ( "p15", "c0", 0, "c2", 7 )   : ( "ID_ISAR6", "Instruction Set Attribute Register 6" ),

        ( "p15", "c0", 1, "c0", 0 )   : ( "CCSIDR", "Current Cache Size ID Register" ),
        ( "p15", "c0", 1, "c0", 2 )   : ( "CCSIDR2", "Current Cache Size ID Register 2" ),
        ( "p15", "c0", 1, "c0", 1 )   : ( "CLIDR", "Cache Level ID Register" ),
        ( "p15", "c0", 1, "c0", 7 )   : ( "AIDR", "Auxiliary ID Register" ),
        ( "p15", "c0", 2, "c0", 0 )   : ( "CSSELR", "Cache Size Selection Register" ),
        ( "p15", "c0", 4, "c0", 0 )   : ( "VPIDR", "Virtualization Processor ID Register" ),
        ( "p15", "c0", 4, "c0", 5 )   : ( "VMPIDR", "Virtualization Multiprocessor ID Register" ),

        # System control registers
        ( "p15", "c1", 0, "c0", 0 )   : ( "SCTLR", "System Control Register" ),
        ( "p15", "c1", 0, "c0", 1 )   : ( "ACTLR", "Auxiliary Control Register" ),
        ( "p15", "c1", 0, "c0", 3 )   : ( "ACTLR2", "Auxiliary Control Register 2" ),
        ( "p15", "c1", 0, "c0", 2 )   : ( "CPACR", "Architectural Feature Access Control Register" ),
        ( "p15", "c1", 0, "c1", 0 )   : ( "SCR", "Secure Configuration Register" ),
        ( "p15", "c1", 0, "c1", 1 )   : ( "SDER", "Secure Debug Enable Register" ),
        ( "p15", "c1", 0, "c3", 1 )   : ( "SDCR", "Secure Debug Control Register" ),
        ( "p15", "c1", 0, "c1", 2 )   : ( "NSACR", "Non-Secure Access Control Register" ),
        ( "p15", "c1", 4, "c0", 0 )   : ( "HSCTLR", "Hyp System Control Register" ),
        ( "p15", "c1", 4, "c0", 1 )   : ( "HACTLR", "Hyp Auxiliary Control Register" ),
        ( "p15", "c1", 4, "c0", 3 )   : ( "HACTLR2", "Hyp Auxiliary Control Register 2" ),
        ( "p15", "c1", 4, "c1", 0 )   : ( "HCR", "Hyp Configuration Register" ),
        ( "p15", "c1", 4, "c1", 4 )   : ( "HCR2", "Hyp Configuration Register 2" ),
        ( "p15", "c1", 4, "c1", 1 )   : ( "HDCR", "Hyp Debug Control Register" ),
        ( "p15", "c1", 4, "c1", 2 )   : ( "HCPTR", "Hyp Architectural Feature Trap Register" ),
        ( "p15", "c1", 4, "c1", 3 )   : ( "HSTR", "Hyp System Trap Register" ),
        ( "p15", "c1", 4, "c1", 7 )   : ( "HACR", "Hyp Auxiliary Configuration Register" ),

        # Translation Table Base Registers
        ( "p15", "c2", 0, "c0", 0 )   : ( "TTBR0", "Translation Table Base Register 0" ),
        ( "p15", "c2", 0, "c0", 1 )   : ( "TTBR1", "Translation Table Base Register 1" ),
        ( "p15", "c2", 4, "c0", 2 )   : ( "HTCR", "Hyp Translation Control Register" ),
        ( "p15", "c2", 4, "c1", 2 )   : ( "VTCR", "Virtualization Translation Control Register" ),
        ( "p15", "c2", 0, "c0", 2 )   : ( "TTBCR", "Translation Table Base Control Register" ),
        ( "p15", "c2", 0, "c0", 3 )   : ( "TTBCR2", "Translation Table Base Control Register 2" ),

        # Domain Access Control registers
        ( "p15", "c3", 0, "c0", 0 )   : ( "DACR", "Domain Access Control Register" ),

        # Fault Status registers
        ( "p15", "c5", 0, "c0", 0 )   : ( "DFSR", "Data Fault Status Register" ),
        ( "p15", "c5", 0, "c0", 1 )   : ( "IFSR", "Instruction Fault Status Register" ),
        ( "p15", "c5", 0, "c1", 0 )   : ( "ADFSR", "Auxiliary Data Fault Status Register" ),
        ( "p15", "c5", 0, "c1", 1 )   : ( "AIFSR", "Auxiliary Instruction Fault Status Register" ),
        ( "p15", "c5", 4, "c1", 0 )   : ( "HADFSR", "Hyp Auxiliary Data Fault Status Register" ),
        ( "p15", "c5", 4, "c1", 1 )   : ( "HAIFSR", "Hyp Auxiliary Instruction Fault Status Register" ),
        ( "p15", "c5", 4, "c2", 0 )   : ( "HSR", "Hyp Syndrome Register" ),

        # Fault Address registers
        ( "p15", "c6", 0, "c0", 0 )   : ( "DFAR", "Data Fault Address Register" ),
        ( "p15", "c6", 0, "c0", 1 )   : ( "N/A", "Watchpoint Fault Address" ), # ARM11
        ( "p15", "c6", 0, "c0", 2 )   : ( "IFAR", "Instruction Fault Address Register" ),
        ( "p15", "c6", 4, "c0", 0 )   : ( "HDFAR", "Hyp Data Fault Address Register" ),
        ( "p15", "c6", 4, "c0", 2 )   : ( "HIFAR", "Hyp Instruction Fault Address Register" ),
        ( "p15", "c6", 4, "c0", 4 )   : ( "HPFAR", "Hyp IPA Fault Address Register" ),

        # Cache maintenance registers
        ( "p15", "c7", 0, "c0", 4 )   : ( "NOP", "No Operation / Wait For Interrupt" ),
        ( "p15", "c7", 0, "c1", 0 )   : ( "ICIALLUIS", "Instruction Cache Invalidate All to PoU, Inner Shareable" ),
        ( "p15", "c7", 0, "c1", 6 )   : ( "BPIALLIS", "Branch Predictor Invalidate All, Inner Shareable" ),
        ( "p15", "c7", 0, "c4", 0 )   : ( "PAR", "Physical Address Register" ),
        ( "p15", "c7", 0, "c5", 0 )   : ( "ICIALLU", "Instruction Cache Invalidate All to PoU" ),
        ( "p15", "c7", 0, "c5", 1 )   : ( "ICIMVAU", "Instruction Cache line Invalidate by VA to PoU" ),
        ( "p15", "c7", 0, "c5", 2 )   : ( "N/A", "Invalidate all instruction caches by set/way" ), # ARM11
        ( "p15", "c7", 0, "c5", 4 )   : ( "CP15ISB", "Instruction Synchronization Barrier System instruction" ),
        ( "p15", "c7", 0, "c5", 6 )   : ( "BPIALL", "Branch Predictor Invalidate All" ),
        ( "p15", "c7", 0, "c5", 7 )   : ( "BPIMVA", "Branch Predictor Invalidate by VA" ),
        ( "p15", "c7", 0, "c6", 0 )   : ( "N/A", "Invalidate entire data cache" ),
        ( "p15", "c7", 0, "c6", 1 )   : ( "DCIMVAC", "Data Cache line Invalidate by VA to PoC" ),
        ( "p15", "c7", 0, "c6", 2 )   : ( "DCISW", "Data Cache line Invalidate by Set/Way" ),
        ( "p15", "c7", 0, "c7", 0 )   : ( "N/A", "Invalidate instruction cache and data cache" ), # ARM11
        ( "p15", "c7", 0, "c8", 0 )   : ( "ATS1CPR", "Address Translate Stage 1 Current state PL1 Read" ),
        ( "p15", "c7", 0, "c8", 1 )   : ( "ATS1CPW", "Address Translate Stage 1 Current state PL1 Write" ),
        ( "p15", "c7", 0, "c8", 2 )   : ( "ATS1CUR", "Address Translate Stage 1 Current state Unprivileged Read" ),
        ( "p15", "c7", 0, "c8", 3 )   : ( "ATS1CUW", "Address Translate Stage 1 Current state Unprivileged Write" ),
        ( "p15", "c7", 0, "c8", 4 )   : ( "ATS12NSOPR", "Address Translate Stages 1 and 2 Non-secure Only PL1 Read" ),
        ( "p15", "c7", 0, "c8", 5 )   : ( "ATS12NSOPW", "Address Translate Stages 1 and 2 Non-secure Only PL1 Write" ),
        ( "p15", "c7", 0, "c8", 6 )   : ( "ATS12NSOUR", "Address Translate Stages 1 and 2 Non-secure Only Unprivileged Read" ),
        ( "p15", "c7", 0, "c8", 7 )   : ( "ATS12NSOUW", "Address Translate Stages 1 and 2 Non-secure Only Unprivileged Write" ),
        ( "p15", "c7", 0, "c9", 0 )   : ( "ATS1CPRP", "Address Translate Stage 1 Current state PL1 Read PAN" ),
        ( "p15", "c7", 0, "c9", 1 )   : ( "ATS1CPWP", "Address Translate Stage 1 Current state PL1 Write PAN" ),
        ( "p15", "c7", 0, "c10", 0 )  : ( "N/A", "Clean entire data cache" ), # ARM11
        ( "p15", "c7", 0, "c10", 1 )  : ( "DCCMVAC", "Data Cache line Clean by VA to PoC" ),
        ( "p15", "c7", 0, "c10", 2 )  : ( "DCCSW", "Data Cache line Clean by Set/Way" ),
        ( "p15", "c7", 0, "c10", 3 )  : ( "N/A", "Test and clean data cache" ), # ARM9
        ( "p15", "c7", 0, "c10", 4 )  : ( "CP15DSB", "Data Synchronization Barrier System instruction" ),
        ( "p15", "c7", 0, "c10", 5 )  : ( "CP15DMB", "Data Memory Barrier System instruction" ),
        ( "p15", "c7", 0, "c10", 6 )  : ( "N/A", "Read Cache Dirty Status Register" ), # ARM11
        ( "p15", "c7", 0, "c11", 1 )  : ( "DCCMVAU", "Data Cache line Clean by VA to PoU" ),
        ( "p15", "c7", 0, "c12", 4 )  : ( "N/A", "Read Block Transfer Status Register" ), # ARM11
        ( "p15", "c7", 0, "c12", 5 )  : ( "N/A", "Stop Prefetch Range" ), # ARM11
        ( "p15", "c7", 0, "c13", 1 )  : ( "NOP", "No Operation / Prefetch Instruction Cache Line" ),
        ( "p15", "c7", 0, "c14", 0 )  : ( "N/A", "Clean and invalidate entire data cache" ), # ARM11
        ( "p15", "c7", 0, "c14", 1 )  : ( "DCCIMVAC", "Data Cache line Clean and Invalidate by VA to PoC" ),
        ( "p15", "c7", 0, "c14", 2 )  : ( "DCCISW", "Data Cache line Clean and Invalidate by Set/Way" ),
        ( "p15", "c7", 0, "c14", 3 )  : ( "N/A", "Test, clean, and invalidate data cache" ), # ARM9
        ( "p15", "c7", 4, "c8", 0 )   : ( "ATS1HR", "Address Translate Stage 1 Hyp mode Read" ),
        ( "p15", "c7", 4, "c8", 1 )   : ( "ATS1HW", "Stage 1 Hyp mode write" ),

        # TLB maintenance operations
        ( "p15", "c8", 0, "c3", 0 )   : ( "TLBIALLIS", "TLB Invalidate All, Inner Shareable" ),
        ( "p15", "c8", 0, "c3", 1 )   : ( "TLBIMVAIS", "TLB Invalidate by VA, Inner Shareable" ),
        ( "p15", "c8", 0, "c3", 2 )   : ( "TLBIASIDIS", "TLB Invalidate by ASID match, Inner Shareable" ),
        ( "p15", "c8", 0, "c3", 3 )   : ( "TLBIMVAAIS", "TLB Invalidate by VA, All ASID, Inner Shareable" ),
        ( "p15", "c8", 0, "c3", 5 )   : ( "TLBIMVALIS", "TLB Invalidate by VA, Last level, Inner Shareable" ),
        ( "p15", "c8", 0, "c3", 7 )   : ( "TLBIMVAALIS", "TLB Invalidate by VA, All ASID, Last level, Inner Shareable" ),
        ( "p15", "c8", 0, "c5", 0 )   : ( "ITLBIALL", "Instruction TLB Invalidate All" ),
        ( "p15", "c8", 0, "c5", 1 )   : ( "ITLBIMVA", "Instruction TLB Invalidate by VA" ),
        ( "p15", "c8", 0, "c5", 2 )   : ( "ITLBIASID", "Instruction TLB Invalidate by ASID match" ),
        ( "p15", "c8", 0, "c6", 0 )   : ( "DTLBIALL", "Data TLB Invalidate All" ),
        ( "p15", "c8", 0, "c6", 1 )   : ( "DTLBIMVA", "Data TLB Invalidate by VA" ),
        ( "p15", "c8", 0, "c6", 2 )   : ( "DTLBIASID", "Data TLB Invalidate by ASID match" ),
        ( "p15", "c8", 0, "c7", 0 )   : ( "TLBIALL", "TLB Invalidate All" ),
        ( "p15", "c8", 0, "c7", 1 )   : ( "TLBIMVA", "TLB Invalidate by VA" ),
        ( "p15", "c8", 0, "c7", 2 )   : ( "TLBIASID", "TLB Invalidate by ASID match" ),
        ( "p15", "c8", 0, "c7", 3 )   : ( "TLBIMVAA", "TLB Invalidate by VA, All ASID" ),
        ( "p15", "c8", 0, "c7", 5 )   : ( "TLBIMVAL", "TLB Invalidate by VA, Last level" ),
        ( "p15", "c8", 0, "c7", 7 )   : ( "TLBIMVAAL", "TLB Invalidate by VA, All ASID, Last level" ),
        ( "p15", "c8", 4, "c0", 1 )   : ( "TLBIIPAS2IS", "TLB Invalidate by Intermediate Physical Address, Stage 2, Inner Shareable" ),
        ( "p15", "c8", 4, "c0", 5 )   : ( "TLBIIPAS2LIS", "TLB Invalidate by Intermediate Physical Address, Stage 2, Last level, Inner Shareable" ),
        ( "p15", "c8", 4, "c3", 0 )   : ( "TLBIALLHIS", "TLB Invalidate All, Hyp mode, Inner Shareable" ),
        ( "p15", "c8", 4, "c3", 1 )   : ( "TLBIMVAHIS", "TLB Invalidate by VA, Hyp mode, Inner Shareable" ),
        ( "p15", "c8", 4, "c3", 4 )   : ( "TLBIALLNSNHIS", "TLB Invalidate All, Non-Secure Non-Hyp, Inner Shareable" ),
        ( "p15", "c8", 4, "c3", 5 )   : ( "TLBIMVALHIS", "TLB Invalidate by VA, Last level, Hyp mode, Inner Shareable" ),
        ( "p15", "c8", 4, "c4", 1 )   : ( "TLBIIPAS2", "TLB Invalidate by Intermediate Physical Address, Stage 2" ),
        ( "p15", "c8", 4, "c4", 5 )   : ( "TLBIIPAS2L", "TLB Invalidate by Intermediate Physical Address, Stage 2, Last level" ),
        ( "p15", "c8", 4, "c7", 0 )   : ( "TLBIALLH", "TLB Invalidate All, Hyp mode" ),
        ( "p15", "c8", 4, "c7", 1 )   : ( "TLBIMVAH", "TLB Invalidate by VA, Hyp mode" ),
        ( "p15", "c8", 4, "c7", 4 )   : ( "TLBIALLNSNH", "TLB Invalidate All, Non-Secure Non-Hyp" ),
        ( "p15", "c8", 4, "c7", 5 )   : ( "TLBIMVALH", "TLB Invalidate by VA, Last level, Hyp mode" ),

        ( "p15", "c9", 0, "c0", 0 )   : ( "N/A", "Data Cache Lockdown" ), # ARM11
        ( "p15", "c9", 0, "c0", 1 )   : ( "N/A", "Instruction Cache Lockdown" ), # ARM11
        ( "p15", "c9", 0, "c1", 0 )   : ( "N/A", "Data TCM Region" ), # ARM11
        ( "p15", "c9", 0, "c1", 1 )   : ( "N/A", "Instruction TCM Region" ), # ARM11
        ( "p15", "c9", 1, "c0", 2 )   : ( "L2CTLR", "L2 Control Register" ),
        ( "p15", "c9", 1, "c0", 3 )   : ( "L2ECTLR", "L2 Extended Control Register" ),

        # Performance monitor registers
        ( "p15", "c9", 0, "c12", 0 )  : ( "PMCR", "Performance Monitors Control Register" ),
        ( "p15", "c9", 0, "c12", 1)   : ( "PMCNTENSET", "Performance Monitor Count Enable Set Register" ),
        ( "p15", "c9", 0, "c12", 2)   : ( "PMCNTENCLR", "Performance Monitor Control Enable Clear Register" ),
        ( "p15", "c9", 0, "c12", 3 )  : ( "PMOVSR", "Performance Monitors Overflow Flag Status Register" ),
        ( "p15", "c9", 0, "c12", 4 )  : ( "PMSWINC", "Performance Monitors Software Increment register" ),
        ( "p15", "c9", 0, "c12", 5 )  : ( "PMSELR", "Performance Monitors Event Counter Selection Register" ),
        ( "p15", "c9", 0, "c12", 6 )  : ( "PMCEID0", "Performance Monitors Common Event Identification register 0" ),
        ( "p15", "c9", 0, "c12", 7 )  : ( "PMCEID1", "Performance Monitors Common Event Identification register 1" ),
        ( "p15", "c9", 0, "c13", 0 )  : ( "PMCCNTR", "Performance Monitors Cycle Count Register" ),
        ( "p15", "c9", 0, "c13", 1 )  : ( "PMXEVTYPER", "Performance Monitors Selected Event Type Register" ),
        ( "p15", "c9", 0, "c13", 2 )  : ( "PMXEVCNTR", "Performance Monitors Selected Event Count Register" ),
        ( "p15", "c9", 0, "c14", 0 )  : ( "PMUSERENR", "Performance Monitors User Enable Register" ),
        ( "p15", "c9", 0, "c14", 1 )  : ( "PMINTENSET", "Performance Monitors Interrupt Enable Set register" ),
        ( "p15", "c9", 0, "c14", 2 )  : ( "PMINTENCLR", "Performance Monitors Interrupt Enable Clear register" ),
        ( "p15", "c9", 0, "c14", 3 )  : ( "PMOVSSET", "Performance Monitors Overflow Flag Status Set register" ),
        ( "p15", "c9", 0, "c14", 4 )  : ( "PMCEID2", "Performance Monitors Common Event Identification register 2" ),
        ( "p15", "c9", 0, "c14", 5 )  : ( "PMCEID3", "Performance Monitors Common Event Identification register 3" ),
        ( "p15", "c14", 0, "c8", 0 )  : ( "PMEVCNTR0", "Performance Monitors Event Count Register 0" ),
        ( "p15", "c14", 0, "c8", 1 )  : ( "PMEVCNTR1", "Performance Monitors Event Count Register 1" ),
        ( "p15", "c14", 0, "c8", 2 )  : ( "PMEVCNTR2", "Performance Monitors Event Count Register 2" ),
        ( "p15", "c14", 0, "c8", 3 )  : ( "PMEVCNTR3", "Performance Monitors Event Count Register 3" ),
        ( "p15", "c14", 0, "c8", 4 )  : ( "PMEVCNTR4", "Performance Monitors Event Count Register 4" ),
        ( "p15", "c14", 0, "c8", 5 )  : ( "PMEVCNTR5", "Performance Monitors Event Count Register 5" ),
        ( "p15", "c14", 0, "c8", 6 )  : ( "PMEVCNTR6", "Performance Monitors Event Count Register 6" ),
        ( "p15", "c14", 0, "c8", 7 )  : ( "PMEVCNTR7", "Performance Monitors Event Count Register 7" ),
        ( "p15", "c14", 0, "c9", 0 )  : ( "PMEVCNTR8", "Performance Monitors Event Count Register 8" ),
        ( "p15", "c14", 0, "c9", 1 )  : ( "PMEVCNTR9", "Performance Monitors Event Count Register 9" ),
        ( "p15", "c14", 0, "c9", 2 )  : ( "PMEVCNTR10", "Performance Monitors Event Count Register 10" ),
        ( "p15", "c14", 0, "c9", 3 )  : ( "PMEVCNTR11", "Performance Monitors Event Count Register 11" ),
        ( "p15", "c14", 0, "c9", 4 )  : ( "PMEVCNTR12", "Performance Monitors Event Count Register 12" ),
        ( "p15", "c14", 0, "c9", 5 )  : ( "PMEVCNTR13", "Performance Monitors Event Count Register 13" ),
        ( "p15", "c14", 0, "c9", 6 )  : ( "PMEVCNTR14", "Performance Monitors Event Count Register 14" ),
        ( "p15", "c14", 0, "c9", 7 )  : ( "PMEVCNTR15", "Performance Monitors Event Count Register 15" ),
        ( "p15", "c14", 0, "c10", 0 ) : ( "PMEVCNTR16", "Performance Monitors Event Count Register 16" ),
        ( "p15", "c14", 0, "c10", 1 ) : ( "PMEVCNTR17", "Performance Monitors Event Count Register 17" ),
        ( "p15", "c14", 0, "c10", 2 ) : ( "PMEVCNTR18", "Performance Monitors Event Count Register 18" ),
        ( "p15", "c14", 0, "c10", 3 ) : ( "PMEVCNTR19", "Performance Monitors Event Count Register 19" ),
        ( "p15", "c14", 0, "c10", 4 ) : ( "PMEVCNTR20", "Performance Monitors Event Count Register 20" ),
        ( "p15", "c14", 0, "c10", 5 ) : ( "PMEVCNTR21", "Performance Monitors Event Count Register 21" ),
        ( "p15", "c14", 0, "c10", 6 ) : ( "PMEVCNTR22", "Performance Monitors Event Count Register 22" ),
        ( "p15", "c14", 0, "c10", 7 ) : ( "PMEVCNTR23", "Performance Monitors Event Count Register 23" ),
        ( "p15", "c14", 0, "c11", 0 ) : ( "PMEVCNTR24", "Performance Monitors Event Count Register 24" ),
        ( "p15", "c14", 0, "c11", 1 ) : ( "PMEVCNTR25", "Performance Monitors Event Count Register 25" ),
        ( "p15", "c14", 0, "c11", 2 ) : ( "PMEVCNTR26", "Performance Monitors Event Count Register 26" ),
        ( "p15", "c14", 0, "c11", 3 ) : ( "PMEVCNTR27", "Performance Monitors Event Count Register 27" ),
        ( "p15", "c14", 0, "c11", 4 ) : ( "PMEVCNTR28", "Performance Monitors Event Count Register 28" ),
        ( "p15", "c14", 0, "c11", 5 ) : ( "PMEVCNTR29", "Performance Monitors Event Count Register 29" ),
        ( "p15", "c14", 0, "c11", 6 ) : ( "PMEVCNTR30", "Performance Monitors Event Count Register 30" ),
        ( "p15", "c14", 0, "c12", 0 ) : ( "PMEVTYPER0", "Performance Monitors Event Type Register 0" ),
        ( "p15", "c14", 0, "c12", 1 ) : ( "PMEVTYPER1", "Performance Monitors Event Type Register 1" ),
        ( "p15", "c14", 0, "c12", 2 ) : ( "PMEVTYPER2", "Performance Monitors Event Type Register 2" ),
        ( "p15", "c14", 0, "c12", 3 ) : ( "PMEVTYPER3", "Performance Monitors Event Type Register 3" ),
        ( "p15", "c14", 0, "c12", 4 ) : ( "PMEVTYPER4", "Performance Monitors Event Type Register 4" ),
        ( "p15", "c14", 0, "c12", 5 ) : ( "PMEVTYPER5", "Performance Monitors Event Type Register 5" ),
        ( "p15", "c14", 0, "c12", 6 ) : ( "PMEVTYPER6", "Performance Monitors Event Type Register 6" ),
        ( "p15", "c14", 0, "c12", 7 ) : ( "PMEVTYPER7", "Performance Monitors Event Type Register 7" ),
        ( "p15", "c14", 0, "c13", 0 ) : ( "PMEVTYPER8", "Performance Monitors Event Type Register 8" ),
        ( "p15", "c14", 0, "c13", 1 ) : ( "PMEVTYPER9", "Performance Monitors Event Type Register 9" ),
        ( "p15", "c14", 0, "c13", 2 ) : ( "PMEVTYPER10", "Performance Monitors Event Type Register 10" ),
        ( "p15", "c14", 0, "c13", 3 ) : ( "PMEVTYPER11", "Performance Monitors Event Type Register 11" ),
        ( "p15", "c14", 0, "c13", 4 ) : ( "PMEVTYPER12", "Performance Monitors Event Type Register 12" ),
        ( "p15", "c14", 0, "c13", 5 ) : ( "PMEVTYPER13", "Performance Monitors Event Type Register 13" ),
        ( "p15", "c14", 0, "c13", 6 ) : ( "PMEVTYPER14", "Performance Monitors Event Type Register 14" ),
        ( "p15", "c14", 0, "c13", 7 ) : ( "PMEVTYPER15", "Performance Monitors Event Type Register 15" ),
        ( "p15", "c14", 0, "c14", 0 ) : ( "PMEVTYPER16", "Performance Monitors Event Type Register 16" ),
        ( "p15", "c14", 0, "c14", 1 ) : ( "PMEVTYPER17", "Performance Monitors Event Type Register 17" ),
        ( "p15", "c14", 0, "c14", 2 ) : ( "PMEVTYPER18", "Performance Monitors Event Type Register 18" ),
        ( "p15", "c14", 0, "c14", 3 ) : ( "PMEVTYPER19", "Performance Monitors Event Type Register 19" ),
        ( "p15", "c14", 0, "c14", 4 ) : ( "PMEVTYPER20", "Performance Monitors Event Type Register 20" ),
        ( "p15", "c14", 0, "c14", 5 ) : ( "PMEVTYPER21", "Performance Monitors Event Type Register 21" ),
        ( "p15", "c14", 0, "c14", 6 ) : ( "PMEVTYPER22", "Performance Monitors Event Type Register 22" ),
        ( "p15", "c14", 0, "c14", 7 ) : ( "PMEVTYPER23", "Performance Monitors Event Type Register 23" ),
        ( "p15", "c14", 0, "c15", 0 ) : ( "PMEVTYPER24", "Performance Monitors Event Type Register 24" ),
        ( "p15", "c14", 0, "c15", 1 ) : ( "PMEVTYPER25", "Performance Monitors Event Type Register 25" ),
        ( "p15", "c14", 0, "c15", 2 ) : ( "PMEVTYPER26", "Performance Monitors Event Type Register 26" ),
        ( "p15", "c14", 0, "c15", 3 ) : ( "PMEVTYPER27", "Performance Monitors Event Type Register 27" ),
        ( "p15", "c14", 0, "c15", 4 ) : ( "PMEVTYPER28", "Performance Monitors Event Type Register 28" ),
        ( "p15", "c14", 0, "c15", 5 ) : ( "PMEVTYPER29", "Performance Monitors Event Type Register 29" ),
        ( "p15", "c14", 0, "c15", 6 ) : ( "PMEVTYPER30", "Performance Monitors Event Type Register 30" ),
        ( "p15", "c14", 0, "c15", 7 ) : ( "PMCCFILTR", "Performance Monitors Cycle Count Filter Register" ),

        # Memory attribute registers
        ( "p15", "c10", 0, "c0", 0 )  : ( "N/A", "TLB Lockdown" ), # ARM11
        ( "p15", "c10", 0, "c2", 0 )  : ( "MAIR0", "Memory Attribute Indirection Register 0", "PRRR", "Primary Region Remap Register" ),
        ( "p15", "c10", 0, "c2", 1 )  : ( "MAIR1", "Memory Attribute Indirection Register 1", "NMRR", "Normal Memory Remap Register" ),
        ( "p15", "c10", 0, "c3", 0 )  : ( "AMAIR0", "Auxiliary Memory Attribute Indirection Register 0" ),
        ( "p15", "c10", 0, "c3", 1 )  : ( "AMAIR1", "Auxiliary Memory Attribute Indirection Register 1" ),
        ( "p15", "c10", 4, "c2", 0 )  : ( "HMAIR0", "Hyp Memory Attribute Indirection Register 0" ),
        ( "p15", "c10", 4, "c2", 1 )  : ( "HMAIR1", "Hyp Memory Attribute Indirection Register 1" ),
        ( "p15", "c10", 4, "c3", 0 )  : ( "HAMAIR0", "Hyp Auxiliary Memory Attribute Indirection Register 0" ),
        ( "p15", "c10", 4, "c3", 1 )  : ( "HAMAIR1", "Hyp Auxiliary Memory Attribute Indirection Register 1" ),

        # DMA registers (ARM11)
        ( "p15", "c11", 0, "c0", 0 )  : ( "N/A", "DMA Identification and Status (Present)" ),
        ( "p15", "c11", 0, "c0", 1 )  : ( "N/A", "DMA Identification and Status (Queued)" ),
        ( "p15", "c11", 0, "c0", 2 )  : ( "N/A", "DMA Identification and Status (Running)" ),
        ( "p15", "c11", 0, "c0", 3 )  : ( "N/A", "DMA Identification and Status (Interrupting)" ),
        ( "p15", "c11", 0, "c1", 0 )  : ( "N/A", "DMA User Accessibility" ),
        ( "p15", "c11", 0, "c2", 0 )  : ( "N/A", "DMA Channel Number" ),
        ( "p15", "c11", 0, "c3", 0 )  : ( "N/A", "DMA Enable (Stop)" ),
        ( "p15", "c11", 0, "c3", 1 )  : ( "N/A", "DMA Enable (Start)" ),
        ( "p15", "c11", 0, "c3", 2 )  : ( "N/A", "DMA Enable (Clear)" ),
        ( "p15", "c11", 0, "c4", 0 )  : ( "N/A", "DMA Control" ),
        ( "p15", "c11", 0, "c5", 0 )  : ( "N/A", "DMA Internal Start Address" ),
        ( "p15", "c11", 0, "c6", 0 )  : ( "N/A", "DMA External Start Address" ),
        ( "p15", "c11", 0, "c7", 0 )  : ( "N/A", "DMA Internal End Address" ),
        ( "p15", "c11", 0, "c8", 0 )  : ( "N/A", "DMA Channel Status" ),
        ( "p15", "c11", 0, "c15", 0)  : ( "N/A", "DMA Context ID" ),

        # Reset management registers.
        ( "p15", "c12", 0, "c0", 0 )  : ( "VBAR", "Vector Base Address Register" ),
        ( "p15", "c12", 0, "c0", 1 )  : ( "RVBAR", "Reset Vector Base Address Register" ,
                                          "MVBAR", "Monitor Vector Base Address Register" ),
        ( "p15", "c12", 0, "c0", 2 )  : ( "RMR", "Reset Management Register" ),
        ( "p15", "c12", 4, "c0", 2 )  : ( "HRMR", "Hyp Reset Management Register" ),

        ( "p15", "c12", 0, "c1", 0 )  : ( "ISR", "Interrupt Status Register" ),
        ( "p15", "c12", 4, "c0", 0 )  : ( "HVBAR", "Hyp Vector Base Address Register" ),

        ( "p15", "c13", 0, "c0", 0 )  : ( "FCSEIDR", "FCSE Process ID register" ),
        ( "p15", "c13", 0, "c0", 1 )  : ( "CONTEXTIDR", "Context ID Register" ),
        ( "p15", "c13", 0, "c0", 2 )  : ( "TPIDRURW", "PL0 Read/Write Software Thread ID Register" ),
        ( "p15", "c13", 0, "c0", 3 )  : ( "TPIDRURO", "PL0 Read-Only Software Thread ID Register" ),
        ( "p15", "c13", 0, "c0", 4 )  : ( "TPIDRPRW", "PL1 Software Thread ID Register" ),
        ( "p15", "c13", 4, "c0", 2 )  : ( "HTPIDR", "Hyp Software Thread ID Register" ),

        # Generic timer registers.
        ( "p15", "c14", 0, "c0", 0 )  : ( "CNTFRQ", "Counter-timer Frequency register" ),
        ( "p15", "c14", 0, "c1", 0 )  : ( "CNTKCTL", "Counter-timer Kernel Control register" ),
        ( "p15", "c14", 0, "c2", 0 )  : ( "CNTP_TVAL", "Counter-timer Physical Timer TimerValue register",
                                          "CNTHP_TVAL", "Counter-timer Hyp Physical Timer TimerValue register" ),
        ( "p15", "c14", 0, "c2", 1 )  : ( "CNTP_CTL", "Counter-timer Physical Timer Control register",
                                          "CNTHP_CTL", "Counter-timer Hyp Physical Timer Control register" ),
        ( "p15", "c14", 0, "c3", 0 )  : ( "CNTV_TVAL", "Counter-timer Virtual Timer TimerValue register",
                                          "CNTHV_TVAL", "Counter-timer Virtual Timer TimerValue register (EL2)" ),
        ( "p15", "c14", 0, "c3", 1 )  : ( "CNTV_CTL", "Counter-timer Virtual Timer Control register",
                                          "CNTHV_CTL", "Counter-timer Virtual Timer Control register (EL2)" ),
        ( "p15", "c14", 4, "c1", 0 )  : ( "CNTHCTL", "Counter-timer Hyp Control register" ),
        ( "p15", "c14", 4, "c2", 0 )  : ( "CNTHP_TVAL", "Counter-timer Hyp Physical Timer TimerValue register" ),
        ( "p15", "c14", 4, "c2", 1 )  : ( "CNTHP_CTL", "Counter-timer Hyp Physical Timer Control register" ),

        # Generic interrupt controller registers.
        ( "p15", "c4", 0, "c6", 0 )   : ( "ICC_PMR", "Interrupt Controller Interrupt Priority Mask Register",
                                          "ICV_PMR", "Interrupt Controller Virtual Interrupt Priority Mask Register" ),
        ( "p15", "c12", 0, "c8", 0 )  : ( "ICC_IAR0", "Interrupt Controller Interrupt Acknowledge Register 0",
                                          "ICV_IAR0", "Interrupt Controller Virtual Interrupt Acknowledge Register 0" ),
        ( "p15", "c12", 0, "c8", 1 )  : ( "ICC_EOIR0", "Interrupt Controller End Of Interrupt Register 0",
                                          "ICV_EOIR0", "Interrupt Controller Virtual End Of Interrupt Register 0" ),
        ( "p15", "c12", 0, "c8", 2 )  : ( "ICC_HPPIR0", "Interrupt Controller Highest Priority Pending Interrupt Register 0",
                                          "ICV_HPPIR0", "Interrupt Controller Virtual Highest Priority Pending Interrupt Register 0" ),
        ( "p15", "c12", 0, "c8", 3 )  : ( "ICC_BPR0", "Interrupt Controller Binary Point Register 0",
                                          "ICV_BPR0", "Interrupt Controller Virtual Binary Point Register 0" ),
        ( "p15", "c12", 0, "c8", 4 )  : ( "ICC_AP0R0", "Interrupt Controller Active Priorities Group 0 Register 0",
                                          "ICV_AP0R0", "Interrupt Controller Virtual Active Priorities Group 0 Register 0" ),
        ( "p15", "c12", 0, "c8", 5 )  : ( "ICC_AP0R1", "Interrupt Controller Active Priorities Group 0 Register 1",
                                          "ICV_AP0R1", "Interrupt Controller Virtual Active Priorities Group 0 Register 1" ),
        ( "p15", "c12", 0, "c8", 6 )  : ( "ICC_AP0R2", "Interrupt Controller Active Priorities Group 0 Register 2",
                                          "ICV_AP0R2", "Interrupt Controller Virtual Active Priorities Group 0 Register 2" ),
        ( "p15", "c12", 0, "c8", 7 )  : ( "ICC_AP0R3", "Interrupt Controller Active Priorities Group 0 Register 3",
                                          "ICV_AP0R3", "Interrupt Controller Virtual Active Priorities Group 0 Register 3" ),
        ( "p15", "c12", 0, "c9", 0 )  : ( "ICC_AP1R0", "Interrupt Controller Active Priorities Group 1 Register 0",
                                          "ICV_AP1R0", "Interrupt Controller Virtual Active Priorities Group 1 Register 0" ),
        ( "p15", "c12", 0, "c9", 1 )  : ( "ICC_AP1R1", "Interrupt Controller Active Priorities Group 1 Register 1",
                                          "ICV_AP1R1", "Interrupt Controller Virtual Active Priorities Group 1 Register 1" ),
        ( "p15", "c12", 0, "c9", 2 )  : ( "ICC_AP1R2", "Interrupt Controller Active Priorities Group 1 Register 2",
                                          "ICV_AP1R2", "Interrupt Controller Virtual Active Priorities Group 1 Register 2" ),
        ( "p15", "c12", 0, "c9", 3 )  : ( "ICC_AP1R3", "Interrupt Controller Active Priorities Group 1 Register 3",
                                          "ICV_AP1R3", "Interrupt Controller Virtual Active Priorities Group 1 Register 3" ),
        ( "p15", "c12", 0, "c11", 1 ) : ( "ICC_DIR", "Interrupt Controller Deactivate Interrupt Register",
                                          "ICV_DIR", "Interrupt Controller Deactivate Virtual Interrupt Register" ),
        ( "p15", "c12", 0, "c11", 3 ) : ( "ICC_RPR", "Interrupt Controller Running Priority Register",
                                          "ICV_RPR", "Interrupt Controller Virtual Running Priority Register" ),
        ( "p15", "c12", 0, "c12", 0 ) : ( "ICC_IAR1", "Interrupt Controller Interrupt Acknowledge Register 1",
                                          "ICV_IAR1", "Interrupt Controller Virtual Interrupt Acknowledge Register 1" ),
        ( "p15", "c12", 0, "c12", 1 ) : ( "ICC_EOIR1", "Interrupt Controller End Of Interrupt Register 1",
                                          "ICV_EOIR1", "Interrupt Controller Virtual End Of Interrupt Register 1" ),
        ( "p15", "c12", 0, "c12", 2 ) : ( "ICC_HPPIR1", "Interrupt Controller Highest Priority Pending Interrupt Register 1",
                                          "ICV_HPPIR1", "Interrupt Controller Virtual Highest Priority Pending Interrupt Register 1" ),
        ( "p15", "c12", 0, "c12", 3 ) : ( "ICC_BPR1", "Interrupt Controller Binary Point Register 1",
                                          "ICV_BPR1", "Interrupt Controller Virtual Binary Point Register 1" ),
        ( "p15", "c12", 0, "c12", 4 ) : ( "ICC_CTLR", "Interrupt Controller Control Register",
                                          "ICV_CTLR", "Interrupt Controller Virtual Control Register" ),
        ( "p15", "c12", 0, "c12", 5 ) : ( "ICC_SRE", "Interrupt Controller System Register Enable register" ),
        ( "p15", "c12", 0, "c12", 6 ) : ( "ICC_IGRPEN0", "Interrupt Controller Interrupt Group 0 Enable register",
                                          "ICV_IGRPEN0", "Interrupt Controller Virtual Interrupt Group 0 Enable register" ),
        ( "p15", "c12", 0, "c12", 7 ) : ( "ICC_IGRPEN1", "Interrupt Controller Interrupt Group 1 Enable register",
                                          "ICV_IGRPEN1", "Interrupt Controller Virtual Interrupt Group 1 Enable register" ),
        ( "p15", "c12", 4, "c8", 0 )  : ( "ICH_AP0R0", "Interrupt Controller Hyp Active Priorities Group 0 Register 0" ),
        ( "p15", "c12", 4, "c8", 1 )  : ( "ICH_AP0R1", "Interrupt Controller Hyp Active Priorities Group 0 Register 1" ),
        ( "p15", "c12", 4, "c8", 2 )  : ( "ICH_AP0R2", "Interrupt Controller Hyp Active Priorities Group 0 Register 2" ),
        ( "p15", "c12", 4, "c8", 3 )  : ( "ICH_AP0R3", "Interrupt Controller Hyp Active Priorities Group 0 Register 3" ),
        ( "p15", "c12", 4, "c9", 0 )  : ( "ICH_AP1R0", "Interrupt Controller Hyp Active Priorities Group 1 Register 0" ),
        ( "p15", "c12", 4, "c9", 1 )  : ( "ICH_AP1R1", "Interrupt Controller Hyp Active Priorities Group 1 Register 1" ),
        ( "p15", "c12", 4, "c9", 2 )  : ( "ICH_AP1R2", "Interrupt Controller Hyp Active Priorities Group 1 Register 2" ),
        ( "p15", "c12", 4, "c9", 3 )  : ( "ICH_AP1R3", "Interrupt Controller Hyp Active Priorities Group 1 Register 3" ),
        ( "p15", "c12", 4, "c9", 5 )  : ( "ICC_HSRE", "Interrupt Controller Hyp System Register Enable register" ),
        ( "p15", "c12", 4, "c11", 0 ) : ( "ICH_HCR", "Interrupt Controller Hyp Control Register" ),
        ( "p15", "c12", 4, "c11", 1 ) : ( "ICH_VTR", "Interrupt Controller VGIC Type Register" ),
        ( "p15", "c12", 4, "c11", 2 ) : ( "ICH_MISR", "Interrupt Controller Maintenance Interrupt State Register" ),
        ( "p15", "c12", 4, "c11", 3 ) : ( "ICH_EISR", "Interrupt Controller End of Interrupt Status Register" ),
        ( "p15", "c12", 4, "c11", 5 ) : ( "ICH_ELRSR", "Interrupt Controller Empty List Register Status Register" ),
        ( "p15", "c12", 4, "c11", 7 ) : ( "ICH_VMCR", "Interrupt Controller Virtual Machine Control Register" ),
        ( "p15", "c12", 4, "c12", 0 ) : ( "ICH_LR0", "Interrupt Controller List Register 0" ),
        ( "p15", "c12", 4, "c12", 1 ) : ( "ICH_LR1", "Interrupt Controller List Register 1" ),
        ( "p15", "c12", 4, "c12", 2 ) : ( "ICH_LR2", "Interrupt Controller List Register 2" ),
        ( "p15", "c12", 4, "c12", 3 ) : ( "ICH_LR3", "Interrupt Controller List Register 3" ),
        ( "p15", "c12", 4, "c12", 4 ) : ( "ICH_LR4", "Interrupt Controller List Register 4" ),
        ( "p15", "c12", 4, "c12", 5 ) : ( "ICH_LR5", "Interrupt Controller List Register 5" ),
        ( "p15", "c12", 4, "c12", 6 ) : ( "ICH_LR6", "Interrupt Controller List Register 6" ),
        ( "p15", "c12", 4, "c12", 7 ) : ( "ICH_LR7", "Interrupt Controller List Register 7" ),
        ( "p15", "c12", 4, "c13", 0 ) : ( "ICH_LR8", "Interrupt Controller List Register 8" ),
        ( "p15", "c12", 4, "c13", 1 ) : ( "ICH_LR9", "Interrupt Controller List Register 9" ),
        ( "p15", "c12", 4, "c13", 2 ) : ( "ICH_LR10", "Interrupt Controller List Register 10" ),
        ( "p15", "c12", 4, "c13", 3 ) : ( "ICH_LR11", "Interrupt Controller List Register 11" ),
        ( "p15", "c12", 4, "c13", 4 ) : ( "ICH_LR12", "Interrupt Controller List Register 12" ),
        ( "p15", "c12", 4, "c13", 5 ) : ( "ICH_LR13", "Interrupt Controller List Register 13" ),
        ( "p15", "c12", 4, "c13", 6 ) : ( "ICH_LR14", "Interrupt Controller List Register 14" ),
        ( "p15", "c12", 4, "c13", 7 ) : ( "ICH_LR15", "Interrupt Controller List Register 15" ),
        ( "p15", "c12", 4, "c14", 0 ) : ( "ICH_LRC0", "Interrupt Controller List Register 0" ),
        ( "p15", "c12", 4, "c14", 1 ) : ( "ICH_LRC1", "Interrupt Controller List Register 1" ),
        ( "p15", "c12", 4, "c14", 2 ) : ( "ICH_LRC2", "Interrupt Controller List Register 2" ),
        ( "p15", "c12", 4, "c14", 3 ) : ( "ICH_LRC3", "Interrupt Controller List Register 3" ),
        ( "p15", "c12", 4, "c14", 4 ) : ( "ICH_LRC4", "Interrupt Controller List Register 4" ),
        ( "p15", "c12", 4, "c14", 5 ) : ( "ICH_LRC5", "Interrupt Controller List Register 5" ),
        ( "p15", "c12", 4, "c14", 6 ) : ( "ICH_LRC6", "Interrupt Controller List Register 6" ),
        ( "p15", "c12", 4, "c14", 7 ) : ( "ICH_LRC7", "Interrupt Controller List Register 7" ),
        ( "p15", "c12", 4, "c15", 0 ) : ( "ICH_LRC8", "Interrupt Controller List Register 8" ),
        ( "p15", "c12", 4, "c15", 1 ) : ( "ICH_LRC9", "Interrupt Controller List Register 9" ),
        ( "p15", "c12", 4, "c15", 2 ) : ( "ICH_LRC10", "Interrupt Controller List Register 10" ),
        ( "p15", "c12", 4, "c15", 3 ) : ( "ICH_LRC11", "Interrupt Controller List Register 11" ),
        ( "p15", "c12", 4, "c15", 4 ) : ( "ICH_LRC12", "Interrupt Controller List Register 12" ),
        ( "p15", "c12", 4, "c15", 5 ) : ( "ICH_LRC13", "Interrupt Controller List Register 13" ),
        ( "p15", "c12", 4, "c15", 6 ) : ( "ICH_LRC14", "Interrupt Controller List Register 14" ),
        ( "p15", "c12", 4, "c15", 7 ) : ( "ICH_LRC15", "Interrupt Controller List Register 15" ),
        ( "p15", "c12", 6, "c12", 4 ) : ( "ICC_MCTLR", "Interrupt Controller Monitor Control Register" ),
        ( "p15", "c12", 6, "c12", 5 ) : ( "ICC_MSRE", "Interrupt Controller Monitor System Register Enable register" ),
        ( "p15", "c12", 6, "c12", 7 ) : ( "ICC_MGRPEN1", "Interrupt Controller Monitor Interrupt Group 1 Enable register" ),

        ( "p15", "c15", 0, "c0", 0 )  : ( "IL1Data0", "Instruction L1 Data n Register" ),
        ( "p15", "c15", 0, "c0", 1 )  : ( "IL1Data1", "Instruction L1 Data n Register" ),
        ( "p15", "c15", 0, "c0", 2 )  : ( "IL1Data2", "Instruction L1 Data n Register" ),
        ( "p15", "c15", 0, "c1", 0 )  : ( "DL1Data0", "Data L1 Data n Register" ),
        ( "p15", "c15", 0, "c1", 1 )  : ( "DL1Data1", "Data L1 Data n Register" ),
        ( "p15", "c15", 0, "c1", 2 )  : ( "DL1Data2", "Data L1 Data n Register" ),
        ( "p15", "c15", 0, "c2", 0 )  : ( "N/A", "Data Memory Remap" ), # ARM11
        ( "p15", "c15", 0, "c2", 1 )  : ( "N/A", "Instruction Memory Remap" ), # ARM11
        ( "p15", "c15", 0, "c2", 2 )  : ( "N/A", "DMA Memory Remap" ), # ARM11
        ( "p15", "c15", 0, "c2", 3 )  : ( "N/A", "Peripheral Port Memory Remap" ), # ARM11
        ( "p15", "c15", 0, "c4", 0 )  : ( "RAMINDEX", "RAM Index Register" ),
        ( "p15", "c15", 0, "c12", 0 ) : ( "N/A", "Performance Monitor Control" ), #ARM11
        ( "p15", "c15", 0, "c12", 1 ) : ( "CCNT", "Cycle Counter" ), #ARM11
        ( "p15", "c15", 0, "c12", 2 ) : ( "PMN0", "Count 0" ), #ARM11
        ( "p15", "c15", 0, "c12", 3 ) : ( "PMN1", "Count 1" ), #ARM11
        ( "p15", "c15", 1, "c0", 0 )  : ( "L2ACTLR", "L2 Auxiliary Control Register" ),
        ( "p15", "c15", 1, "c0", 3 )  : ( "L2FPR", "L2 Prefetch Control Register" ),
        ( "p15", "c15", 3, "c0", 0 )  : ( "N/A", "Data Debug Cache" ), # ARM11
        ( "p15", "c15", 3, "c0", 1 )  : ( "N/A", "Instruction Debug Cache" ), # ARM11
        ( "p15", "c15", 3, "c2", 0 )  : ( "N/A", "Data Tag RAM Read Operation" ), # ARM11
        ( "p15", "c15", 3, "c2", 1 )  : ( "N/A", "Instruction Tag RAM Read Operation" ), # ARM11
        ( "p15", "c15", 4, "c0", 0 )  : ( "CBAR", "Configuration Base Address Register" ),
        ( "p15", "c15", 5, "c4", 0 )  : ( "N/A", "Data MicroTLB Index" ), # ARM11
        ( "p15", "c15", 5, "c4", 1 )  : ( "N/A", "Instruction MicroTLB Index" ), # ARM11
        ( "p15", "c15", 5, "c4", 2 )  : ( "N/A", "Read Main TLB Entry" ), # ARM11
        ( "p15", "c15", 5, "c4", 4 )  : ( "N/A", "Write Main TLB Entry" ), # ARM11
        ( "p15", "c15", 5, "c5", 0 )  : ( "N/A", "Data MicroTLB VA" ), # ARM11
        ( "p15", "c15", 5, "c5", 1 )  : ( "N/A", "Instruction MicroTLB VA" ), # ARM11
        ( "p15", "c15", 5, "c5", 2 )  : ( "N/A", "Main TLB VA" ), # ARM11
        ( "p15", "c15", 5, "c7", 0 )  : ( "N/A", "Data MicroTLB Attribute" ), # ARM11
        ( "p15", "c15", 5, "c7", 1 )  : ( "N/A", "Instruction MicroTLB Attribute" ), # ARM11
        ( "p15", "c15", 5, "c7", 2 )  : ( "N/A", "Main TLB Attribute" ), # ARM11
        ( "p15", "c15", 7, "c0", 0 )  : ( "N/A", "Cache Debug Control" ), # ARM11
        ( "p15", "c15", 7, "c1", 0 )  : ( "N/A", "TLB Debug Control" ), # ARM11

        # Preload Engine control registers
        ( "p15", "c11", 0, "c0", 0 )   : ( "PLEIDR", "Preload Engine ID Register" ),
        ( "p15", "c11", 0, "c0", 2 )   : ( "PLEASR", "Preload Engine Activity Status Register" ),
        ( "p15", "c11", 0, "c0", 4 )   : ( "PLEFSR", "Preload Engine FIFO Status Register" ),
        ( "p15", "c11", 0, "c1", 0 )   : ( "PLEUAR", "Preload Engine User Accessibility Register" ),
        ( "p15", "c11", 0, "c1", 1 )   : ( "PLEPCR", "Preload Engine Parameters Control Register" ),

        # Preload Engine operations
        ( "p15", "c11", 0, "c2", 1 )   : ( "PLEFF", "Preload Engine FIFO flush operation" ),
        ( "p15", "c11", 0, "c3", 0 )   : ( "PLEPC", "Preload Engine pause channel operation" ),
        ( "p15", "c11", 0, "c3", 1 )   : ( "PLERC", "Preload Engine resume channel operation" ),
        ( "p15", "c11", 0, "c3", 2 )   : ( "PLEKC", "Preload Engine kill channel operation" ),

        # Jazelle registers
        ( "p14", "c0", 7, "c0", 0 )   : ( "JIDR", "Jazelle ID Register" ),
        ( "p14", "c1", 7, "c0", 0 )   : ( "JOSCR", "Jazelle OS Control Register" ),
        ( "p14", "c2", 7, "c0", 0 )   : ( "JMCR", "Jazelle Main Configuration Register" ),

        # Debug registers
        ( "p15", "c4", 3, "c5", 0 )   : ( "DSPSR", "Debug Saved Program Status Register" ),
        ( "p15", "c4", 3, "c5", 1 )   : ( "DLR", "Debug Link Register" ),
        ( "p14", "c0", 0, "c0", 0 )   : ( "DBGDIDR", "Debug ID Register" ),
        ( "p14", "c0", 0, "c6", 0 )   : ( "DBGWFAR", "Debug Watchpoint Fault Address Register" ),
        ( "p14", "c0", 0, "c6", 2 )   : ( "DBGOSECCR", "Debug OS Lock Exception Catch Control Register" ),
        ( "p14", "c0", 0, "c7", 0 )   : ( "DBGVCR", "Debug Vector Catch Register" ),
        ( "p14", "c0", 0, "c0", 2 )   : ( "DBGDTRRXext", "Debug OS Lock Data Transfer Register, Receive, External View" ),
        ( "p14", "c0", 0, "c2", 0 )   : ( "DBGDCCINT", "DCC Interrupt Enable Register" ),
        ( "p14", "c0", 0, "c2", 2 )   : ( "DBGDSCRext", "Debug Status and Control Register, External View" ),
        ( "p14", "c0", 0, "c3", 2 )   : ( "DBGDTRTXext", "Debug OS Lock Data Transfer Register, Transmit" ),
        ( "p14", "c0", 0, "c0", 4 )   : ( "DBGBVR0", "Debug Breakpoint Value Register 0" ),
        ( "p14", "c0", 0, "c1", 4 )   : ( "DBGBVR1", "Debug Breakpoint Value Register 1" ),
        ( "p14", "c0", 0, "c2", 4 )   : ( "DBGBVR2", "Debug Breakpoint Value Register 2" ),
        ( "p14", "c0", 0, "c3", 4 )   : ( "DBGBVR3", "Debug Breakpoint Value Register 3" ),
        ( "p14", "c0", 0, "c4", 4 )   : ( "DBGBVR4", "Debug Breakpoint Value Register 4" ),
        ( "p14", "c0", 0, "c5", 4 )   : ( "DBGBVR5", "Debug Breakpoint Value Register 5" ),
        ( "p14", "c0", 0, "c6", 4 )   : ( "DBGBVR6", "Debug Breakpoint Value Register 6" ),
        ( "p14", "c0", 0, "c7", 4 )   : ( "DBGBVR7", "Debug Breakpoint Value Register 7" ),
        ( "p14", "c0", 0, "c8", 4 )   : ( "DBGBVR8", "Debug Breakpoint Value Register 8" ),
        ( "p14", "c0", 0, "c9", 4 )   : ( "DBGBVR9", "Debug Breakpoint Value Register 9" ),
        ( "p14", "c0", 0, "c10", 4 )  : ( "DBGBVR10", "Debug Breakpoint Value Register 10" ),
        ( "p14", "c0", 0, "c11", 4 )  : ( "DBGBVR11", "Debug Breakpoint Value Register 11" ),
        ( "p14", "c0", 0, "c12", 4 )  : ( "DBGBVR12", "Debug Breakpoint Value Register 12" ),
        ( "p14", "c0", 0, "c13", 4 )  : ( "DBGBVR13", "Debug Breakpoint Value Register 13" ),
        ( "p14", "c0", 0, "c14", 4 )  : ( "DBGBVR14", "Debug Breakpoint Value Register 14" ),
        ( "p14", "c0", 0, "c15", 4 )  : ( "DBGBVR15", "Debug Breakpoint Value Register 15" ),
        ( "p14", "c0", 0, "c0", 5 )   : ( "DBGBCR0", "Debug Breakpoint Control Register 0" ),
        ( "p14", "c0", 0, "c1", 5 )   : ( "DBGBCR1", "Debug Breakpoint Control Register 1" ),
        ( "p14", "c0", 0, "c2", 5 )   : ( "DBGBCR2", "Debug Breakpoint Control Register 2" ),
        ( "p14", "c0", 0, "c3", 5 )   : ( "DBGBCR3", "Debug Breakpoint Control Register 3" ),
        ( "p14", "c0", 0, "c4", 5 )   : ( "DBGBCR4", "Debug Breakpoint Control Register 4" ),
        ( "p14", "c0", 0, "c5", 5 )   : ( "DBGBCR5", "Debug Breakpoint Control Register 5" ),
        ( "p14", "c0", 0, "c6", 5 )   : ( "DBGBCR6", "Debug Breakpoint Control Register 6" ),
        ( "p14", "c0", 0, "c7", 5 )   : ( "DBGBCR7", "Debug Breakpoint Control Register 7" ),
        ( "p14", "c0", 0, "c8", 5 )   : ( "DBGBCR8", "Debug Breakpoint Control Register 8" ),
        ( "p14", "c0", 0, "c9", 5 )   : ( "DBGBCR9", "Debug Breakpoint Control Register 9" ),
        ( "p14", "c0", 0, "c10", 5 )  : ( "DBGBCR10", "Debug Breakpoint Control Register 10" ),
        ( "p14", "c0", 0, "c11", 5 )  : ( "DBGBCR11", "Debug Breakpoint Control Register 11" ),
        ( "p14", "c0", 0, "c12", 5 )  : ( "DBGBCR12", "Debug Breakpoint Control Register 12" ),
        ( "p14", "c0", 0, "c13", 5 )  : ( "DBGBCR13", "Debug Breakpoint Control Register 13" ),
        ( "p14", "c0", 0, "c14", 5 )  : ( "DBGBCR14", "Debug Breakpoint Control Register 14" ),
        ( "p14", "c0", 0, "c15", 5 )  : ( "DBGBCR15", "Debug Breakpoint Control Register 15" ),
        ( "p14", "c0", 0, "c0", 6 )   : ( "DBGWVR0", "Debug Watchpoint Value Register 0" ),
        ( "p14", "c0", 0, "c1", 6 )   : ( "DBGWVR1", "Debug Watchpoint Value Register 1" ),
        ( "p14", "c0", 0, "c2", 6 )   : ( "DBGWVR2", "Debug Watchpoint Value Register 2" ),
        ( "p14", "c0", 0, "c3", 6 )   : ( "DBGWVR3", "Debug Watchpoint Value Register 3" ),
        ( "p14", "c0", 0, "c4", 6 )   : ( "DBGWVR4", "Debug Watchpoint Value Register 4" ),
        ( "p14", "c0", 0, "c5", 6 )   : ( "DBGWVR5", "Debug Watchpoint Value Register 5" ),
        ( "p14", "c0", 0, "c6", 6 )   : ( "DBGWVR6", "Debug Watchpoint Value Register 6" ),
        ( "p14", "c0", 0, "c7", 6 )   : ( "DBGWVR7", "Debug Watchpoint Value Register 7" ),
        ( "p14", "c0", 0, "c8", 6 )   : ( "DBGWVR8", "Debug Watchpoint Value Register 8" ),
        ( "p14", "c0", 0, "c9", 6 )   : ( "DBGWVR9", "Debug Watchpoint Value Register 9" ),
        ( "p14", "c0", 0, "c10", 6 )  : ( "DBGWVR10", "Debug Watchpoint Value Register 10" ),
        ( "p14", "c0", 0, "c11", 6 )  : ( "DBGWVR11", "Debug Watchpoint Value Register 11" ),
        ( "p14", "c0", 0, "c12", 6 )  : ( "DBGWVR12", "Debug Watchpoint Value Register 12" ),
        ( "p14", "c0", 0, "c13", 6 )  : ( "DBGWVR13", "Debug Watchpoint Value Register 13" ),
        ( "p14", "c0", 0, "c14", 6 )  : ( "DBGWVR14", "Debug Watchpoint Value Register 14" ),
        ( "p14", "c0", 0, "c15", 6 )  : ( "DBGWVR15", "Debug Watchpoint Value Register 15" ),
        ( "p14", "c0", 0, "c0", 7 )   : ( "DBGWCR0", "Debug Watchpoint Control Register 0" ),
        ( "p14", "c0", 0, "c1", 7 )   : ( "DBGWCR1", "Debug Watchpoint Control Register 1" ),
        ( "p14", "c0", 0, "c2", 7 )   : ( "DBGWCR2", "Debug Watchpoint Control Register 2" ),
        ( "p14", "c0", 0, "c3", 7 )   : ( "DBGWCR3", "Debug Watchpoint Control Register 3" ),
        ( "p14", "c0", 0, "c4", 7 )   : ( "DBGWCR4", "Debug Watchpoint Control Register 4" ),
        ( "p14", "c0", 0, "c5", 7 )   : ( "DBGWCR5", "Debug Watchpoint Control Register 5" ),
        ( "p14", "c0", 0, "c6", 7 )   : ( "DBGWCR6", "Debug Watchpoint Control Register 6" ),
        ( "p14", "c0", 0, "c7", 7 )   : ( "DBGWCR7", "Debug Watchpoint Control Register 7" ),
        ( "p14", "c0", 0, "c8", 7 )   : ( "DBGWCR8", "Debug Watchpoint Control Register 8" ),
        ( "p14", "c0", 0, "c9", 7 )   : ( "DBGWCR9", "Debug Watchpoint Control Register 9" ),
        ( "p14", "c0", 0, "c10", 7 )  : ( "DBGWCR10", "Debug Watchpoint Control Register 10" ),
        ( "p14", "c0", 0, "c11", 7 )  : ( "DBGWCR11", "Debug Watchpoint Control Register 11" ),
        ( "p14", "c0", 0, "c12", 7 )  : ( "DBGWCR12", "Debug Watchpoint Control Register 12" ),
        ( "p14", "c0", 0, "c13", 7 )  : ( "DBGWCR13", "Debug Watchpoint Control Register 13" ),
        ( "p14", "c0", 0, "c14", 7 )  : ( "DBGWCR14", "Debug Watchpoint Control Register 14" ),
        ( "p14", "c0", 0, "c15", 7 )  : ( "DBGWCR15", "Debug Watchpoint Control Register 15" ),
        ( "p14", "c1", 0, "c0", 1 )   : ( "DBGBXVR0", "Debug Breakpoint Extended Value Register 0" ),
        ( "p14", "c1", 0, "c1", 1 )   : ( "DBGBXVR1", "Debug Breakpoint Extended Value Register 1" ),
        ( "p14", "c1", 0, "c2", 1 )   : ( "DBGBXVR2", "Debug Breakpoint Extended Value Register 2" ),
        ( "p14", "c1", 0, "c3", 1 )   : ( "DBGBXVR3", "Debug Breakpoint Extended Value Register 3" ),
        ( "p14", "c1", 0, "c4", 1 )   : ( "DBGBXVR4", "Debug Breakpoint Extended Value Register 4" ),
        ( "p14", "c1", 0, "c5", 1 )   : ( "DBGBXVR5", "Debug Breakpoint Extended Value Register 5" ),
        ( "p14", "c1", 0, "c6", 1 )   : ( "DBGBXVR6", "Debug Breakpoint Extended Value Register 6" ),
        ( "p14", "c1", 0, "c7", 1 )   : ( "DBGBXVR7", "Debug Breakpoint Extended Value Register 7" ),
        ( "p14", "c1", 0, "c8", 1 )   : ( "DBGBXVR8", "Debug Breakpoint Extended Value Register 8" ),
        ( "p14", "c1", 0, "c9", 1 )   : ( "DBGBXVR9", "Debug Breakpoint Extended Value Register 9" ),
        ( "p14", "c1", 0, "c10", 1 )  : ( "DBGBXVR10", "Debug Breakpoint Extended Value Register 10" ),
        ( "p14", "c1", 0, "c11", 1 )  : ( "DBGBXVR11", "Debug Breakpoint Extended Value Register 11" ),
        ( "p14", "c1", 0, "c12", 1 )  : ( "DBGBXVR12", "Debug Breakpoint Extended Value Register 12" ),
        ( "p14", "c1", 0, "c13", 1 )  : ( "DBGBXVR13", "Debug Breakpoint Extended Value Register 13" ),
        ( "p14", "c1", 0, "c14", 1 )  : ( "DBGBXVR14", "Debug Breakpoint Extended Value Register 14" ),
        ( "p14", "c1", 0, "c15", 1 )  : ( "DBGBXVR15", "Debug Breakpoint Extended Value Register 15" ),
        ( "p14", "c1", 0, "c0", 4 )   : ( "DBGOSLAR", "Debug OS Lock Access Register" ),
        ( "p14", "c1", 0, "c1", 4 )   : ( "DBGOSLSR", "Debug OS Lock Status Register" ),
        ( "p14", "c1", 0, "c4", 4 )   : ( "DBGPRCR", "Debug Power Control Register" ),
        ( "p14", "c7", 0, "c14", 6 )  : ( "DBGAUTHSTATUS", "Debug Authentication Status register" ),
        ( "p14", "c7", 0, "c0", 7 )   : ( "DBGDEVID2", "Debug Device ID register 2" ),
        ( "p14", "c7", 0, "c1", 7 )   : ( "DBGDEVID1", "Debug Device ID register 1" ),
        ( "p14", "c7", 0, "c2", 7 )   : ( "DBGDEVID", "Debug Device ID register 0" ),
        ( "p14", "c7", 0, "c8", 6 )   : ( "DBGCLAIMSET", "Debug Claim Tag Set register" ),
        ( "p14", "c7", 0, "c9", 6 )   : ( "DBGCLAIMCLR", "Debug Claim Tag Clear register" ),
        ( "p14", "c0", 0, "c1", 0 )   : ( "DBGDSCRint", "Debug Status and Control Register, Internal View" ),
        ( "p14", "c0", 0, "c5", 0 )   : ( "DBGDTRRXint", "Debug Data Transfer Register, Receive",
                                          "DBGDTRTXint", "Debug Data Transfer Register, Transmit" ),
        ( "p14", "c1", 0, "c0", 0 )   : ( "DBGDRAR", "Debug ROM Address Register" ),
        ( "p14", "c1", 0, "c3", 4 )   : ( "DBGOSDLR", "Debug OS Double Lock Register" ),
        ( "p14", "c2", 0, "c0", 0 )   : ( "DBGDSAR", "Debug Self Address Register" ),
}

# Aarch64 system registers.
# Extracted from the 00bet4 XML specifications for ARMv8.3.
SYSTEM_REGISTERS = {
        # Special purpose registers.
        ( 0b011, 0b000, "c4", "c2", 0b010 )   : ( "CurrentEL", "Current Exception Level" ),
        ( 0b011, 0b011, "c4", "c2", 0b001 )   : ( "DAIF", "Interrupt Mask Bits" ),
        ( 0b011, 0b000, "c4", "c0", 0b001 )   : ( "ELR_EL1", "Exception Link Register (EL1)" ),
        ( 0b011, 0b100, "c4", "c0", 0b001 )   : ( "ELR_EL2", "Exception Link Register (EL2)" ),
        ( 0b011, 0b101, "c4", "c0", 0b001 )   : ( "ELR_EL12", "Exception Link Register (EL1)" ),
        ( 0b011, 0b110, "c4", "c0", 0b001 )   : ( "ELR_EL3", "Exception Link Register (EL3)" ),
        ( 0b011, 0b011, "c4", "c4", 0b001 )   : ( "FPSR", "Floating-point Status Register" ),
        ( 0b011, 0b011, "c4", "c4", 0b000 )   : ( "FPCR", "Floating-point Control Register" ),
        ( 0b011, 0b011, "c4", "c2", 0b000 )   : ( "NZCV", "Condition Flags" ),
        ( 0b011, 0b000, "c4", "c1", 0b000 )   : ( "SP_EL0", "Stack Pointer (EL0)" ),
        ( 0b011, 0b100, "c4", "c1", 0b000 )   : ( "SP_EL1", "Stack Pointer (EL1)" ),
        ( 0b011, 0b110, "c4", "c1", 0b000 )   : ( "SP_EL2", "Stack Pointer (EL2)" ),
        ( 0b011, 0b000, "c4", "c2", 0b000 )   : ( "SPSel", "Stack Pointer Select" ),
        ( 0b011, 0b100, "c4", "c3", 0b001 )   : ( "SPSR_abt", "Saved Program Status Register (Abort mode)" ),
        ( 0b011, 0b000, "c4", "c0", 0b000 )   : ( "SPSR_EL1", "Saved Program Status Register (EL1)" ),
        ( 0b011, 0b100, "c4", "c0", 0b000 )   : ( "SPSR_EL2", "Saved Program Status Register (EL2)" ),
        ( 0b011, 0b101, "c4", "c0", 0b000 )   : ( "SPSR_EL12", "Saved Program Status Register (EL1)" ),
        ( 0b011, 0b110, "c4", "c0", 0b000 )   : ( "SPSR_EL3", "Saved Program Status Register (EL3)" ),
        ( 0b011, 0b100, "c4", "c3", 0b011 )   : ( "SPSR_fiq", "Saved Program Status Register (FIQ mode)" ),
        ( 0b011, 0b100, "c4", "c3", 0b000 )   : ( "SPSR_irq", "Saved Program Status Register (IRQ mode)" ),
        ( 0b011, 0b100, "c4", "c3", 0b010 )   : ( "SPSR_und", "Saved Program Status Register (Undefined mode)" ),

        # General system control registers.
        ( 0b011, 0b000, "c1", "c0", 0b001 )   : ( "ACTLR_EL1", "Auxiliary Control Register (EL1)" ),
        ( 0b011, 0b100, "c1", "c0", 0b001 )   : ( "ACTLR_EL2", "Auxiliary Control Register (EL2)" ),
        ( 0b011, 0b110, "c1", "c0", 0b001 )   : ( "ACTLR_EL3", "Auxiliary Control Register (EL3)" ),
        ( 0b011, 0b000, "c4", "c2", 0b011 )   : ( "PAN", "Privileged Access Never" ),
        ( 0b011, 0b000, "c4", "c2", 0b100 )   : ( "UAO", "User Access Override" ),
        ( 0b011, 0b000, "c5", "c1", 0b000 )   : ( "AFSR0_EL1", "Auxiliary Fault Status Register 0 (EL1)" ),
        ( 0b011, 0b100, "c5", "c1", 0b000 )   : ( "AFSR0_EL2", "Auxiliary Fault Status Register 0 (EL2)" ),
        ( 0b011, 0b101, "c5", "c1", 0b000 )   : ( "AFSR0_EL12", "Auxiliary Fault Status Register 0 (EL1)" ),
        ( 0b011, 0b110, "c5", "c1", 0b000 )   : ( "AFSR0_EL3", "Auxiliary Fault Status Register 0 (EL3)" ),
        ( 0b011, 0b000, "c5", "c1", 0b001 )   : ( "AFSR1_EL1", "Auxiliary Fault Status Register 1 (EL1)" ),
        ( 0b011, 0b100, "c5", "c1", 0b001 )   : ( "AFSR1_EL2", "Auxiliary Fault Status Register 1 (EL2)" ),
        ( 0b011, 0b101, "c5", "c1", 0b001 )   : ( "AFSR1_EL12", "Auxiliary Fault Status Register 1 (EL1)" ),
        ( 0b011, 0b110, "c5", "c1", 0b001 )   : ( "AFSR1_EL3", "Auxiliary Fault Status Register 1 (EL3)" ),
        ( 0b011, 0b001, "c0", "c0", 0b111 )   : ( "AIDR_EL1", "Auxiliary ID Register" ),
        ( 0b011, 0b000, "c10", "c3", 0b000 )  : ( "AMAIR_EL1", "Auxiliary Memory Attribute Indirection Register (EL1)" ),
        ( 0b011, 0b100, "c10", "c3", 0b000 )  : ( "AMAIR_EL2", "Auxiliary Memory Attribute Indirection Register (EL2)" ),
        ( 0b011, 0b101, "c10", "c3", 0b000 )  : ( "AMAIR_EL12", "Auxiliary Memory Attribute Indirection Register (EL1)" ),
        ( 0b011, 0b110, "c10", "c3", 0b000 )  : ( "AMAIR_EL3", "Auxiliary Memory Attribute Indirection Register (EL3)" ),
        ( 0b011, 0b001, "c0", "c0", 0b000 )   : ( "CCSIDR_EL1", "Current Cache Size ID Register" ),
        ( 0b011, 0b001, "c0", "c0", 0b010 )   : ( "CCSIDR2_EL1", "Current Cache Size ID Register 2" ),
        ( 0b011, 0b001, "c0", "c0", 0b001 )   : ( "CLIDR_EL1", "Cache Level ID Register" ),
        ( 0b011, 0b000, "c13", "c0", 0b001 )  : ( "CONTEXTIDR_EL1", "Context ID Register (EL1)" ),
        ( 0b011, 0b100, "c13", "c0", 0b001 )  : ( "CONTEXTIDR_EL2", "Context ID Register (EL2)" ),
        ( 0b011, 0b101, "c13", "c0", 0b001 )  : ( "CONTEXTIDR_EL12", "Context ID Register (EL1)" ),
        ( 0b011, 0b000, "c1", "c0", 0b010 )   : ( "CPACR_EL1", "Architectural Feature Access Control Register (EL1)" ),
        ( 0b011, 0b101, "c1", "c0", 0b010 )   : ( "CPACR_EL12", "Architectural Feature Access Control Register (EL1)" ),
        ( 0b011, 0b100, "c1", "c1", 0b010 )   : ( "CPTR_EL2", "Architectural Feature Trap Register (EL2)" ),
        ( 0b011, 0b110, "c1", "c1", 0b010 )   : ( "CPTR_EL3", "Architectural Feature Trap Register (EL3)" ),
        ( 0b011, 0b010, "c0", "c0", 0b000 )   : ( "CSSELR_EL1", "Cache Size Selection Register" ),
        ( 0b011, 0b011, "c0", "c0", 0b001 )   : ( "CTR_EL0", "Cache Type Register" ),
        ( 0b011, 0b100, "c3", "c0", 0b000 )   : ( "DACR32_EL2", "Domain Access Control Register" ),
        ( 0b011, 0b011, "c0", "c0", 0b111 )   : ( "DCZID_EL0", "Data Cache Zero ID register" ),
        ( 0b011, 0b000, "c5", "c2", 0b000 )   : ( "ESR_EL1", "Exception Syndrome Register (EL1)" ),
        ( 0b011, 0b100, "c5", "c2", 0b000 )   : ( "ESR_EL2", "Exception Syndrome Register (EL2)" ),
        ( 0b011, 0b101, "c5", "c2", 0b000 )   : ( "ESR_EL12", "Exception Syndrome Register (EL1)" ),
        ( 0b011, 0b110, "c5", "c2", 0b000 )   : ( "ESR_EL3", "Exception Syndrome Register (EL3)" ),
        ( 0b011, 0b000, "c6", "c0", 0b000 )   : ( "FAR_EL1", "Fault Address Register (EL1)" ),
        ( 0b011, 0b100, "c6", "c0", 0b000 )   : ( "FAR_EL2", "Fault Address Register (EL2)" ),
        ( 0b011, 0b101, "c6", "c0", 0b000 )   : ( "FAR_EL12", "Fault Address Register (EL1)" ),
        ( 0b011, 0b110, "c6", "c0", 0b000 )   : ( "FAR_EL3", "Fault Address Register (EL3)" ),
        ( 0b011, 0b100, "c5", "c3", 0b000 )   : ( "FPEXC32_EL2", "Floating-Point Exception Control register" ),
        ( 0b011, 0b100, "c1", "c1", 0b111 )   : ( "HACR_EL2", "Hypervisor Auxiliary Control Register" ),
        ( 0b011, 0b100, "c1", "c1", 0b000 )   : ( "HCR_EL2", "Hypervisor Configuration Register" ),
        ( 0b011, 0b100, "c6", "c0", 0b100 )   : ( "HPFAR_EL2", "Hypervisor IPA Fault Address Register" ),
        ( 0b011, 0b100, "c1", "c1", 0b011 )   : ( "HSTR_EL2", "Hypervisor System Trap Register" ),
        ( 0b011, 0b000, "c0", "c5", 0b100 )   : ( "ID_AA64AFR0_EL1", "AArch64 Auxiliary Feature Register 0" ),
        ( 0b011, 0b000, "c0", "c5", 0b101 )   : ( "ID_AA64AFR1_EL1", "AArch64 Auxiliary Feature Register 1" ),
        ( 0b011, 0b000, "c0", "c5", 0b000 )   : ( "ID_AA64DFR0_EL1", "AArch64 Debug Feature Register 0" ),
        ( 0b011, 0b000, "c0", "c5", 0b001 )   : ( "ID_AA64DFR1_EL1", "AArch64 Debug Feature Register 1" ),
        ( 0b011, 0b000, "c0", "c6", 0b000 )   : ( "ID_AA64ISAR0_EL1", "AArch64 Instruction Set Attribute Register 0" ),
        ( 0b011, 0b000, "c0", "c6", 0b001 )   : ( "ID_AA64ISAR1_EL1", "AArch64 Instruction Set Attribute Register 1" ),
        ( 0b011, 0b000, "c0", "c7", 0b000 )   : ( "ID_AA64MMFR0_EL1", "AArch64 Memory Model Feature Register 0" ),
        ( 0b011, 0b000, "c0", "c7", 0b001 )   : ( "ID_AA64MMFR1_EL1", "AArch64 Memory Model Feature Register 1" ),
        ( 0b011, 0b000, "c0", "c7", 0b010 )   : ( "ID_AA64MMFR2_EL1", "AArch64 Memory Model Feature Register 2" ),
        ( 0b011, 0b000, "c0", "c4", 0b000 )   : ( "ID_AA64PFR0_EL1", "AArch64 Processor Feature Register 0" ),
        ( 0b011, 0b000, "c0", "c4", 0b001 )   : ( "ID_AA64PFR1_EL1", "AArch64 Processor Feature Register 1" ),
        ( 0b011, 0b000, "c0", "c1", 0b011 )   : ( "ID_AFR0_EL1", "AArch32 Auxiliary Feature Register 0" ),
        ( 0b011, 0b000, "c0", "c1", 0b010 )   : ( "ID_DFR0_EL1", "AArch32 Debug Feature Register 0" ),
        ( 0b011, 0b000, "c0", "c2", 0b000 )   : ( "ID_ISAR0_EL1", "AArch32 Instruction Set Attribute Register 0" ),
        ( 0b011, 0b000, "c0", "c2", 0b001 )   : ( "ID_ISAR1_EL1", "AArch32 Instruction Set Attribute Register 1" ),
        ( 0b011, 0b000, "c0", "c2", 0b010 )   : ( "ID_ISAR2_EL1", "AArch32 Instruction Set Attribute Register 2" ),
        ( 0b011, 0b000, "c0", "c2", 0b011 )   : ( "ID_ISAR3_EL1", "AArch32 Instruction Set Attribute Register 3" ),
        ( 0b011, 0b000, "c0", "c2", 0b100 )   : ( "ID_ISAR4_EL1", "AArch32 Instruction Set Attribute Register 4" ),
        ( 0b011, 0b000, "c0", "c2", 0b101 )   : ( "ID_ISAR5_EL1", "AArch32 Instruction Set Attribute Register 5" ),
        ( 0b011, 0b000, "c0", "c2", 0b111 )   : ( "ID_ISAR6_EL1", "AArch32 Instruction Set Attribute Register 6" ),
        ( 0b011, 0b000, "c0", "c1", 0b100 )   : ( "ID_MMFR0_EL1", "AArch32 Memory Model Feature Register 0" ),
        ( 0b011, 0b000, "c0", "c1", 0b101 )   : ( "ID_MMFR1_EL1", "AArch32 Memory Model Feature Register 1" ),
        ( 0b011, 0b000, "c0", "c1", 0b110 )   : ( "ID_MMFR2_EL1", "AArch32 Memory Model Feature Register 2" ),
        ( 0b011, 0b000, "c0", "c1", 0b111 )   : ( "ID_MMFR3_EL1", "AArch32 Memory Model Feature Register 3" ),
        ( 0b011, 0b000, "c0", "c2", 0b110 )   : ( "ID_MMFR4_EL1", "AArch32 Memory Model Feature Register 4" ),
        ( 0b011, 0b000, "c0", "c1", 0b000 )   : ( "ID_PFR0_EL1", "AArch32 Processor Feature Register 0" ),
        ( 0b011, 0b000, "c0", "c1", 0b001 )   : ( "ID_PFR1_EL1", "AArch32 Processor Feature Register 1" ),
        ( 0b011, 0b100, "c5", "c0", 0b001 )   : ( "IFSR32_EL2", "Instruction Fault Status Register (EL2)" ),
        ( 0b011, 0b000, "c12", "c1", 0b000 )  : ( "ISR_EL1", "Interrupt Status Register" ),
        ( 0b011, 0b000, "c10", "c2", 0b000 )  : ( "MAIR_EL1", "Memory Attribute Indirection Register (EL1)" ),
        ( 0b011, 0b100, "c10", "c2", 0b000 )  : ( "MAIR_EL2", "Memory Attribute Indirection Register (EL2)" ),
        ( 0b011, 0b101, "c10", "c2", 0b000 )  : ( "MAIR_EL12", "Memory Attribute Indirection Register (EL1)" ),
        ( 0b011, 0b110, "c10", "c2", 0b000 )  : ( "MAIR_EL3", "Memory Attribute Indirection Register (EL3)" ),
        ( 0b011, 0b000, "c0", "c0", 0b000 )   : ( "MIDR_EL1", "Main ID Register" ),
        ( 0b011, 0b000, "c0", "c0", 0b101 )   : ( "MPIDR_EL1", "Multiprocessor Affinity Register" ),
        ( 0b011, 0b000, "c0", "c3", 0b000 )   : ( "MVFR0_EL1", "AArch32 Media and VFP Feature Register 0" ),
        ( 0b011, 0b000, "c0", "c3", 0b001 )   : ( "MVFR1_EL1", "AArch32 Media and VFP Feature Register 1" ),
        ( 0b011, 0b000, "c0", "c3", 0b010 )   : ( "MVFR2_EL1", "AArch32 Media and VFP Feature Register 2" ),
        ( 0b011, 0b000, "c7", "c4", 0b000 )   : ( "PAR_EL1", "Physical Address Register" ),
        ( 0b011, 0b000, "c0", "c0", 0b110 )   : ( "REVIDR_EL1", "Revision ID Register" ),
        ( 0b011, 0b000, "c12", "c0", 0b010 )  : ( "RMR_EL1", "Reset Management Register (EL1)" ),
        ( 0b011, 0b100, "c12", "c0", 0b010 )  : ( "RMR_EL2", "Reset Management Register (EL2)" ),
        ( 0b011, 0b110, "c12", "c0", 0b010 )  : ( "RMR_EL3", "Reset Management Register (EL3)" ),
        ( 0b011, 0b000, "c12", "c0", 0b001 )  : ( "RVBAR_EL1", "Reset Vector Base Address Register (if EL2 and EL3 not implemented)" ),
        ( 0b011, 0b100, "c12", "c0", 0b001 )  : ( "RVBAR_EL2", "Reset Vector Base Address Register (if EL3 not implemented)" ),
        ( 0b011, 0b110, "c12", "c0", 0b001 )  : ( "RVBAR_EL3", "Reset Vector Base Address Register (if EL3 implemented)" ),
        ( 0b011, 0b110, "c1", "c1", 0b000 )   : ( "SCR_EL3", "Secure Configuration Register" ),
        ( 0b011, 0b110, "c1", "c1", 0b001 )   : ( "SDER_EL3", "AArch32 Secure Debug Enable Register" ),
        ( 0b011, 0b000, "c1", "c0", 0b000 )   : ( "SCTLR_EL1", "System Control Register (EL1)" ),
        ( 0b011, 0b100, "c1", "c0", 0b000 )   : ( "SCTLR_EL2", "System Control Register (EL2)" ),
        ( 0b011, 0b101, "c1", "c0", 0b000 )   : ( "SCTLR_EL12", "System Control Register (EL1)" ),
        ( 0b011, 0b110, "c1", "c0", 0b000 )   : ( "SCTLR_EL3", "System Control Register (EL3)" ),
        ( 0b011, 0b000, "c2", "c0", 0b010 )   : ( "TCR_EL1", "Translation Control Register (EL1)" ),
        ( 0b011, 0b100, "c2", "c0", 0b010 )   : ( "TCR_EL2", "Translation Control Register (EL2)" ),
        ( 0b011, 0b101, "c2", "c0", 0b010 )   : ( "TCR_EL12", "Translation Control Register (EL1)" ),
        ( 0b011, 0b110, "c2", "c0", 0b010 )   : ( "TCR_EL3", "Translation Control Register (EL3)" ),
        ( 0b011, 0b010, "c0", "c0", 0b000 )   : ( "TEECR32_EL1", "T32EE Configuration Register" ), # Not defined in 8.2 specifications.
        ( 0b011, 0b010, "c1", "c0", 0b000 )   : ( "TEEHBR32_EL1", "T32EE Handler Base Register" ), # Not defined in 8.2 specifications.
        ( 0b011, 0b011, "c13", "c0", 0b010 )  : ( "TPIDR_EL0", "EL0 Read/Write Software Thread ID Register" ),
        ( 0b011, 0b000, "c13", "c0", 0b100 )  : ( "TPIDR_EL1", "EL1 Software Thread ID Register" ),
        ( 0b011, 0b100, "c13", "c0", 0b010 )  : ( "TPIDR_EL2", "EL2 Software Thread ID Register" ),
        ( 0b011, 0b110, "c13", "c0", 0b010 )  : ( "TPIDR_EL3", "EL3 Software Thread ID Register" ),
        ( 0b011, 0b011, "c13", "c0", 0b011 )  : ( "TPIDRRO_EL0", "EL0 Read-Only Software Thread ID Register" ),
        ( 0b011, 0b000, "c2", "c0", 0b000 )   : ( "TTBR0_EL1", "Translation Table Base Register 0 (EL1)" ),
        ( 0b011, 0b100, "c2", "c0", 0b000 )   : ( "TTBR0_EL2", "Translation Table Base Register 0 (EL2)" ),
        ( 0b011, 0b101, "c2", "c0", 0b000 )   : ( "TTBR0_EL12", "Translation Table Base Register 0 (EL1)" ),
        ( 0b011, 0b110, "c2", "c0", 0b000 )   : ( "TTBR0_EL3", "Translation Table Base Register 0 (EL3)" ),
        ( 0b011, 0b000, "c2", "c0", 0b001 )   : ( "TTBR1_EL1", "Translation Table Base Register 1 (EL1)" ),
        ( 0b011, 0b100, "c2", "c0", 0b001 )   : ( "TTBR1_EL2", "Translation Table Base Register 1 (EL2)" ),
        ( 0b011, 0b101, "c2", "c0", 0b001 )   : ( "TTBR1_EL12", "Translation Table Base Register 1 (EL1)" ),
        ( 0b011, 0b000, "c12", "c0", 0b000 )  : ( "VBAR_EL1", "Vector Base Address Register (EL1)" ),
        ( 0b011, 0b100, "c12", "c0", 0b000 )  : ( "VBAR_EL2", "Vector Base Address Register (EL2)" ),
        ( 0b011, 0b101, "c12", "c0", 0b000 )  : ( "VBAR_EL12", "Vector Base Address Register (EL1)" ),
        ( 0b011, 0b110, "c12", "c0", 0b000 )  : ( "VBAR_EL3", "Vector Base Address Register (EL3)" ),
        ( 0b011, 0b100, "c0", "c0", 0b101 )   : ( "VMPIDR_EL2", "Virtualization Multiprocessor ID Register" ),
        ( 0b011, 0b100, "c0", "c0", 0b000 )   : ( "VPIDR_EL2", "Virtualization Processor ID Register" ),
        ( 0b011, 0b100, "c2", "c1", 0b010 )   : ( "VTCR_EL2", "Virtualization Translation Control Register" ),
        ( 0b011, 0b100, "c2", "c1", 0b000 )   : ( "VTTBR_EL2", "Virtualization Translation Table Base Register" ),
        ( 0b011, 0b001, "c15", "c2", 0b000 )  : ( "CPUACTLR_EL1", "CPU Auxiliary Control Register (EL1)" ),
        ( 0b011, 0b001, "c15", "c2", 0b001 )  : ( "CPUECTLR_EL1", "CPU Extended Control Register (EL1)" ),
        ( 0b011, 0b001, "c15", "c2", 0b010 )  : ( "CPUMERRSR_EL1", "CPU Memory Error Syndrome Register" ),
        ( 0b011, 0b001, "c15", "c2", 0b011 )  : ( "L2MERRSR_EL1", "L2 Memory Error Syndrome Register" ),

        # Pointer authentication keys.
        ( 0b011, 0b000, "c2", "c1", 0b000 )   : ( "APIAKeyLo_EL1", "Pointer Authentication Key A for Instruction (bits[63:0]) " ),
        ( 0b011, 0b000, "c2", "c1", 0b001 )   : ( "APIAKeyHi_EL1", "Pointer Authentication Key A for Instruction (bits[127:64]) " ),
        ( 0b011, 0b000, "c2", "c1", 0b010 )   : ( "APIBKeyLo_EL1", "Pointer Authentication Key B for Instruction (bits[63:0]) " ),
        ( 0b011, 0b000, "c2", "c1", 0b011 )   : ( "APIBKeyHi_EL1", "Pointer Authentication Key B for Instruction (bits[127:64]) " ),
        ( 0b011, 0b000, "c2", "c2", 0b000 )   : ( "APDAKeyLo_EL1", "Pointer Authentication Key A for Data (bits[63:0]) " ),
        ( 0b011, 0b000, "c2", "c2", 0b001 )   : ( "APDAKeyHi_EL1", "Pointer Authentication Key A for Data (bits[127:64]) " ),
        ( 0b011, 0b000, "c2", "c2", 0b010 )   : ( "APDBKeyLo_EL1", "Pointer Authentication Key B for Data (bits[63:0]) " ),
        ( 0b011, 0b000, "c2", "c2", 0b011 )   : ( "APDBKeyHi_EL1", "Pointer Authentication Key B for Data (bits[127:64]) " ),
        ( 0b011, 0b000, "c2", "c3", 0b000 )   : ( "APGAKeyLo_EL1", "Pointer Authentication Key A for Code  (bits[63:0]) " ),
        ( 0b011, 0b000, "c2", "c3", 0b001 )   : ( "APGAKeyHi_EL1", "Pointer Authentication Key A for Code (bits[127:64]) " ),

        # Debug registers.
        ( 0b011, 0b100, "c1", "c1", 0b001 )   : ( "MDCR_EL2", "Monitor Debug Configuration Register (EL2)" ),
        ( 0b011, 0b110, "c1", "c3", 0b001 )   : ( "MDCR_EL3", "Monitor Debug Configuration Register (EL3)" ),
        ( 0b011, 0b011, "c4", "c5", 0b000 )   : ( "DSPSR_EL0", "Debug Saved Program Status Register" ),
        ( 0b011, 0b011, "c4", "c5", 0b001 )   : ( "DLR_EL0", "Debug Link Register" ),
        ( 0b010, 0b000, "c0", "c0", 0b010 )   : ( "OSDTRRX_EL1", "OS Lock Data Transfer Register, Receive" ),
        ( 0b010, 0b000, "c0", "c3", 0b010 )   : ( "OSDTRTX_EL1", "OS Lock Data Transfer Register, Transmit" ),
        ( 0b010, 0b000, "c0", "c6", 0b010 )   : ( "OSECCR_EL1", "OS Lock Exception Catch Control Register" ),
        ( 0b010, 0b011, "c0", "c4", 0b000 )   : ( "DBGDTR_EL0", "Debug Data Transfer Register, half-duplex" ),
        ( 0b010, 0b011, "c0", "c5", 0b000 )   : ( "DBGDTRTX_EL0", "Debug Data Transfer Register, Transmit",
                                                  "DBGDTRRX_EL0", "Debug Data Transfer Register, Receive" ),
        ( 0b010, 0b100, "c0", "c7", 0b000 )   : ( "DBGVCR32_EL2", "Debug Vector Catch Register" ),
        ( 0b010, 0b000, "c0", "c0", 0b100 )   : ( "DBGBVR0_EL1", "Debug Breakpoint Value Register 0" ),
        ( 0b010, 0b000, "c0", "c1", 0b100 )   : ( "DBGBVR1_EL1", "Debug Breakpoint Value Register 1" ),
        ( 0b010, 0b000, "c0", "c2", 0b100 )   : ( "DBGBVR2_EL1", "Debug Breakpoint Value Register 2" ),
        ( 0b010, 0b000, "c0", "c3", 0b100 )   : ( "DBGBVR3_EL1", "Debug Breakpoint Value Register 3" ),
        ( 0b010, 0b000, "c0", "c4", 0b100 )   : ( "DBGBVR4_EL1", "Debug Breakpoint Value Register 4" ),
        ( 0b010, 0b000, "c0", "c5", 0b100 )   : ( "DBGBVR5_EL1", "Debug Breakpoint Value Register 5" ),
        ( 0b010, 0b000, "c0", "c6", 0b100 )   : ( "DBGBVR6_EL1", "Debug Breakpoint Value Register 6" ),
        ( 0b010, 0b000, "c0", "c7", 0b100 )   : ( "DBGBVR7_EL1", "Debug Breakpoint Value Register 7" ),
        ( 0b010, 0b000, "c0", "c8", 0b100 )   : ( "DBGBVR8_EL1", "Debug Breakpoint Value Register 8" ),
        ( 0b010, 0b000, "c0", "c9", 0b100 )   : ( "DBGBVR9_EL1", "Debug Breakpoint Value Register 9" ),
        ( 0b010, 0b000, "c0", "c10", 0b100 )  : ( "DBGBVR10_EL1", "Debug Breakpoint Value Registers 10" ),
        ( 0b010, 0b000, "c0", "c11", 0b100 )  : ( "DBGBVR11_EL1", "Debug Breakpoint Value Registers 11" ),
        ( 0b010, 0b000, "c0", "c12", 0b100 )  : ( "DBGBVR12_EL1", "Debug Breakpoint Value Registers 12" ),
        ( 0b010, 0b000, "c0", "c13", 0b100 )  : ( "DBGBVR13_EL1", "Debug Breakpoint Value Registers 13" ),
        ( 0b010, 0b000, "c0", "c14", 0b100 )  : ( "DBGBVR14_EL1", "Debug Breakpoint Value Registers 14" ),
        ( 0b010, 0b000, "c0", "c15", 0b100 )  : ( "DBGBVR15_EL1", "Debug Breakpoint Value Registers 15" ),
        ( 0b010, 0b000, "c0", "c0", 0b101 )   : ( "DBGBCR0_EL1", "Debug Breakpoint Control Register 0" ),
        ( 0b010, 0b000, "c0", "c1", 0b101 )   : ( "DBGBCR1_EL1", "Debug Breakpoint Control Register 1" ),
        ( 0b010, 0b000, "c0", "c2", 0b101 )   : ( "DBGBCR2_EL1", "Debug Breakpoint Control Register 2" ),
        ( 0b010, 0b000, "c0", "c3", 0b101 )   : ( "DBGBCR3_EL1", "Debug Breakpoint Control Register 3" ),
        ( 0b010, 0b000, "c0", "c4", 0b101 )   : ( "DBGBCR4_EL1", "Debug Breakpoint Control Register 4" ),
        ( 0b010, 0b000, "c0", "c5", 0b101 )   : ( "DBGBCR5_EL1", "Debug Breakpoint Control Register 5" ),
        ( 0b010, 0b000, "c0", "c6", 0b101 )   : ( "DBGBCR6_EL1", "Debug Breakpoint Control Register 6" ),
        ( 0b010, 0b000, "c0", "c7", 0b101 )   : ( "DBGBCR7_EL1", "Debug Breakpoint Control Register 7" ),
        ( 0b010, 0b000, "c0", "c8", 0b101 )   : ( "DBGBCR8_EL1", "Debug Breakpoint Control Register 8" ),
        ( 0b010, 0b000, "c0", "c9", 0b101 )   : ( "DBGBCR9_EL1", "Debug Breakpoint Control Register 9" ),
        ( 0b010, 0b000, "c0", "c10", 0b101 )  : ( "DBGBCR10_EL1", "Debug Breakpoint Control Register 10" ),
        ( 0b010, 0b000, "c0", "c11", 0b101 )  : ( "DBGBCR11_EL1", "Debug Breakpoint Control Register 11" ),
        ( 0b010, 0b000, "c0", "c12", 0b101 )  : ( "DBGBCR12_EL1", "Debug Breakpoint Control Register 12" ),
        ( 0b010, 0b000, "c0", "c13", 0b101 )  : ( "DBGBCR13_EL1", "Debug Breakpoint Control Register 13" ),
        ( 0b010, 0b000, "c0", "c14", 0b101 )  : ( "DBGBCR14_EL1", "Debug Breakpoint Control Register 14" ),
        ( 0b010, 0b000, "c0", "c15", 0b101 )  : ( "DBGBCR15_EL1", "Debug Breakpoint Control Register 15" ),
        ( 0b010, 0b000, "c0", "c0", 0b110 )   : ( "DBGWVR0_EL1", "Debug Watchpoint Value Register 0" ),
        ( 0b010, 0b000, "c0", "c1", 0b110 )   : ( "DBGWVR1_EL1", "Debug Watchpoint Value Register 1" ),
        ( 0b010, 0b000, "c0", "c2", 0b110 )   : ( "DBGWVR2_EL1", "Debug Watchpoint Value Register 2" ),
        ( 0b010, 0b000, "c0", "c3", 0b110 )   : ( "DBGWVR3_EL1", "Debug Watchpoint Value Register 3" ),
        ( 0b010, 0b000, "c0", "c4", 0b110 )   : ( "DBGWVR4_EL1", "Debug Watchpoint Value Register 4" ),
        ( 0b010, 0b000, "c0", "c5", 0b110 )   : ( "DBGWVR5_EL1", "Debug Watchpoint Value Register 5" ),
        ( 0b010, 0b000, "c0", "c6", 0b110 )   : ( "DBGWVR6_EL1", "Debug Watchpoint Value Register 6" ),
        ( 0b010, 0b000, "c0", "c7", 0b110 )   : ( "DBGWVR7_EL1", "Debug Watchpoint Value Register 7" ),
        ( 0b010, 0b000, "c0", "c8", 0b110 )   : ( "DBGWVR8_EL1", "Debug Watchpoint Value Register 8" ),
        ( 0b010, 0b000, "c0", "c9", 0b110 )   : ( "DBGWVR9_EL1", "Debug Watchpoint Value Register 9" ),
        ( 0b010, 0b000, "c0", "c10", 0b110 )  : ( "DBGWVR10_EL1", "Debug Watchpoint Value Register 10" ),
        ( 0b010, 0b000, "c0", "c11", 0b110 )  : ( "DBGWVR11_EL1", "Debug Watchpoint Value Register 11" ),
        ( 0b010, 0b000, "c0", "c12", 0b110 )  : ( "DBGWVR12_EL1", "Debug Watchpoint Value Register 12" ),
        ( 0b010, 0b000, "c0", "c13", 0b110 )  : ( "DBGWVR13_EL1", "Debug Watchpoint Value Register 13" ),
        ( 0b010, 0b000, "c0", "c14", 0b110 )  : ( "DBGWVR14_EL1", "Debug Watchpoint Value Register 14" ),
        ( 0b010, 0b000, "c0", "c15", 0b110 )  : ( "DBGWVR15_EL1", "Debug Watchpoint Value Register 15" ),
        ( 0b010, 0b000, "c0", "c0", 0b111 )   : ( "DBGWCR0_EL1", "Debug Watchpoint Control Register 0" ),
        ( 0b010, 0b000, "c0", "c1", 0b111 )   : ( "DBGWCR1_EL1", "Debug Watchpoint Control Register 1" ),
        ( 0b010, 0b000, "c0", "c2", 0b111 )   : ( "DBGWCR2_EL1", "Debug Watchpoint Control Register 2" ),
        ( 0b010, 0b000, "c0", "c3", 0b111 )   : ( "DBGWCR3_EL1", "Debug Watchpoint Control Register 3" ),
        ( 0b010, 0b000, "c0", "c4", 0b111 )   : ( "DBGWCR4_EL1", "Debug Watchpoint Control Register 4" ),
        ( 0b010, 0b000, "c0", "c5", 0b111 )   : ( "DBGWCR5_EL1", "Debug Watchpoint Control Register 5" ),
        ( 0b010, 0b000, "c0", "c6", 0b111 )   : ( "DBGWCR6_EL1", "Debug Watchpoint Control Register 6" ),
        ( 0b010, 0b000, "c0", "c7", 0b111 )   : ( "DBGWCR7_EL1", "Debug Watchpoint Control Register 7" ),
        ( 0b010, 0b000, "c0", "c8", 0b111 )   : ( "DBGWCR8_EL1", "Debug Watchpoint Control Register 8" ),
        ( 0b010, 0b000, "c0", "c9", 0b111 )   : ( "DBGWCR9_EL1", "Debug Watchpoint Control Register 9" ),
        ( 0b010, 0b000, "c0", "c10", 0b111 )  : ( "DBGWCR10_EL1", "Debug Watchpoint Control Register 10" ),
        ( 0b010, 0b000, "c0", "c11", 0b111 )  : ( "DBGWCR11_EL1", "Debug Watchpoint Control Register 11" ),
        ( 0b010, 0b000, "c0", "c12", 0b111 )  : ( "DBGWCR12_EL1", "Debug Watchpoint Control Register 12" ),
        ( 0b010, 0b000, "c0", "c13", 0b111 )  : ( "DBGWCR13_EL1", "Debug Watchpoint Control Register 13" ),
        ( 0b010, 0b000, "c0", "c14", 0b111 )  : ( "DBGWCR14_EL1", "Debug Watchpoint Control Register 14" ),
        ( 0b010, 0b000, "c0", "c15", 0b111 )  : ( "DBGWCR15_EL1", "Debug Watchpoint Control Register 15" ),
        ( 0b010, 0b011, "c0", "c1", 0b000 )   : ( "MDCCSR_EL0", "Monitor DCC Status Register" ),
        ( 0b010, 0b000, "c0", "c2", 0b000 )   : ( "MDCCINT_EL1", "Monitor DCC Interrupt Enable Register" ),
        ( 0b010, 0b000, "c0", "c2", 0b010 )   : ( "MDSCR_EL1", "Monitor Debug System Control Register" ),
        ( 0b010, 0b000, "c1", "c0", 0b000 )   : ( "MDRAR_EL1", "Monitor Debug ROM Address Register" ),
        ( 0b010, 0b000, "c1", "c0", 0b100 )   : ( "OSLAR_EL1", "OS Lock Access Register" ),
        ( 0b010, 0b000, "c1", "c1", 0b100 )   : ( "OSLSR_EL1", "OS Lock Status Register" ),
        ( 0b010, 0b000, "c1", "c3", 0b100 )   : ( "OSDLR_EL1", "OS Double Lock Register" ),
        ( 0b010, 0b000, "c1", "c4", 0b100 )   : ( "DBGPRCR_EL1", "Debug Power Control Register" ),
        ( 0b010, 0b000, "c7", "c8", 0b110 )   : ( "DBGCLAIMSET_EL1", "Debug Claim Tag Set register" ),
        ( 0b010, 0b000, "c7", "c9", 0b110 )   : ( "DBGCLAIMCLR_EL1", "Debug Claim Tag Clear register" ),
        ( 0b010, 0b000, "c7", "c14", 0b110 )  : ( "DBGAUTHSTATUS_EL1", "Debug Authentication Status register" ),

        # Limited ordering regions.
        ( 0b011, 0b000, "c10", "c4", 0b011 )  : ( "LORC_EL1", "LORegion Control (EL1)" ),
        ( 0b011, 0b000, "c10", "c4", 0b000 )  : ( "LORSA_EL1", "LORegion Start Address (EL1)" ),
        ( 0b011, 0b000, "c10", "c4", 0b001 )  : ( "LOREA_EL1", "LORegion End Address (EL1)" ),
        ( 0b011, 0b000, "c10", "c4", 0b010 )  : ( "LORN_EL1", "LORegion Number (EL1)" ),
        ( 0b011, 0b000, "c10", "c4", 0b111 )  : ( "LORID_EL1", "LORegionID (EL1)" ),

        # Performance monitor registers.
        ( 0b011, 0b011, "c14", "c15", 0b111 ) : ( "PMCCFILTR_EL0", "Performance Monitors Cycle Count Filter Register" ),
        ( 0b011, 0b011, "c9", "c13", 0b000 )  : ( "PMCCNTR_EL0", "Performance Monitors Cycle Count Register" ),
        ( 0b011, 0b011, "c9", "c12", 0b110 )  : ( "PMCEID0_EL0", "Performance Monitors Common Event Identification register 0" ),
        ( 0b011, 0b011, "c9", "c12", 0b111 )  : ( "PMCEID1_EL0", "Performance Monitors Common Event Identification register 1" ),
        ( 0b011, 0b011, "c9", "c12", 0b010 )  : ( "PMCNTENCLR_EL0", "Performance Monitors Count Enable Clear register" ),
        ( 0b011, 0b011, "c9", "c12", 0b001 )  : ( "PMCNTENSET_EL0", "Performance Monitors Count Enable Set register" ),
        ( 0b011, 0b011, "c9", "c12", 0b000 )  : ( "PMCR_EL0", "Performance Monitors Control Register" ),
        ( 0b011, 0b011, "c14", "c8", 0b000 )  : ( "PMEVCNTR0_EL0", "Performance Monitors Event Count Register 0" ),
        ( 0b011, 0b011, "c14", "c8", 0b001 )  : ( "PMEVCNTR1_EL0", "Performance Monitors Event Count Register 1" ),
        ( 0b011, 0b011, "c14", "c8", 0b010 )  : ( "PMEVCNTR2_EL0", "Performance Monitors Event Count Register 2" ),
        ( 0b011, 0b011, "c14", "c8", 0b011 )  : ( "PMEVCNTR3_EL0", "Performance Monitors Event Count Register 3" ),
        ( 0b011, 0b011, "c14", "c8", 0b100 )  : ( "PMEVCNTR4_EL0", "Performance Monitors Event Count Register 4" ),
        ( 0b011, 0b011, "c14", "c8", 0b101 )  : ( "PMEVCNTR5_EL0", "Performance Monitors Event Count Register 5" ),
        ( 0b011, 0b011, "c14", "c8", 0b110 )  : ( "PMEVCNTR6_EL0", "Performance Monitors Event Count Register 6" ),
        ( 0b011, 0b011, "c14", "c8", 0b111 )  : ( "PMEVCNTR7_EL0", "Performance Monitors Event Count Register 7" ),
        ( 0b011, 0b011, "c14", "c9", 0b000 )  : ( "PMEVCNTR8_EL0", "Performance Monitors Event Count Register 8" ),
        ( 0b011, 0b011, "c14", "c9", 0b001 )  : ( "PMEVCNTR9_EL0", "Performance Monitors Event Count Register 9" ),
        ( 0b011, 0b011, "c14", "c9", 0b010 )  : ( "PMEVCNTR10_EL0", "Performance Monitors Event Count Register 10" ),
        ( 0b011, 0b011, "c14", "c9", 0b011 )  : ( "PMEVCNTR11_EL0", "Performance Monitors Event Count Register 11" ),
        ( 0b011, 0b011, "c14", "c9", 0b100 )  : ( "PMEVCNTR12_EL0", "Performance Monitors Event Count Register 12" ),
        ( 0b011, 0b011, "c14", "c9", 0b101 )  : ( "PMEVCNTR13_EL0", "Performance Monitors Event Count Register 13" ),
        ( 0b011, 0b011, "c14", "c9", 0b110 )  : ( "PMEVCNTR14_EL0", "Performance Monitors Event Count Register 14" ),
        ( 0b011, 0b011, "c14", "c9", 0b111 )  : ( "PMEVCNTR15_EL0", "Performance Monitors Event Count Register 15" ),
        ( 0b011, 0b011, "c14", "c10", 0b000 ) : ( "PMEVCNTR16_EL0", "Performance Monitors Event Count Register 16" ),
        ( 0b011, 0b011, "c14", "c10", 0b001 ) : ( "PMEVCNTR17_EL0", "Performance Monitors Event Count Register 17" ),
        ( 0b011, 0b011, "c14", "c10", 0b010 ) : ( "PMEVCNTR18_EL0", "Performance Monitors Event Count Register 18" ),
        ( 0b011, 0b011, "c14", "c10", 0b011 ) : ( "PMEVCNTR19_EL0", "Performance Monitors Event Count Register 19" ),
        ( 0b011, 0b011, "c14", "c10", 0b100 ) : ( "PMEVCNTR20_EL0", "Performance Monitors Event Count Register 20" ),
        ( 0b011, 0b011, "c14", "c10", 0b101 ) : ( "PMEVCNTR21_EL0", "Performance Monitors Event Count Register 21" ),
        ( 0b011, 0b011, "c14", "c10", 0b110 ) : ( "PMEVCNTR22_EL0", "Performance Monitors Event Count Register 22" ),
        ( 0b011, 0b011, "c14", "c10", 0b111 ) : ( "PMEVCNTR23_EL0", "Performance Monitors Event Count Register 23" ),
        ( 0b011, 0b011, "c14", "c11", 0b000 ) : ( "PMEVCNTR24_EL0", "Performance Monitors Event Count Register 24" ),
        ( 0b011, 0b011, "c14", "c11", 0b001 ) : ( "PMEVCNTR25_EL0", "Performance Monitors Event Count Register 25" ),
        ( 0b011, 0b011, "c14", "c11", 0b010 ) : ( "PMEVCNTR26_EL0", "Performance Monitors Event Count Register 26" ),
        ( 0b011, 0b011, "c14", "c11", 0b011 ) : ( "PMEVCNTR27_EL0", "Performance Monitors Event Count Register 27" ),
        ( 0b011, 0b011, "c14", "c11", 0b100 ) : ( "PMEVCNTR28_EL0", "Performance Monitors Event Count Register 28" ),
        ( 0b011, 0b011, "c14", "c11", 0b101 ) : ( "PMEVCNTR29_EL0", "Performance Monitors Event Count Register 29" ),
        ( 0b011, 0b011, "c14", "c11", 0b110 ) : ( "PMEVCNTR30_EL0", "Performance Monitors Event Count Register 30" ),
        ( 0b011, 0b011, "c14", "c12", 0b000 ) : ( "PMEVTYPER0_EL0", "Performance Monitors Event Type Register 0" ),
        ( 0b011, 0b011, "c14", "c12", 0b001 ) : ( "PMEVTYPER1_EL0", "Performance Monitors Event Type Register 1" ),
        ( 0b011, 0b011, "c14", "c12", 0b010 ) : ( "PMEVTYPER2_EL0", "Performance Monitors Event Type Register 2" ),
        ( 0b011, 0b011, "c14", "c12", 0b011 ) : ( "PMEVTYPER3_EL0", "Performance Monitors Event Type Register 3" ),
        ( 0b011, 0b011, "c14", "c12", 0b100 ) : ( "PMEVTYPER4_EL0", "Performance Monitors Event Type Register 4" ),
        ( 0b011, 0b011, "c14", "c12", 0b101 ) : ( "PMEVTYPER5_EL0", "Performance Monitors Event Type Register 5" ),
        ( 0b011, 0b011, "c14", "c12", 0b110 ) : ( "PMEVTYPER6_EL0", "Performance Monitors Event Type Register 6" ),
        ( 0b011, 0b011, "c14", "c12", 0b111 ) : ( "PMEVTYPER7_EL0", "Performance Monitors Event Type Register 7" ),
        ( 0b011, 0b011, "c14", "c13", 0b000 ) : ( "PMEVTYPER8_EL0", "Performance Monitors Event Type Register 8" ),
        ( 0b011, 0b011, "c14", "c13", 0b001 ) : ( "PMEVTYPER9_EL0", "Performance Monitors Event Type Register 9" ),
        ( 0b011, 0b011, "c14", "c13", 0b010 ) : ( "PMEVTYPER10_EL0", "Performance Monitors Event Type Register 10" ),
        ( 0b011, 0b011, "c14", "c13", 0b011 ) : ( "PMEVTYPER11_EL0", "Performance Monitors Event Type Register 11" ),
        ( 0b011, 0b011, "c14", "c13", 0b100 ) : ( "PMEVTYPER12_EL0", "Performance Monitors Event Type Register 12" ),
        ( 0b011, 0b011, "c14", "c13", 0b101 ) : ( "PMEVTYPER13_EL0", "Performance Monitors Event Type Register 13" ),
        ( 0b011, 0b011, "c14", "c13", 0b110 ) : ( "PMEVTYPER14_EL0", "Performance Monitors Event Type Register 14" ),
        ( 0b011, 0b011, "c14", "c13", 0b111 ) : ( "PMEVTYPER15_EL0", "Performance Monitors Event Type Register 15" ),
        ( 0b011, 0b011, "c14", "c14", 0b000 ) : ( "PMEVTYPER16_EL0", "Performance Monitors Event Type Register 16" ),
        ( 0b011, 0b011, "c14", "c14", 0b001 ) : ( "PMEVTYPER17_EL0", "Performance Monitors Event Type Register 17" ),
        ( 0b011, 0b011, "c14", "c14", 0b010 ) : ( "PMEVTYPER18_EL0", "Performance Monitors Event Type Register 18" ),
        ( 0b011, 0b011, "c14", "c14", 0b011 ) : ( "PMEVTYPER19_EL0", "Performance Monitors Event Type Register 19" ),
        ( 0b011, 0b011, "c14", "c14", 0b100 ) : ( "PMEVTYPER20_EL0", "Performance Monitors Event Type Register 20" ),
        ( 0b011, 0b011, "c14", "c14", 0b101 ) : ( "PMEVTYPER21_EL0", "Performance Monitors Event Type Register 21" ),
        ( 0b011, 0b011, "c14", "c14", 0b110 ) : ( "PMEVTYPER22_EL0", "Performance Monitors Event Type Register 22" ),
        ( 0b011, 0b011, "c14", "c14", 0b111 ) : ( "PMEVTYPER23_EL0", "Performance Monitors Event Type Register 23" ),
        ( 0b011, 0b011, "c14", "c15", 0b000 ) : ( "PMEVTYPER24_EL0", "Performance Monitors Event Type Register 24" ),
        ( 0b011, 0b011, "c14", "c15", 0b001 ) : ( "PMEVTYPER25_EL0", "Performance Monitors Event Type Register 25" ),
        ( 0b011, 0b011, "c14", "c15", 0b010 ) : ( "PMEVTYPER26_EL0", "Performance Monitors Event Type Register 26" ),
        ( 0b011, 0b011, "c14", "c15", 0b011 ) : ( "PMEVTYPER27_EL0", "Performance Monitors Event Type Register 27" ),
        ( 0b011, 0b011, "c14", "c15", 0b100 ) : ( "PMEVTYPER28_EL0", "Performance Monitors Event Type Register 28" ),
        ( 0b011, 0b011, "c14", "c15", 0b101 ) : ( "PMEVTYPER29_EL0", "Performance Monitors Event Type Register 29" ),
        ( 0b011, 0b011, "c14", "c15", 0b110 ) : ( "PMEVTYPER30_EL0", "Performance Monitors Event Type Register 30" ),
        ( 0b011, 0b000, "c9", "c14", 0b010 )  : ( "PMINTENCLR_EL1", "Performance Monitors Interrupt Enable Clear register" ),
        ( 0b011, 0b000, "c9", "c14", 0b001 )  : ( "PMINTENSET_EL1", "Performance Monitors Interrupt Enable Set register" ),
        ( 0b011, 0b011, "c9", "c12", 0b011 )  : ( "PMOVSCLR_EL0", "Performance Monitors Overflow Flag Status Clear Register" ),
        ( 0b011, 0b011, "c9", "c14", 0b011 )  : ( "PMOVSSET_EL0", "Performance Monitors Overflow Flag Status Set register" ),
        ( 0b011, 0b011, "c9", "c12", 0b101 )  : ( "PMSELR_EL0", "Performance Monitors Event Counter Selection Register" ),
        ( 0b011, 0b011, "c9", "c12", 0b100 )  : ( "PMSWINC_EL0", "Performance Monitors Software Increment register" ),
        ( 0b011, 0b011, "c9", "c14", 0b000 )  : ( "PMUSERENR_EL0", "Performance Monitors User Enable Register" ),
        ( 0b011, 0b011, "c9", "c13", 0b010 )  : ( "PMXEVCNTR_EL0", "Performance Monitors Selected Event Count Register" ),
        ( 0b011, 0b011, "c9", "c13", 0b001 )  : ( "PMXEVTYPER_EL0", "Performance Monitors Selected Event Type Register" ),

        # Generic Timer registers.
        ( 0b011, 0b011, "c14", "c0", 0b000 )  : ( "CNTFRQ_EL0", "Counter-timer Frequency register" ),
        ( 0b011, 0b100, "c14", "c1", 0b000 )  : ( "CNTHCTL_EL2", "Counter-timer Hypervisor Control register" ),
        ( 0b011, 0b100, "c14", "c2", 0b001 )  : ( "CNTHP_CTL_EL2", "Counter-timer Hypervisor Physical Timer Control register" ),
        ( 0b011, 0b100, "c14", "c2", 0b010 )  : ( "CNTHP_CVAL_EL2", "Counter-timer Hypervisor Physical Timer CompareValue register" ),
        ( 0b011, 0b100, "c14", "c2", 0b000 )  : ( "CNTHP_TVAL_EL2", "Counter-timer Hypervisor Physical Timer TimerValue register" ),
        ( 0b011, 0b100, "c14", "c3", 0b000 )  : ( "CNTHV_TVAL_EL2", "Counter-timer Virtual Timer TimerValue register (EL2)" ),
        ( 0b011, 0b100, "c14", "c3", 0b001 )  : ( "CNTHV_CTL_EL2", "Counter-timer Virtual Timer Control register (EL2)" ),
        ( 0b011, 0b100, "c14", "c3", 0b010 )  : ( "CNTHV_CVAL_EL2", "Counter-timer Virtual Timer CompareValue register (EL2)" ),
        ( 0b011, 0b000, "c14", "c1", 0b000 )  : ( "CNTKCTL_EL1", "Counter-timer Hypervisor Control register" ),
        ( 0b011, 0b101, "c14", "c1", 0b000 )  : ( "CNTKCTL_EL12", "Counter-timer Kernel Control register" ),
        ( 0b011, 0b011, "c14", "c2", 0b001 )  : ( "CNTP_CTL_EL0", "Counter-timer Hypervisor Physical Timer Control register" ),
        ( 0b011, 0b101, "c14", "c2", 0b001 )  : ( "CNTP_CTL_EL02", "Counter-timer Physical Timer Control register" ),
        ( 0b011, 0b011, "c14", "c2", 0b010 )  : ( "CNTP_CVAL_EL0", "Counter-timer Physical Timer CompareValue register" ),
        ( 0b011, 0b101, "c14", "c2", 0b010 )  : ( "CNTP_CVAL_EL02", "Counter-timer Physical Timer CompareValue register" ),
        ( 0b011, 0b011, "c14", "c2", 0b000 )  : ( "CNTP_TVAL_EL0", "Counter-timer Physical Timer TimerValue register" ),
        ( 0b011, 0b101, "c14", "c2", 0b000 )  : ( "CNTP_TVAL_EL02", "Counter-timer Physical Timer TimerValue register" ),
        ( 0b011, 0b011, "c14", "c0", 0b001 )  : ( "CNTPCT_EL0", "Counter-timer Physical Count register" ),
        ( 0b011, 0b111, "c14", "c2", 0b001 )  : ( "CNTPS_CTL_EL1", "Counter-timer Physical Secure Timer Control register" ),
        ( 0b011, 0b111, "c14", "c2", 0b010 )  : ( "CNTPS_CVAL_EL1", "Counter-timer Physical Secure Timer CompareValue register" ),
        ( 0b011, 0b111, "c14", "c2", 0b000 )  : ( "CNTPS_TVAL_EL1", "Counter-timer Physical Secure Timer TimerValue register" ),
        ( 0b011, 0b011, "c14", "c3", 0b001 )  : ( "CNTV_CTL_EL0", "Counter-timer Virtual Timer Control register (EL2)" ),
        ( 0b011, 0b101, "c14", "c3", 0b001 )  : ( "CNTV_CTL_EL02", "Counter-timer Virtual Timer Control register" ),
        ( 0b011, 0b011, "c14", "c3", 0b010 )  : ( "CNTV_CVAL_EL0", "Counter-timer Virtual Timer CompareValue register" ),
        ( 0b011, 0b101, "c14", "c3", 0b010 )  : ( "CNTV_CVAL_EL02", "Counter-timer Virtual Timer CompareValue register" ),
        ( 0b011, 0b011, "c14", "c3", 0b000 )  : ( "CNTV_TVAL_EL0", "Counter-timer Virtual Timer TimerValue register" ),
        ( 0b011, 0b101, "c14", "c3", 0b000 )  : ( "CNTV_TVAL_EL02", "Counter-timer Virtual Timer TimerValue register" ),
        ( 0b011, 0b011, "c14", "c0", 0b010 )  : ( "CNTVCT_EL0", "Counter-timer Virtual Count register" ),
        ( 0b011, 0b100, "c14", "c0", 0b011 )  : ( "CNTVOFF_EL2", "Counter-timer Virtual Offset register" ),

        # Generic Interrupt Controller CPU interface registers.
        ( 0b011, 0b000, "c12", "c8", 0b100 )  : ( "ICC_AP0R0_EL1", "Interrupt Controller Active Priorities Group 0 Register 0" ),
        ( 0b011, 0b000, "c12", "c8", 0b101 )  : ( "ICC_AP0R1_EL1", "Interrupt Controller Active Priorities Group 0 Register 1" ),
        ( 0b011, 0b000, "c12", "c8", 0b110 )  : ( "ICC_AP0R2_EL1", "Interrupt Controller Active Priorities Group 0 Register 2" ),
        ( 0b011, 0b000, "c12", "c8", 0b111 )  : ( "ICC_AP0R3_EL1", "Interrupt Controller Active Priorities Group 0 Register 3" ),
        ( 0b011, 0b000, "c12", "c9", 0b000 )  : ( "ICC_AP1R0_EL1", "Interrupt Controller Active Priorities Group 1 Register 0" ),
        ( 0b011, 0b000, "c12", "c9", 0b001 )  : ( "ICC_AP1R1_EL1", "Interrupt Controller Active Priorities Group 1 Register 1" ),
        ( 0b011, 0b000, "c12", "c9", 0b010 )  : ( "ICC_AP1R2_EL1", "Interrupt Controller Active Priorities Group 1 Register 2" ),
        ( 0b011, 0b000, "c12", "c9", 0b011 )  : ( "ICC_AP1R3_EL1", "Interrupt Controller Active Priorities Group 1 Register 3" ),
        ( 0b011, 0b000, "c12", "c11", 0b110 ) : ( "ICC_ASGI1R_EL1", "Interrupt Controller Alias Software Generated Interrupt Group 1 Register" ),
        ( 0b011, 0b000, "c12", "c8", 0b011 )  : ( "ICC_BPR0_EL1", "Interrupt Controller Binary Point Register 0" ),
        ( 0b011, 0b000, "c12", "c12", 0b011 ) : ( "ICC_BPR1_EL1", "Interrupt Controller Binary Point Register 1" ),
        ( 0b011, 0b000, "c12", "c12", 0b100 ) : ( "ICC_CTLR_EL1", "Interrupt Controller Virtual Control Register" ),
        ( 0b011, 0b110, "c12", "c12", 0b100 ) : ( "ICC_CTLR_EL3", "Interrupt Controller Control Register (EL3)" ),
        ( 0b011, 0b000, "c12", "c11", 0b001 ) : ( "ICC_DIR_EL1", "Interrupt Controller Deactivate Virtual Interrupt Register" ),
        ( 0b011, 0b000, "c12", "c8", 0b001 )  : ( "ICC_EOIR0_EL1", "Interrupt Controller End Of Interrupt Register 0" ),
        ( 0b011, 0b000, "c12", "c12", 0b001 ) : ( "ICC_EOIR1_EL1", "Interrupt Controller End Of Interrupt Register 1" ),
        ( 0b011, 0b000, "c12", "c8", 0b010 )  : ( "ICC_HPPIR0_EL1", "Interrupt Controller Virtual Highest Priority Pending Interrupt Register 0" ),
        ( 0b011, 0b000, "c12", "c12", 0b010 ) : ( "ICC_HPPIR1_EL1", "Interrupt Controller Virtual Highest Priority Pending Interrupt Register 1" ),
        ( 0b011, 0b000, "c12", "c8", 0b000 )  : ( "ICC_IAR0_EL1", "Interrupt Controller Virtual Interrupt Acknowledge Register 0" ),
        ( 0b011, 0b000, "c12", "c12", 0b000 ) : ( "ICC_IAR1_EL1", "Interrupt Controller Interrupt Acknowledge Register 1" ),
        ( 0b011, 0b000, "c12", "c12", 0b110 ) : ( "ICC_IGRPEN0_EL1", "Interrupt Controller Virtual Interrupt Group 0 Enable register" ),
        ( 0b011, 0b000, "c12", "c12", 0b111 ) : ( "ICC_IGRPEN1_EL1", "Interrupt Controller Interrupt Group 1 Enable register" ),
        ( 0b011, 0b110, "c12", "c12", 0b111 ) : ( "ICC_IGRPEN1_EL3", "Interrupt Controller Interrupt Group 1 Enable register (EL3)" ),
        ( 0b011, 0b000, "c4", "c6", 0b000 )   : ( "ICC_PMR_EL1", "Interrupt Controller Interrupt Priority Mask Register" ),
        ( 0b011, 0b000, "c12", "c11", 0b011 ) : ( "ICC_RPR_EL1", "Interrupt Controller Running Priority Register" ), # Not defined in 8.2 specifications.
        ( 0b011, 0b000, "c12", "c11", 0b000 ) : ( "ICC_SEIEN_EL1", "Interrupt Controller System Error Interrupt Enable Register" ),
        ( 0b011, 0b000, "c12", "c11", 0b111 ) : ( "ICC_SGI0R_EL1", "Interrupt Controller Software Generated Interrupt Group 0 Register" ),
        ( 0b011, 0b000, "c12", "c11", 0b101 ) : ( "ICC_SGI1R_EL1", "Interrupt Controller Software Generated Interrupt Group 1 Register" ),
        ( 0b011, 0b000, "c12", "c12", 0b101 ) : ( "ICC_SRE_EL1", "Interrupt Controller System Register Enable register (EL1)" ),
        ( 0b011, 0b100, "c12", "c9", 0b101 )  : ( "ICC_SRE_EL2", "Interrupt Controller System Register Enable register (EL2)" ),
        ( 0b011, 0b110, "c12", "c12", 0b101 ) : ( "ICC_SRE_EL3", "Interrupt Controller System Register Enable register (EL3)" ),
        ( 0b011, 0b100, "c12", "c8", 0b000 )  : ( "ICH_AP0R0_EL2", "Interrupt Controller Hyp Active Priorities Group 0 Register 0" ),
        ( 0b011, 0b100, "c12", "c8", 0b001 )  : ( "ICH_AP0R1_EL2", "Interrupt Controller Hyp Active Priorities Group 0 Register 1" ),
        ( 0b011, 0b100, "c12", "c8", 0b010 )  : ( "ICH_AP0R2_EL2", "Interrupt Controller Hyp Active Priorities Group 0 Register 2" ),
        ( 0b011, 0b100, "c12", "c8", 0b011 )  : ( "ICH_AP0R3_EL2", "Interrupt Controller Hyp Active Priorities Group 0 Register 3" ),
        ( 0b011, 0b100, "c12", "c9", 0b000 )  : ( "ICH_AP1R0_EL2", "Interrupt Controller Hyp Active Priorities Group 1 Register 0" ),
        ( 0b011, 0b100, "c12", "c9", 0b001 )  : ( "ICH_AP1R1_EL2", "Interrupt Controller Hyp Active Priorities Group 1 Register 1" ),
        ( 0b011, 0b100, "c12", "c9", 0b010 )  : ( "ICH_AP1R2_EL2", "Interrupt Controller Hyp Active Priorities Group 1 Register 2" ),
        ( 0b011, 0b100, "c12", "c9", 0b011 )  : ( "ICH_AP1R3_EL2", "Interrupt Controller Hyp Active Priorities Group 1 Register 3" ),
        ( 0b011, 0b100, "c12", "c11", 0b011 ) : ( "ICH_EISR_EL2", "Interrupt Controller End of Interrupt Status Register" ),
        ( 0b011, 0b100, "c12", "c11", 0b101 ) : ( "ICH_ELSR_EL2", "Interrupt Controller Empty List Register Status Register" ), # Named ICH_ELRSR_EL2 in 8.2 specifications.
        ( 0b011, 0b100, "c12", "c11", 0b000 ) : ( "ICH_HCR_EL2", "Interrupt Controller Hyp Control Register" ),
        ( 0b011, 0b100, "c12", "c12", 0b000 ) : ( "ICH_LR0_EL2", "Interrupt Controller List Register 0" ),
        ( 0b011, 0b100, "c12", "c12", 0b001 ) : ( "ICH_LR1_EL2", "Interrupt Controller List Register 1" ),
        ( 0b011, 0b100, "c12", "c12", 0b010 ) : ( "ICH_LR2_EL2", "Interrupt Controller List Register 2" ),
        ( 0b011, 0b100, "c12", "c12", 0b011 ) : ( "ICH_LR3_EL2", "Interrupt Controller List Register 3" ),
        ( 0b011, 0b100, "c12", "c12", 0b100 ) : ( "ICH_LR4_EL2", "Interrupt Controller List Register 4" ),
        ( 0b011, 0b100, "c12", "c12", 0b101 ) : ( "ICH_LR5_EL2", "Interrupt Controller List Register 5" ),
        ( 0b011, 0b100, "c12", "c12", 0b110 ) : ( "ICH_LR6_EL2", "Interrupt Controller List Register 6" ),
        ( 0b011, 0b100, "c12", "c12", 0b111 ) : ( "ICH_LR7_EL2", "Interrupt Controller List Register 7" ),
        ( 0b011, 0b100, "c12", "c13", 0b000 ) : ( "ICH_LR8_EL2", "Interrupt Controller List Register 8" ),
        ( 0b011, 0b100, "c12", "c13", 0b001 ) : ( "ICH_LR9_EL2", "Interrupt Controller List Register 9" ),
        ( 0b011, 0b100, "c12", "c13", 0b010 ) : ( "ICH_LR10_EL2", "Interrupt Controller List Register 10" ),
        ( 0b011, 0b100, "c12", "c13", 0b011 ) : ( "ICH_LR11_EL2", "Interrupt Controller List Register 11" ),
        ( 0b011, 0b100, "c12", "c13", 0b100 ) : ( "ICH_LR12_EL2", "Interrupt Controller List Register 12" ),
        ( 0b011, 0b100, "c12", "c13", 0b101 ) : ( "ICH_LR13_EL2", "Interrupt Controller List Register 13" ),
        ( 0b011, 0b100, "c12", "c13", 0b110 ) : ( "ICH_LR14_EL2", "Interrupt Controller List Register 14" ),
        ( 0b011, 0b100, "c12", "c13", 0b111 ) : ( "ICH_LR15_EL2", "Interrupt Controller List Register 15" ),
        ( 0b011, 0b100, "c12", "c11", 0b010 ) : ( "ICH_MISR_EL2", "Interrupt Controller Maintenance Interrupt State Register" ),
        ( 0b011, 0b100, "c12", "c11", 0b111 ) : ( "ICH_VMCR_EL2", "Interrupt Controller Virtual Machine Control Register" ),
        ( 0b011, 0b100, "c12", "c9", 0b100 )  : ( "ICH_VSEIR_EL2", "Interrupt Controller Virtual System Error Interrupt Register" ), # Not defined in 8.2 specifications.
        ( 0b011, 0b100, "c12", "c11", 0b001 ) : ( "ICH_VTR_EL2", "Interrupt Controller VGIC Type Register" ),
}

# Aarch32 fields.
COPROC_FIELDS = {
        "FPSCR" : {
            0 : ( "IOC", "Invalid Operation exception" ),
            1 : ( "DZC", "Division by Zero exception" ),
            2 : ( "OFC", "Overflow exception" ),
            3 : ( "UFC", "Underflow exception" ),
            4 : ( "IXC", "Inexact exception" ),
            7 : ( "IDC", "Input Denormal exception" ),
            19 : ( "FZ16", "Flush-to-zero mode on half-precision instructions" ),
            # 22-23: RMode
            24 : ( "FZ", "Flush-to-zero mode" ),
            25 : ( "DN", "Default NaN mode" ),
            26 : ( "AHP", "Alternative Half-Precision" ),
            27 : ( "QC", "Saturation" ),
            28 : ( "V", "Overflow flag" ),
            29 : ( "C", "Carry flag" ),
            30 : ( "Z", "Zero flag" ),
            31 : ( "N", "Negative flag" )
        },
        "HCR" : {
            0 : ( "VM", "Virtualization MMU enable" ),
            1 : ( "SWIO", "Set/Way Invalidation Override" ),
            2 : ( "PTW", "Protected Table Walk" ),
            3 : ( "FMO", "FIQ Mask Override" ),
            4 : ( "IMO", "IRQ Mask Override" ),
            5 : ( "AMO", "Asynchronous Abort Mask Override" ),
            6 : ( "VE", "Virtual FIQ exception" ),
            7 : ( "VI", "Virtual IRQ exception" ),
            8 : ( "VA", "Virtual Asynchronous Abort exception" ),
            9 : ( "FB", "Force Broadcast" ),
            10 : ( "BSU_0", "Barrier Shareability Upgrade" ),
            11 : ( "BSU_1", "Barrier Shareability Upgrade" ),
            12 : ( "DC", "Default cacheable" ),
            13 : ( "TWI", "Trap WFI" ),
            14 : ( "TWE", "Trap WFE" ),
            15 : ( "TID0", "Trap ID Group 0" ),
            16 : ( "TID1", "Trap ID Group 1" ),
            17 : ( "TID2", "Trap ID Group 2" ),
            18 : ( "TID3", "Trap ID Group 3" ),
            19 : ( "TSC", "Trap SMC instruction" ),
            20 : ( "TIDCP", "Trap Implementation Dependent functionality" ),
            21 : ( "TAC", "Trap ACTLR accesses" ),
            22 : ( "TSW", "Trap Data/Unified Cache maintenance operations by Set/Way" ),
            23 : ( "TPC", "Trap Data/Unified Cache maintenance operations to Point of Coherency" ),
            24 : ( "TPU", "Trap Cache maintenance instructions to Point of Unification" ),
            25 : ( "TTLB", "Trap TLB maintenance instructions" ),
            26 : ( "TVM", "Trap Virtual Memory controls" ),
            27 : ( "TGE", "Trap General Exceptions" ),
            29 : ( "HCD", "Hypervisor Call Disable" ),
            30 : ( "TRVM", "Trap Read of Virtual Memory controls" )
        },
        "HCR2" : {
            0 : ( "CD", "Stage 2 Data cache disable" ),
            1 : ( "ID", "Stage 2 Instruction cache disable" ),
            4 : ( "TERR", "Trap Error record accesses" ),
            5 : ( "TEA", "Route synchronous External Abort exceptions to EL2" ),
            6 : ( "MIOCNCE", "Mismatched Inner/Outer Cacheable Non-Coherency Enable" )
        },
        "SCR" : {
            0 : ( "NS", "Non-secure" ),
            1 : ( "IRQ", "IRQ handler" ),
            2 : ( "FIQ", "FIQ handler" ),
            3 : ( "EA", "External Abort handler" ),
            4 : ( "FW", "Can mask Non-secure FIQ" ),
            5 : ( "AW", "Can mask Non-secure external aborts" ),
            6 : ( "nET", "Not Early Termination" ),
            7 : ( "SCD", "Secure Monitor Call disable" ),
            8 : ( "HCE", "Hypervisor Call instruction enable" ),
            9 : ( "SIF", "Secure instruction fetch" ),
            12 : ( "TWI", "Traps WFI instructions to Monitor mode" ),
            13 : ( "TWE", "Traps WFE instructions to Monitor mode" ),
            15 : ( "TERR", "Trap Error record accesses" )
        },
        "SCTLR" : {
            0 : ( "M", "MMU Enable" ),
            1 : ( "A", "Alignment" ),
            2 : ( "C", "Cache Enable" ),
            3 : ( "nTLSMD", "No Trap Load Multiple and Store Multiple to Device-nGRE/Device-nGnRE/Device-nGnRnE memory" ),
            4 : ( "LSMAOE", "Load Multiple and Store Multiple Atomicity and Ordering Enable" ),
            5 : ( "CP15BEN", "System instruction memory barrier enable" ),
            7 : ( "ITD", "IT Disable" ),
            8 : ( "SETEND", "SETEND instruction disable" ),
            10 : ( "SW", "SWP/SWPB Enable" ),
            11 : ( "Z", "Branch Prediction Enable" ),
            12 : ( "I", "Instruction cache Enable" ),
            13 : ( "V", "High exception vectors" ),
            14 : ( "RR", "Round-robin cache" ),
            16 : ( "nTWI", "Traps EL0 execution of WFI instructions to Undefined mode" ),
            17 : ( "HA", "Hardware Access Enable" ),
            18 : ( "nTWE", "Traps EL0 execution of WFE instructions to Undefined mode" ),
            19 : ( "WXN", "Write permission implies XN" ),
            20 : ( "UWXN", "Unprivileged write permission implies PL1 XN" ),
            21 : ( "FI", "Fast Interrupts configuration" ),
            23 : ( "SPAN", "Set Privileged Access Never" ),
            24 : ( "VE", "Interrupt Vectors Enable" ),
            25 : ( "EE", "Exception Endianness" ),
            27 : ( "NMFI", "Non-maskable Fast Interrupts" ),
            28 : ( "TRE", "TEX Remap Enable" ),
            29 : ( "AFE", "Access Flag Enable" ),
            30 : ( "TE", "Thumb Exception Enable" )
        },
        "HSCTLR" : {
            0 : ( "M", "MMU Enable" ),
            1 : ( "A", "Alignment" ),
            2 : ( "C", "Cache Enable" ),
            3 : ( "SA", "Stack alignment check" ),
            12 : ( "I", "Instruction cache Enable" ),
            19 : ( "WXN", "Write permission implies XN" ),
            25 : ( "EE", "Exception Endianness" ),
            30 : ( "TE", "Thumb Exception Enable" )
        },
        "NSACR" : {
            10 : ( "CP10", "CP10 access in the NS state" ),
            11 : ( "CP11", "CP11 access in the NS state" ),
            14 : ( "NSD32DIS", "Disable the NS use of D16-D31 of the VFP register file" ),
            15 : ( "NSASEDIS", "Disable NS Advanced SIMD Extension functionality" ),
            16 : ( "PLE", "NS access to the Preload Engine resources" ),
            17 : ( "TL", "Lockable TLB entries can be allocated in NS state" ),
            18 : ( "NS_SMP", "SMP bit of the Auxiliary Control Register is writable in NS state" ),
        },
}

# Aarch64 fields.
SYSREG_FIELDS = {
        "DAIF" : {
            6 : ( "F", "FIQ mask" ),
            7 : ( "I", "IRQ mask" ),
            8 : ( "A", "SError interrupt mask" ),
            9 : ( "D", "Process state D mask" )
        },
        "FPCR" : {
            8 : ( "IOE", "Invalid Operation exception trap enable" ),
            9 : ( "DZE", "Division by Zero exception trap enable" ),
            10 : ( "OFE", "Overflow exception trap enable" ),
            11 : ( "UFE", "Underflow exception trap enable" ),
            12 : ( "IXE", "Inexact exception trap enable" ),
            15 : ( "IDE", "Input Denormal exception trap enable" ),
            19 : ( "FZ16", "Flush-to-zero mode on half-precision instructions" ),
            # 22-23 : RMode
            24 : ( "FZ", "Flush-to-zero-mode" ),
            25 : ( "DN", "Default NaN mode" ),
            26 : ( "AHP", "Alternative Half-Precision" )
        },
        "FPSR" : {
            0 : ( "IOC", "Invalid Operation exception" ),
            1 : ( "DZC", "Division by Zero exception" ),
            2 : ( "OFC", "Overflow exception" ),
            3 : ( "UFC", "Underflow exception" ),
            4 : ( "IXC", "Inexact exception" ),
            7 : ( "IDC", "Input Denormal exception" ),
            27 : ( "QC", "Saturation" ),
            28 : ( "V", "Overflow flag" ),
            29 : ( "C", "Carry flag" ),
            30 : ( "Z", "Zero flag" ),
            31 : ( "N", "Negative flag" )
        },
        "HCR_EL2" : {
            0 : ( "VM", "Virtualization MMU enable" ),
            1 : ( "SWIO", "Set/Way Invalidation Override" ),
            2 : ( "PTW", "Protected Table Walk" ),
            3 : ( "FMO", "FIQ Mask Override" ),
            4 : ( "IMO", "IRQ Mask Override" ),
            5 : ( "AMO", "Asynchronous Abort Mask Override" ),
            6 : ( "VE", "Virtual FIQ exception" ),
            7 : ( "VI", "Virtual IRQ exception" ),
            8 : ( "VA", "Virtual Asynchronous Abort exception" ),
            9 : ( "FB", "Force Broadcast" ),
            10 : ( "BSU_0", "Barrier Shareability Upgrade" ),
            11 : ( "BSU_1", "Barrier Shareability Upgrade" ),
            12 : ( "DC", "Default cacheable" ),
            13 : ( "TWI", "Trap WFI" ),
            14 : ( "TWE", "Trap WFE" ),
            15 : ( "TID0", "Trap ID Group 0" ),
            16 : ( "TID1", "Trap ID Group 1" ),
            17 : ( "TID2", "Trap ID Group 2" ),
            18 : ( "TID3", "Trap ID Group 3" ),
            19 : ( "TSC", "Trap SMC instruction" ),
            20 : ( "TIDCP", "Trap Implementation Dependent functionality" ),
            21 : ( "TAC", "Trap ACTLR accesses" ),
            22 : ( "TSW", "Trap Data/Unified Cache maintenance operations by Set/Way" ),
            23 : ( "TPC", "Trap Data/Unified Cache maintenance operations to Point of Coherency" ),
            24 : ( "TPU", "Trap Cache maintenance instructions to Point of Unification" ),
            25 : ( "TTLB", "Trap TLB maintenance instructions" ),
            26 : ( "TVM", "Trap Virtual Memory controls" ),
            27 : ( "TGE", "Trap General Exceptions" ),
            29 : ( "HCD", "Hypervisor Call Disable" ),
            30 : ( "TRVM", "Trap Read of Virtual Memory controls" ),
            31 : ( "RW", "Lower level is AArch64" ),
            32 : ( "CD", "Stage 2 Data cache disable" ),
            33 : ( "ID", "Stage 2 Instruction cache disable" ),
            34 : ( "E2H", "EL2 Host" ),
            35 : ( "TLOR", "Trap LOR registers" ),
            36 : ( "TERR", "Trap Error record accesses" ),
            37 : ( "TEA", "Route synchronous External Abort exceptions to EL2" ),
            38 : ( "MIOCNCE", "Mismatched Inner/Outer Cacheable Non-Coherency Enable" )
        },
        "SCR_EL3" : {
            0 : ( "NS", "Non-secure" ),
            1 : ( "IRQ", "IRQ handler" ),
            2 : ( "FIQ", "FIQ handler" ),
            3 : ( "EA", "External Abort handler" ),
            7 : ( "SMD", "Secure Monitor Call disable" ),
            8 : ( "HCE", "Hypervisor Call instruction enable" ),
            9 : ( "SIF", "Secure instruction fetch" ),
            10 : ( "RW", "Lower level is AArch64" ),
            11 : ( "ST", "Traps Secure EL1 accesses to the Counter-timer Physical Secure timer registers to EL3, from AArch64 state only." ),
            12 : ( "TWI", "Traps WFI instructions to Monitor mode" ),
            13 : ( "TWE", "Traps WFE instructions to Monitor mode" ),
            14 : ( "TLOR", "Traps LOR registers" ),
            15 : ( "TERR", "Trap Error record accesses" )
        },
        "SCTLR_EL1" : {
            0 : ( "M", "MMU Enable" ),
            1 : ( "A", "Alignment" ),
            2 : ( "C", "Cache Enable" ),
            3 : ( "SA", "Stack alignment check" ),
            4 : ( "SA0", "Stack alignment check for EL0" ),
            5 : ( "CP15BEN", "System instruction memory barrier enable" ),
            6 : ( "THEE", "T32EE enable" ),
            7 : ( "ITD", "IT Disable" ),
            8 : ( "SED", "SETEND instruction disable" ),
            9 : ( "UMA", "User Mask Access" ),
            12 : ( "I", "Instruction cache Enable" ),
            14 : ( "DZE", "Access to DC ZVA instruction at EL0" ),
            15 : ( "UCT", "Access to CTR_EL0 to EL0" ),
            16 : ( "nTWI", "Traps EL0 execution of WFI instructions to Undefined mode" ),
            18 : ( "nTWE", "Traps EL0 execution of WFE instructions to Undefined mode" ),
            19 : ( "WXN", "Write permission implies XN" ),
            24 : ( "E0E", "Endianess of explicit data accesses at EL0" ),
            25 : ( "EE", "Exception Endianness" ),
            26 : ( "UCI", "Enable EL0 access to DC CVAU, DC CIVAC, DC CVAC and DC IVAU instructions" ),
        },
        "SCTLR_EL2" : {
            0 : ( "M", "MMU Enable" ),
            1 : ( "A", "Alignment" ),
            2 : ( "C", "Cache Enable" ),
            3 : ( "SA", "Stack alignment check" ),
            12 : ( "I", "Instruction cache Enable" ),
            19 : ( "WXN", "Write permission implies XN" ),
            25 : ( "EE", "Exception Endianness" ),
        },
        "SCTLR_EL3" : {
            0 : ( "M", "MMU Enable" ),
            1 : ( "A", "Alignment" ),
            2 : ( "C", "Cache Enable" ),
            3 : ( "SA", "Stack alignment check" ),
            12 : ( "I", "Instruction cache Enable" ),
            19 : ( "WXN", "Write permission implies XN" ),
            25 : ( "EE", "Exception Endianness" ),
        },
}

ARM_MODES = {
        0b10000 : "User",
        0b10001 : "FIQ",
        0b10010 : "IRQ",
        0b10011 : "Supervisor",
        0b10110 : "Monitor",
        0b10111 : "Abort",
        0b11011 : "Undefined",
        0b11111 : "System"
}

PSTATE_OPS = {
        0b101   : "SPSel",
        0b110   : "DAIFSet",
        0b111   : "DAIFClr"
}

def extract_bits(bitmap, value):
    return [ bitmap[b] for b in bitmap if value & (1 << b) ]

def is_system_insn(ea):
    mnem = print_insn_mnem(ea)
    if len(mnem) > 0:
        if mnem in SYSTEM_INSN:
            return True
        if mnem[0:3] == "LDM" and print_operand(ea, 1)[-1:] == "^":
            return True
        if mnem[0:4] in ("SUBS", "MOVS") and print_operand(ea, 0) == "PC" and print_operand(ea, 1) == "LR":
            return True
    return False

def backtrack_fields(ea, reg, fields):
    while True:
        ea -= get_item_size(ea)
        prev_mnem = print_insn_mnem(ea)[0:3]
        if prev_mnem in ("LDR", "MOV", "ORR", "BIC") and print_operand(ea, 0) == reg:
            if prev_mnem == "LDR" and print_operand(ea, 1)[0] == "=":
                bits = extract_bits(fields, get_wide_dword(get_operand_value(ea, 1)))
                set_cmt(ea, "Set bits %s" % ", ".join([abbrev for (abbrev,name) in bits]), 0)
                break
            elif prev_mnem == "MOV" and print_operand(ea, 1)[0] == "#":
                bits = extract_bits(fields, get_operand_value(ea, 1))
                set_cmt(ea, "Set bits %s" % ", ".join([abbrev for (abbrev,name) in bits]), 0)
                break
            elif prev_mnem == "ORR"  and print_operand(ea, 2)[0] == "#":
                bits = extract_bits(fields, get_operand_value(ea, 2))
                set_cmt(ea, "Set bit %s" % ", ".join([name for (abbrev,name) in bits]), 0)
            elif prev_mnem == "BIC"  and print_operand(ea, 2)[0] == "#":
                bits = extract_bits(fields, get_operand_value(ea, 2))
                set_cmt(ea, "Clear bit %s" % ", ".join([name for (abbrev,name) in bits]), 0)
            else:
                break
        else:
            break

def track_fields(ea, reg, fields):
    while True:
        ea += get_item_size(ea)
        next_mnem = print_insn_mnem(ea)[0:3]
        if next_mnem in ("TST", "TEQ") and print_operand(ea, 0) == reg and print_operand(ea, 1)[0] == "#":
            bits = extract_bits(fields, get_operand_value(ea, 1))
            set_cmt(ea, "Test bit %s" % ", ".join([name for (abbrev,name) in bits]), 0)
        elif next_mnem == "AND" and print_operand(ea, 1) == reg and print_operand(ea, 2)[0] == "#":
            bits = extract_bits(fields, get_operand_value(ea, 2))
            set_cmt(ea, "Test bit %s" % ", ".join([name for (abbrev,name) in bits]), 0)
        elif next_mnem == "LSL" and GetDisasm(ea)[3] == "S" and print_operand(ea, 1) == reg and print_operand(ea, 2)[0] == "#":
            bits = extract_bits(fields, 1 << (31 - get_operand_value(ea, 2)))
            set_cmt(ea, "Test bit %s" % ", ".join([name for (abbrev,name) in bits]), 0)
        else:
            break

def identify_register(ea, access, sig, known_regs, cpu_reg = None, known_fields = {}):
    desc = known_regs.get(sig, None)
    if desc:
        cmt = ("[%s] " + "\n or ".join(["%s (%s)"] * (len(desc) / 2))) % ((access,) + desc)
        set_cmt(ea, cmt, 0)
        print(cmt)

        # Try to resolve fields during a write operation.
        fields = known_fields.get(desc[0], None)
        if fields and len(desc) == 2:
            if access == '>':
                backtrack_fields(ea, cpu_reg, fields)
            else:
                track_fields(ea, cpu_reg, fields)
    else:
        print("Cannot identify system register.")
        set_cmt(ea, "[%s] Unknown system register." % access, 0)

def markup_coproc_reg64_insn(ea):
    if print_insn_mnem(ea)[1] == "R":
        access = '<'
    else:
        access = '>'
    op1 = get_operand_value(ea, 0)
    cp = "p%d" % DecodeInstruction(ea).Op1.specflag1
    reg1, reg2, crm = print_operand(ea, 1).split(',')

    sig = ( cp, op1, crm )
    identify_register(ea, access, sig, COPROC_REGISTERS_64)

def markup_coproc_insn(ea):
    if print_insn_mnem(ea)[1] == "R":
        access = '<'
    else:
        access = '>'
    op1, op2 = get_operand_value(ea, 0), get_operand_value(ea, 2)
    reg, crn, crm = print_operand(ea, 1).split(',')
    cp = "p%d" % DecodeInstruction(ea).Op1.specflag1

    sig = ( cp, crn, op1, crm, op2 )
    identify_register(ea, access, sig, COPROC_REGISTERS, reg, COPROC_FIELDS)

def markup_aarch64_sys_insn(ea):
    if print_insn_mnem(ea)[1] == "R":
        reg_pos = 0
        access = '<'
    else:
        reg_pos = 4
        access = '>'
    base_args = (reg_pos + 1) % 5
    op0 = 2 + ((get_wide_dword(ea) >> 19) & 1)
    op1, op2 = get_operand_value(ea, base_args), get_operand_value(ea, base_args + 3)
    crn, crm = print_operand(ea, base_args + 1), print_operand(ea, base_args + 2)
    reg = print_operand(ea, reg_pos)

    sig = ( op0, op1, crn, crm, op2 )
    identify_register(ea, access, sig, SYSTEM_REGISTERS, reg, SYSREG_FIELDS)

def markup_psr_insn(ea):
    if print_operand(ea,1)[0] == "#": # immediate
        psr = get_operand_value(ea, 1)
        mode = ARM_MODES.get(psr & 0b11111, "Unknown")
        e = (psr & (1 << 9)) and 'E' or '-'
        a = (psr & (1 << 8)) and 'A' or '-'
        i = (psr & (1 << 7)) and 'I' or '-'
        f = (psr & (1 << 6)) and 'F' or '-'
        t = (psr & (1 << 5)) and 'T' or '-'
        set_cmt(ea, "Set CPSR [%c%c%c%c%c], Mode: %s" % (e,a,i,f,t,mode), 0)

def markup_pstate_insn(ea):
    if print_operand(ea,0)[0] == "#" and print_operand(ea,1)[0] == "#":
        op = PSTATE_OPS.get(get_operand_value(ea, 0), "Unknown")
        value = get_operand_value(ea, 1)
        if op == "SPSel":
            set_cmt(ea, "Select PSTATE.SP = SP_EL%c" % ('0', 'x')[value & 1], 0)
        elif op[0:4] == "DAIF":
            d = (value & (1 << 3)) and 'D' or '-'
            a = (value & (1 << 2)) and 'A' or '-'
            i = (value & (1 << 1)) and 'I' or '-'
            f = (value & (1 << 0)) and 'F' or '-'
            set_cmt(ea, "%s PSTATE.DAIF [%c%c%c%c]" % (op[4:7], d,a,i,f), 0)

def markup_system_insn(ea):
    mnem = print_insn_mnem(ea)
    if mnem[0:4] in ("MRRC", "MCRR"):
        markup_coproc_reg64_insn(ea)
    elif mnem[0:3] in ("MRC", "MCR"):
        markup_coproc_insn(ea)
    elif current_arch == 'aarch32' and mnem[0:3] == "MSR":
        markup_psr_insn(ea)
    elif current_arch == 'aarch64' and mnem[0:3] == "MSR" and not print_operand(ea, 2):
        markup_pstate_insn(ea)
    elif current_arch == 'aarch64' and mnem[0:3] in ("MSR", "MRS"):
        markup_aarch64_sys_insn(ea)
    set_color(ea, CIC_ITEM, 0x00000000) # Black background, adjust to your own theme

def current_arch_size():
    _, t, _ = parse_decl("void *", 0)
    return SizeOf(t) * 8

def run_script():
    for addr in Heads():
        if is_system_insn(addr):
            print("Found system instruction %s at %08x" % ( print_insn_mnem(addr), addr ))
            markup_system_insn(addr)

#
# Check we are running this script on an ARM architecture.
#
if get_inf_attr(INF_PROCNAME) in ('ARM', 'ARMB'):
    current_arch = 'aarch64' if current_arch_size() == 64 else 'aarch32'
    run_script()
else:
    Warning("This script can only work with ARM and AArch64 architectures.")
