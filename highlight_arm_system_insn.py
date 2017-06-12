# -*- coding: utf-8 -*-
#
# Script to highlight low-level instructions in ARM code.
# Automatically comment coprocessor accesses (MRC*/MCR*) with documentation.
#
# Support up to ARMv7-A / ARMv8 processors.
#
# Author: Guillaume Delugré.
#

from idautils import *
from idc import *

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
)

# 64 bits registers accessible from AArch32.
# Extracted from the 00bet3.2 XML specifications for ARMv8.2.
COPROC_REGISTERS_64 = {
        # MMU registers
        ( "p15", 0, "c2"  )         : ( "TTBR0", "Translation Table Base Register 0" ),
        ( "p15", 1, "c2"  )         : ( "TTBR1", "Translation Table Base Register 1" ),
        ( "p15", 6, "c2"  )         : ( "VTTBR", "Virtualization Translation Table Base Register" ),
        ( "p15", 4, "c2"  )         : ( "HTTBR", "Hyp Translation Table Base Register" ),
        ( "p15", 0, "c7"  )         : ( "PAR", "Physical Address Register" ),

        # Counters
        ( "p15", 0, "c9"  )         : ( "PMCCNTR", "Performance Monitors Cycle Count Register" ),
        ( "p15", 0, "c14" )         : ( "CNTPCT", "Counter-timer Physical Count register" ),
        ( "p15", 1, "c14" )         : ( "CNTVCT", "Counter-timer Virtual Count register" ),
        ( "p15", 2, "c14" )         : ( "CNTP_CVAL", "Counter-timer Physical Timer CompareValue register",
                                        "CNTHP_CVAL", "Counter-timer Hyp Physical CompareValue register" ),
        ( "p15", 3, "c14" )         : ( "CNTV_CVAL", "Counter-timer Virtual Timer CompareValue register", 
                                        "CNTHV_CVAL", "Counter-timer Virtual Timer CompareValue register (EL2)" ),
        ( "p15", 4, "c14" )         : ( "CNTVOFF", "Counter-timer Virtual Offset register" ),
        ( "p15", 6, "c14" )         : ( "CNTHP_CVAL", "Counter-timer Hyp Physical CompareValue register" ),

        # Interrupts
        ( "p15", 0, "c12" )         : ( "ICC_SGI1R", "Interrupt Controller Software Generated Interrupt Group 1 Register" ),
        ( "p15", 1, "c12" )         : ( "ICC_ASGI1R", "Interrupt Controller Alias Software Generated Interrupt Group 1 Register" ),
        ( "p15", 2, "c12" )         : ( "ICC_SGI0R", "Interrupt Controller Software Generated Interrupt Group 0 Register" ),

        # Debug registers
        ( "p14", 0, "c1"  )         : ( "DBGDRAR", "Debug ROM Address Register" ),
        ( "p14", 0, "c2"  )         : ( "DBGDSAR", "Debug Self Address Register" ),
}

# Taken from the Cortex-A15 manual.
COPROC_REGISTERS = {
        ( "p15", "c0", 0, "c0", 0 ) : ( "MIDR", "Main ID Register" ),
        ( "p15", "c0", 0, "c0", 1 ) : ( "CTR", "Cache Type Register" ),
        ( "p15", "c0", 0, "c0", 2 ) : ( "TCMTR", "TCM Type Register" ),
        ( "p15", "c0", 0, "c0", 3 ) : ( "TLBTR", "TLB Type Register" ),
        ( "p15", "c0", 0, "c0", 5 ) : ( "MPIDR", "Multiprocessor Affinity Register" ),
        ( "p15", "c0", 0, "c0", 6 ) : ( "REVIDR", "Revision ID Register" ),

        # Aliases
        ( "p15", "c0", 0, "c0", 4 ) : ( "MIDR", "Main ID Register" ),
        ( "p15", "c0", 0, "c0", 7 ) : ( "MIDR", "Main ID Register" ),

        # CPUID registers
        ( "p15", "c0", 0, "c1", 0 ) : ( "ID_PFR0", "Processor Feature Register 0" ),
        ( "p15", "c0", 0, "c1", 1 ) : ( "ID_PFR1", "Processor Feature Register 1" ),
        ( "p15", "c0", 0, "c1", 2 ) : ( "ID_DFR0", "Debug Feature Register 0" ),
        ( "p15", "c0", 0, "c1", 3 ) : ( "ID_AFR0", "Auxiliary Feature Register 0" ),
        ( "p15", "c0", 0, "c1", 4 ) : ( "ID_MMFR0", "Memory Model Feature Register 0" ),
        ( "p15", "c0", 0, "c1", 5 ) : ( "ID_MMFR1", "Memory Model Feature Register 1" ),
        ( "p15", "c0", 0, "c1", 6 ) : ( "ID_MMFR2", "Memory Model Feature Register 2" ),
        ( "p15", "c0", 0, "c1", 7 ) : ( "ID_MMFR3", "Memory Model Feature Register 3" ),
        ( "p15", "c0", 0, "c2", 0 ) : ( "ID_ISAR0", "ISA Feature Register 0" ),
        ( "p15", "c0", 0, "c2", 1 ) : ( "ID_ISAR1", "ISA Feature Register 1" ),
        ( "p15", "c0", 0, "c2", 2 ) : ( "ID_ISAR2", "ISA Feature Register 2" ),
        ( "p15", "c0", 0, "c2", 3 ) : ( "ID_ISAR3", "ISA Feature Register 3" ),
        ( "p15", "c0", 0, "c2", 4 ) : ( "ID_ISAR4", "ISA Feature Register 4" ),
        ( "p15", "c0", 0, "c2", 5 ) : ( "ID_ISAR5", "ISA Feature Register 5" ),

        ( "p15", "c0", 1, "c0", 0 ) : ( "CCSIDR", "Current Cache Size ID Register" ),
        ( "p15", "c0", 1, "c0", 1 ) : ( "CLIDR", "Cache Level ID Register" ),
        ( "p15", "c0", 1, "c0", 7 ) : ( "AIDR", "Auxiliary ID Register" ),
        ( "p15", "c0", 2, "c0", 0 ) : ( "CCSELR", "Cache Size Selection Register" ),
        ( "p15", "c0", 4, "c0", 0 ) : ( "VPIDR", "Virtualization Processor ID Register" ),
        ( "p15", "c0", 4, "c0", 5 ) : ( "VMPIDR", "Virtualization Multiprocessor ID Register" ),

        # System control registers
        ( "p15", "c1", 0, "c0", 0 ) : ( "SCTLR", "System Control Register" ),
        ( "p15", "c1", 0, "c0", 1 ) : ( "ACTLR", "Auxiliary Control Register" ),
        ( "p15", "c1", 0, "c0", 2 ) : ( "CPACR", "Coprocessor Access Control Register" ),
        ( "p15", "c1", 0, "c1", 0 ) : ( "SCR", "Secure Configuration Register" ),
        ( "p15", "c1", 0, "c1", 1 ) : ( "SDER", "Secure Debug Enable Register" ),
        ( "p15", "c1", 0, "c1", 2 ) : ( "NSACR", "Non-secure Access Control Register" ),
        ( "p15", "c1", 4, "c0", 0 ) : ( "HSCTLR", "Hyp System Control Register" ),
        ( "p15", "c1", 4, "c0", 1 ) : ( "HACTLR", "Hyp Auxiliary Control Register" ),
        ( "p15", "c1", 4, "c1", 0 ) : ( "HCR", "Hyp Configuration Register" ),
        ( "p15", "c1", 4, "c1", 1 ) : ( "HDCR", "Hyp Debug Configuration Register" ),
        ( "p15", "c1", 4, "c1", 2 ) : ( "HCPTR", "Hyp Coprocessor Trap Register" ),
        ( "p15", "c1", 4, "c1", 3 ) : ( "HSTR", "Hyp System Trap Register" ),
        ( "p15", "c1", 4, "c1", 7 ) : ( "HACR", "Hyp Auxialiary Configuration Register" ),

        # Translation Table Base Registers
        ( "p15", "c2", 0, "c0", 0 ) : ( "TTBR0", "Translation Table Base Register 0" ),
        ( "p15", "c2", 0, "c0", 1 ) : ( "TTBR1", "Translation Table Base Register 1" ),
        ( "p15", "c2", 4, "c0", 2 ) : ( "HTCR", "Hyp Translation Control Register" ),
        ( "p15", "c2", 4, "c1", 2 ) : ( "VTCR", "Virtualization Translation Control Register" ),

        # Domain Access Control registers
        ( "p15", "c3", 0, "c0", 0 ) : ( "DACR", "Domain Access Control Register" ),

        # Fault Status registers
        ( "p15", "c5", 0, "c0", 0 ) : ( "DFSR", "Data Fault Status Register" ),
        ( "p15", "c5", 0, "c0", 1 ) : ( "IFSR", "Instruction Fault Status Register" ),
        ( "p15", "c5", 0, "c1", 0 ) : ( "ADFSR", "Auxiliary Data Fault Status Register" ),
        ( "p15", "c5", 0, "c1", 0 ) : ( "AIFSR", "Auxiliary Instruction Fault Status Register" ),
        ( "p15", "c5", 4, "c1", 0 ) : ( "HADFSR", "Hyp Auxiliary Data Fault Syndrome Register" ),
        ( "p15", "c5", 4, "c1", 1 ) : ( "HAIFSR", "Hyp Auxiliary Instruction Fault Syndrome Register" ),
        ( "p15", "c5", 4, "c2", 0 ) : ( "HSR", "Hyp Syndrome Register" ),

        # Fault Address registers
        ( "p15", "c6", 0, "c0", 0 ) : ( "DFAR", "Data Fault Address Register" ),
        ( "p15", "c6", 0, "c0", 1 ) : ( "N/A", "Watchpoint Fault Address" ), # ARM11
        ( "p15", "c6", 0, "c0", 2 ) : ( "IFAR", "Instruction Fault Address Register" ),
        ( "p15", "c6", 4, "c0", 0 ) : ( "HDFAR", "Hyp Data Fault Address Register" ),
        ( "p15", "c6", 4, "c0", 2 ) : ( "HIFAR", "Hyp Instruction Fault Address Register" ),
        ( "p15", "c6", 4, "c0", 4 ) : ( "HPFAR", "Hyp IPA Fault Address Register" ),

        # Cache maintenance registers
        ( "p15", "c7", 0, "c0", 4 ) : ( "NOP", "No Operation / Wait For Interrupt" ),
        ( "p15", "c7", 0, "c1", 0 ) : ( "ICIALLUIS", "Invalidate all instruction caches to PoU Inner Shareable" ),
        ( "p15", "c7", 0, "c1", 6 ) : ( "BPIALLIS", "Invalidate all branch predictors Inner Shareable" ),
        ( "p15", "c7", 0, "c4", 0 ) : ( "PAR", "Physical Address Register" ),
        ( "p15", "c7", 0, "c5", 0 ) : ( "ICIALLU", "Invalidate all instruction caches to PoU" ),
        ( "p15", "c7", 0, "c5", 1 ) : ( "ICIMVAU", "Invalidate all instruction caches by MVA to PoU" ),
        ( "p15", "c7", 0, "c5", 2 ) : ( "N/A", "Invalidate all instruction caches by set/way" ), # ARM11
        ( "p15", "c7", 0, "c5", 4 ) : ( "CP15ISB", "Instruction Synchronization Barrier operation" ),
        ( "p15", "c7", 0, "c5", 6 ) : ( "BPIALL", "Invalidate all branch predictors" ),
        ( "p15", "c7", 0, "c5", 7 ) : ( "BPIMVA", "Invalidate MVA from branch predictors" ),
        ( "p15", "c7", 0, "c6", 0 ) : ( "N/A", "Invalidate entire data cache" ),
        ( "p15", "c7", 0, "c6", 1 ) : ( "DCIMVAC", "Invalidate data cache line by MVA to PoC" ),
        ( "p15", "c7", 0, "c6", 2 ) : ( "DCISW", "Invalidate data cache line by set/way" ),
        ( "p15", "c7", 0, "c7", 0 ) : ( "N/A", "Invalidate instruction cache and data cache" ), # ARM11
        ( "p15", "c7", 0, "c8", 0 ) : ( "ATS1CPR", "Stage 1 current state PLI read" ),
        ( "p15", "c7", 0, "c8", 1 ) : ( "ATS1CPW", "Stage 1 current state PLI write" ),
        ( "p15", "c7", 0, "c8", 2 ) : ( "ATS1CUR", "Stage 1 current state unprivileged read" ),
        ( "p15", "c7", 0, "c8", 3 ) : ( "ATS1CUW", "Stage 1 current state unprivileged write" ),
        ( "p15", "c7", 0, "c8", 4 ) : ( "ATS12NSOPR", "Stage 1 and 2 Non-secure PLI read" ),
        ( "p15", "c7", 0, "c8", 5 ) : ( "ATS12NSOPW", "Stage 1 and 2 Non-secure PLI write" ),
        ( "p15", "c7", 0, "c8", 6 ) : ( "ATS12NSOUR", "Stage 1 and 2 Non-secure unprivileged read" ),
        ( "p15", "c7", 0, "c8", 7 ) : ( "ATS12NSOUW", "Stage 1 and 2 Non-secure unprivileged write" ),
        ( "p15", "c7", 0, "c10", 0 ): ( "N/A", "Clean entire data cache" ), # ARM11
        ( "p15", "c7", 0, "c10", 1 ): ( "DCCMVAC", "Clean data cache line by MVA to PoC" ),
        ( "p15", "c7", 0, "c10", 2 ): ( "DCCSW", "Clean data cache line by set/way" ),
        ( "p15", "c7", 0, "c10", 3 ): ( "N/A", "Test and clean data cache" ), # ARM9
        ( "p15", "c7", 0, "c10", 4 ): ( "CP15DSB", "Data Synchronization Barrier Operation" ),
        ( "p15", "c7", 0, "c10", 5 ): ( "CP15DMB", "Data Memory Barrier Operation" ),
        ( "p15", "c7", 0, "c10", 6 ): ( "N/A", "Read Cache Dirty Status Register" ), # ARM11
        ( "p15", "c7", 0, "c11", 1 ): ( "DCCMVAU", "Clean data cache line by MVA to PoU" ),
        ( "p15", "c7", 0, "c12", 4 ): ( "N/A", "Read Block Transfer Status Register" ), # ARM11
        ( "p15", "c7", 0, "c12", 5 ): ( "N/A", "Stop Prefetch Range" ), # ARM11
        ( "p15", "c7", 0, "c13", 1 ): ( "NOP", "No Operation / Prefetch Instruction Cache Line" ),
        ( "p15", "c7", 0, "c14", 0 ): ( "N/A", "Clean and invalidate entire data cache" ), # ARM11
        ( "p15", "c7", 0, "c14", 1 ): ( "DCCIMVAC", "Clean and invalidate data cache line by MVA to PoC" ),
        ( "p15", "c7", 0, "c14", 2 ): ( "DCCISW", "Clean and invalidate data cache line by set/way" ),
        ( "p15", "c7", 0, "c14", 3 ): ( "N/A", "Test, clean, and invalidate data cache" ), # ARM9
        ( "p15", "c7", 4, "c8", 0 ) : ( "ATS1HR", "Stage 1 Hyp mode read" ),
        ( "p15", "c7", 4, "c8", 1 ) : ( "ATS1HR", "Stage 1 Hyp mode write" ),

        # TLB maintenance operations
        ( "p15", "c8", 0, "c3", 0 ) : ( "TLBIALLIS", "Invalidate entire TLB Inner Shareable" ),
        ( "p15", "c8", 0, "c3", 1 ) : ( "TLBIMVAIS", "Invalidate unified TLB entry by MVA and ASID Inner Shareable" ),
        ( "p15", "c8", 0, "c3", 2 ) : ( "TLBIASIDIS", "Invalidate unified TLB by ASID match Inner Shareable" ),
        ( "p15", "c8", 0, "c3", 3 ) : ( "TLBIMVAAIS", "Invalidate unified TLB entry by MVA all ASID Inner Shareable" ),
        ( "p15", "c8", 0, "c5", 0 ) : ( "ITLBIALL", "Invalidate instruction TLB" ),
        ( "p15", "c8", 0, "c5", 1 ) : ( "ITLBIMVA", "Invalidate instruction TLB entry by MVA and ASID" ),
        ( "p15", "c8", 0, "c5", 2 ) : ( "ITLBIASID", "Invalidate instruction TLB by ASID match" ),
        ( "p15", "c8", 0, "c6", 0 ) : ( "DTLBIALL", "Invalidate data TLB" ),
        ( "p15", "c8", 0, "c6", 1 ) : ( "DTLBIMVA", "Invalidate data TLB entry by MVA and ASID" ),
        ( "p15", "c8", 0, "c6", 2 ) : ( "DTLBIASID", "Invalidate data TLB by ASID match" ),
        ( "p15", "c8", 0, "c7", 0 ) : ( "TLBIALL", "Invalidate unified TLB" ),
        ( "p15", "c8", 0, "c7", 1 ) : ( "TLBIMVA", "Invalidate unified TLB by MVA and ASID" ),
        ( "p15", "c8", 0, "c7", 2 ) : ( "TLBIASID", "Invalidate unified TLB by ASID match" ),
        ( "p15", "c8", 0, "c7", 3 ) : ( "TLBIMVAA", "Invalidate unified TLB entries by MVA all ASID" ),
        ( "p15", "c8", 4, "c3", 0 ) : ( "TLBIALLHIS", "Invalidate entire Hyp unified TLB Inner Shareable" ),
        ( "p15", "c8", 4, "c3", 1 ) : ( "TLBIMVAHIS", "Invalidate Hyp unified TLB entry by MVA Inner Shareable" ),
        ( "p15", "c8", 4, "c3", 4 ) : ( "TLBIALLNSNHIS", "Invalidate entire Non-secure non-Hyp unified TLB Inner Shareable" ),
        ( "p15", "c8", 4, "c7", 0 ) : ( "TLBIALLH", "Invalidate entire Hyp unified TLB" ),
        ( "p15", "c8", 4, "c7", 1 ) : ( "TLBIMVAH", "Invalidate Hyp unified TLB entry by MVA" ),
        ( "p15", "c8", 4, "c7", 4 ) : ( "TLBIALLNSNH", "Invalidate entire Non-secure non-Hyp unified TLB" ),

        # Performance monitor registers
        ( "p15", "c9", 0, "c0", 0 ) : ( "N/A", "Data Cache Lockdown" ), # ARM11
        ( "p15", "c9", 0, "c0", 1 ) : ( "N/A", "Instruction Cache Lockdown" ), # ARM11
        ( "p15", "c9", 0, "c1", 0 ) : ( "N/A", "Data TCM Region" ), # ARM11
        ( "p15", "c9", 0, "c1", 1 ) : ( "N/A", "Instruction TCM Region" ), # ARM11
        ( "p15", "c9", 0, "c12", 0) : ( "PMCR", "Performance Monitor Control Register" ),
        ( "p15", "c9", 0, "c12", 1) : ( "PMNCNTENSET", "Performance Monitor Count Enable Set Register" ),
        ( "p15", "c9", 0, "c12", 2) : ( "PMNCNTENCLR", "Performance Monitor Control Enable Clear Register" ),
        ( "p15", "c9", 0, "c12", 3) : ( "PMOVSR", "Performance Monitor Overflow Flag Status Register" ),
        ( "p15", "c9", 0, "c12", 4) : ( "PMSWINC", "Performance Monitor Software Increment Register" ),
        ( "p15", "c9", 0, "c12", 5) : ( "PMSELR", "Performance Monitor Event Counter Selection Register" ),
        ( "p15", "c9", 0, "c12", 6) : ( "PMCEID0", "Performance Monitor Common Event Identification Register 0" ),
        ( "p15", "c9", 0, "c12", 7) : ( "PMCEID1", "Performance Monitor Common Event Identification Register 1" ),
        ( "p15", "c9", 0, "c13", 0) : ( "PMCCNTR", "Performance Monitor Cycle Count Register" ),
        ( "p15", "c9", 0, "c13", 1) : ( "PMXEVTYPER", "Performance Monitor Event Type Select Register" ),
        ( "p15", "c9", 0, "c13", 2) : ( "PMXEVCNTR", "Performance Monitor Event Count Register" ),
        ( "p15", "c9", 0, "c14", 0) : ( "PMUSERENR", "Performance Monitor User Enable Register" ),
        ( "p15", "c9", 0, "c14", 1) : ( "PMINTENSET", "Performance Monitor Interrupt Enable Set Register" ),
        ( "p15", "c9", 0, "c14", 2) : ( "PMINTENCLR", "Performance Monitor Interrupt Enable Clear Register" ),
        ( "p15", "c9", 0, "c14", 3) : ( "PMOVSSET", "Performance Monitor Overflow Flag Status Register" ),
        ( "p15", "c9", 1, "c0", 2 ) : ( "L2CTLR", "L2 Control Register" ),
        ( "p15", "c9", 1, "c0", 3 ) : ( "L2ECTLR", "L2 Extended Control Register" ),

        # Memory attribute registers
        ( "p15", "c10", 0, "c0", 0) : ( "N/A", "TLB Lockdown" ), # ARM11
        ( "p15", "c10", 0, "c2", 0) : ( "MAIR0", "Memory Attribute Indirection Register 0" ),
        ( "p15", "c10", 0, "c2", 1) : ( "MAIR1", "Memory Attribute Indirection Register 1" ),
        ( "p15", "c10", 0, "c3", 0) : ( "AMAIR0", "Auxiliary Memory Attribute Indirection Register 0" ),
        ( "p15", "c10", 0, "c3", 1) : ( "AMAIR1", "Auxiliary Memory Attribute Indirection Register 1" ),
        ( "p15", "c10", 4, "c2", 0) : ( "HMAIR0", "Hyp Memory Attribute Indirection Register 0" ),
        ( "p15", "c10", 4, "c2", 1) : ( "HMAIR1", "Hyp Memory Attribute Indirection Register 1" ),
        ( "p15", "c10", 4, "c3", 0) : ( "HAMAIR0", "Hyp Auxiliary Memory Attribute Indirection Register 0" ),
        ( "p15", "c10", 4, "c3", 1) : ( "HAMAIR1", "Hyp Auxiliary Memory Attribute Indirection Register 1" ),

        # DMA registers (ARM11)
        ( "p15", "c11", 0, "c0", 0) : ( "N/A", "DMA Identification and Status (Present)" ),
        ( "p15", "c11", 0, "c0", 1) : ( "N/A", "DMA Identification and Status (Queued)" ),
        ( "p15", "c11", 0, "c0", 2) : ( "N/A", "DMA Identification and Status (Running)" ),
        ( "p15", "c11", 0, "c0", 3) : ( "N/A", "DMA Identification and Status (Interrupting)" ),
        ( "p15", "c11", 0, "c1", 0) : ( "N/A", "DMA User Accessibility" ),
        ( "p15", "c11", 0, "c2", 0) : ( "N/A", "DMA Channel Number" ),
        ( "p15", "c11", 0, "c3", 0) : ( "N/A", "DMA Enable (Stop)" ),
        ( "p15", "c11", 0, "c3", 1) : ( "N/A", "DMA Enable (Start)" ),
        ( "p15", "c11", 0, "c3", 2) : ( "N/A", "DMA Enable (Clear)" ),
        ( "p15", "c11", 0, "c4", 0) : ( "N/A", "DMA Control" ),
        ( "p15", "c11", 0, "c5", 0) : ( "N/A", "DMA Internal Start Address" ),
        ( "p15", "c11", 0, "c6", 0) : ( "N/A", "DMA External Start Address" ),
        ( "p15", "c11", 0, "c7", 0) : ( "N/A", "DMA Internal End Address" ),
        ( "p15", "c11", 0, "c8", 0) : ( "N/A", "DMA Channel Status" ),
        ( "p15", "c11", 0, "c15", 0): ( "N/A", "DMA Context ID" ),

        ( "p15", "c12", 0, "c0", 0) : ( "VBAR", "Vector Base Address Register" ),
        ( "p15", "c12", 0, "c0", 1) : ( "MVBAR", "Monitor Vector Base Address Register" ),
        ( "p15", "c12", 0, "c1", 0) : ( "ISR", "Interrupt Status Register" ),
        ( "p15", "c12", 4, "c0", 0) : ( "HVBAR", "Hyp Vector Base Address Register" ),

        ( "p15", "c13", 0, "c0", 0) : ( "FCSEIDR", "FCSE Process ID Register" ),
        ( "p15", "c13", 0, "c0", 1) : ( "CONTEXTIDR", "Context ID Register" ),
        ( "p15", "c13", 0, "c0", 2) : ( "TPIDRURW", "User Read/Write Thread ID Register" ),
        ( "p15", "c13", 0, "c0", 3) : ( "TPIDRURO", "User Read-Only Thread ID Register" ),
        ( "p15", "c13", 0, "c0", 4) : ( "TPIDRPRW", "PLI only Thread ID Register" ),
        ( "p15", "c13", 4, "c0", 2) : ( "HTPIDR", "Hyp Software Thread ID Register" ),

        # Generic timer registers
        ( "p15", "c14", 0, "c0", 0) : ( "CNTFRQ", "Counter Frequency Register" ),
        #TODO

        ( "p15", "c15", 0, "c0", 0) : ( "IL1Data0", "Instruction L1 Data n Register" ),
        ( "p15", "c15", 0, "c0", 1) : ( "IL1Data1", "Instruction L1 Data n Register" ),
        ( "p15", "c15", 0, "c0", 2) : ( "IL1Data2", "Instruction L1 Data n Register" ),
        ( "p15", "c15", 0, "c1", 0) : ( "DL1Data0", "Data L1 Data n Register" ),
        ( "p15", "c15", 0, "c1", 1) : ( "DL1Data1", "Data L1 Data n Register" ),
        ( "p15", "c15", 0, "c1", 2) : ( "DL1Data2", "Data L1 Data n Register" ),
        ( "p15", "c15", 0, "c2", 0) : ( "N/A", "Data Memory Remap" ), # ARM11
        ( "p15", "c15", 0, "c2", 1) : ( "N/A", "Instruction Memory Remap" ), # ARM11
        ( "p15", "c15", 0, "c2", 2) : ( "N/A", "DMA Memory Remap" ), # ARM11
        ( "p15", "c15", 0, "c2", 3) : ( "N/A", "Peripheral Port Memory Remap" ), # ARM11
        ( "p15", "c15", 0, "c4", 0) : ( "RAMINDEX", "RAM Index Register" ),
        ( "p15", "c15", 0, "c12", 0): ( "N/A", "Performance Monitor Control" ), #ARM11
        ( "p15", "c15", 0, "c12", 1): ( "CCNT", "Cycle Counter" ), #ARM11
        ( "p15", "c15", 0, "c12", 2): ( "PMN0", "Count 0" ), #ARM11
        ( "p15", "c15", 0, "c12", 3): ( "PMN1", "Count 1" ), #ARM11
        ( "p15", "c15", 1, "c0", 0) : ( "L2ACTLR", "L2 Auxiliary Control Register" ),
        ( "p15", "c15", 1, "c0", 3) : ( "L2FPR", "L2 Prefetch Control Register" ),
        ( "p15", "c15", 3, "c0", 0) : ( "N/A", "Data Debug Cache" ), # ARM11
        ( "p15", "c15", 3, "c0", 1) : ( "N/A", "Instruction Debug Cache" ), # ARM11
        ( "p15", "c15", 3, "c2", 0) : ( "N/A", "Data Tag RAM Read Operation" ), # ARM11
        ( "p15", "c15", 3, "c2", 1) : ( "N/A", "Instruction Tag RAM Read Operation" ), # ARM11
        ( "p15", "c15", 4, "c0", 0) : ( "CBAR", "Configuration Base Address Register" ),
        ( "p15", "c15", 5, "c4", 0) : ( "N/A", "Data MicroTLB Index" ), # ARM11
        ( "p15", "c15", 5, "c4", 1) : ( "N/A", "Instruction MicroTLB Index" ), # ARM11
        ( "p15", "c15", 5, "c4", 2) : ( "N/A", "Read Main TLB Entry" ), # ARM11
        ( "p15", "c15", 5, "c4", 4) : ( "N/A", "Write Main TLB Entry" ), # ARM11
        ( "p15", "c15", 5, "c5", 0) : ( "N/A", "Data MicroTLB VA" ), # ARM11
        ( "p15", "c15", 5, "c5", 1) : ( "N/A", "Instruction MicroTLB VA" ), # ARM11
        ( "p15", "c15", 5, "c5", 2) : ( "N/A", "Main TLB VA" ), # ARM11
        ( "p15", "c15", 5, "c7", 0) : ( "N/A", "Data MicroTLB Attribute" ), # ARM11
        ( "p15", "c15", 5, "c7", 1) : ( "N/A", "Instruction MicroTLB Attribute" ), # ARM11
        ( "p15", "c15", 5, "c7", 2) : ( "N/A", "Main TLB Attribute" ), # ARM11
        ( "p15", "c15", 7, "c0", 0) : ( "N/A", "Cache Debug Control" ), # ARM11
        ( "p15", "c15", 7, "c1", 0) : ( "N/A", "TLB Debug Control" ), # ARM11

        # Debug registers
        ( "p14", "c0", 0, "c0", 0 ) : ( "DBGDIDR", "Debug ID Register" ),
        ( "p14", "c0", 0, "c6", 0 ) : ( "DBGWFAR", "Watchpoint Fault Address Register" ),
        ( "p14", "c0", 0, "c7", 0 ) : ( "DBGVCR", "Vector Catch Register" ),
        ( "p14", "c0", 0, "c0", 2 ) : ( "DBGDTRRX", "Host to Target Data Transfer" ),
        ( "p14", "c0", 0, "c2", 2 ) : ( "DBGDSCR", "Debug Status and Control Register" ),
        ( "p14", "c0", 0, "c3", 2 ) : ( "DBGDTRTX", "Target to Host Data Transfer" ),
        ( "p14", "c0", 0, "c0", 4 ) : ( "DBGBVR0", "Breakpoint Value Register 0" ),
        ( "p14", "c0", 0, "c1", 4 ) : ( "DBGBVR1", "Breakpoint Value Register 1" ),
        ( "p14", "c0", 0, "c2", 4 ) : ( "DBGBVR2", "Breakpoint Value Register 2" ),
        ( "p14", "c0", 0, "c3", 4 ) : ( "DBGBVR3", "Breakpoint Value Register 3" ),
        ( "p14", "c0", 0, "c4", 4 ) : ( "DBGBVR4", "Breakpoint Value Register 4" ),
        ( "p14", "c0", 0, "c5", 4 ) : ( "DBGBVR5", "Breakpoint Value Register 5" ),
        ( "p14", "c0", 0, "c0", 5 ) : ( "DBGBCR0", "Breakpoint Control Register 0" ),
        ( "p14", "c0", 0, "c1", 5 ) : ( "DBGBCR1", "Breakpoint Control Register 1" ),
        ( "p14", "c0", 0, "c2", 5 ) : ( "DBGBCR2", "Breakpoint Control Register 2" ),
        ( "p14", "c0", 0, "c3", 5 ) : ( "DBGBCR3", "Breakpoint Control Register 3" ),
        ( "p14", "c0", 0, "c4", 5 ) : ( "DBGBCR4", "Breakpoint Control Register 4" ),
        ( "p14", "c0", 0, "c5", 5 ) : ( "DBGBCR5", "Breakpoint Control Register 5" ),
        ( "p14", "c0", 0, "c0", 6 ) : ( "DBGWVR0", "Watchpoint Value Register 0" ),
        ( "p14", "c0", 0, "c1", 6 ) : ( "DBGWVR1", "Watchpoint Value Register 1" ),
        ( "p14", "c0", 0, "c2", 6 ) : ( "DBGWVR2", "Watchpoint Value Register 2" ),
        ( "p14", "c0", 0, "c3", 6 ) : ( "DBGWVR3", "Watchpoint Value Register 3" ),
        ( "p14", "c0", 0, "c0", 7 ) : ( "DBGWCR0", "Watchpoint Control Register 0" ),
        ( "p14", "c0", 0, "c1", 7 ) : ( "DBGWCR1", "Watchpoint Control Register 1" ),
        ( "p14", "c0", 0, "c2", 7 ) : ( "DBGWCR2", "Watchpoint Control Register 2" ),
        ( "p14", "c0", 0, "c3", 7 ) : ( "DBGWCR3", "Watchpoint Control Register 3" ),
        ( "p14", "c0", 0, "c4", 1 ) : ( "DBGBXVR0", "Breakpoint Extended Value Register 0" ),
        ( "p14", "c0", 0, "c5", 1 ) : ( "DBGBXVR1", "Breakpoint Extended Value Register 1" ),
        ( "p14", "c1", 0, "c0", 4 ) : ( "DBGOSLAR", "OS Lock Access Register" ),
        ( "p14", "c1", 0, "c0", 4 ) : ( "DBGOSLSR", "OS Lock Status Register" ),
        ( "p14", "c1", 0, "c4", 4 ) : ( "DBGPRCR", "Device Powerdown and Reset Status Register" ),
        ( "p14", "c7", 0, "c14", 6) : ( "DBGAUTHSTATUS", "Authentication Status Register" ),
        ( "p14", "c7", 0, "c0", 7 ) : ( "DBGDEVID2", "UNK" ),
        ( "p14", "c7", 0, "c1", 7 ) : ( "DBGDEVID1", "Debug Device ID Register 1" ),
        ( "p14", "c7", 0, "c2", 7 ) : ( "DBGDEVID", "Debug Device ID Register" ),
        ( "p14", "c0", 0, "c1", 0 ) : ( "DBGDSCR", "Debug Status and Control Register" ),
        ( "p14", "c0", 0, "c5", 0 ) : ( "DBGDTRRX", "Host to Target Data Transfer" ),
        ( "p14", "c1", 0, "c0", 0 ) : ( "DBGDRAR", "Debug ROM Address Register" ),
        ( "p14", "c1", 0, "c3", 4 ) : ( "DBGOSDLR", "OS Double Lock Register" ),
        ( "p14", "c2", 0, "c0", 0 ) : ( "DBGDSAR", "Debug Self Address Offset Register" ),
}

# Aarch64 system registers.
# Extracted from the 00bet3.2 XML specifications for ARMv8.2.
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
        ( 0b011, 0b100, "c12", "c9", 0b100 ) : ( "ICH_VSEIR_EL2", "Interrupt Controller Virtual System Error Interrupt Register" ), # Not defined in 8.2 specifications.
        ( 0b011, 0b100, "c12", "c11", 0b001 ) : ( "ICH_VTR_EL2", "Interrupt Controller VGIC Type Register" ),
}

# Aarch32 fields.
COPROC_FIELDS = {
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
}

# Aarch64 fields.
SYSREG_FIELDS = {
        "DAIF" : {
            6 : ( "F", "FIQ mask" ),
            7 : ( "I", "IRQ mask" ),
            8 : ( "A", "SError interrupt mask" ),
            9 : ( "D", "Process state D mask" )
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


def extract_bits(bitmap, value):
    return [ bitmap[b] for b in bitmap if value & (1 << b) ]

def is_system_insn(ea):
    mnem = GetMnem(ea)
    if len(mnem) > 0:
        if mnem in SYSTEM_INSN:
            return True
        if mnem[0:3] == "LDM" and GetOpnd(ea, 1)[-1:] == "^":
            return True
        if mnem[0:4] in ("SUBS", "MOVS") and GetOpnd(ea, 0) == "PC" and GetOpnd(ea, 1) == "LR":
            return True
    return False

def backtrack_fields(ea, reg, fields):
    while True:
        ea -= ItemSize(ea)
        prev_mnem = GetMnem(ea)[0:3]
        if prev_mnem in ("LDR", "MOV", "ORR", "BIC") and GetOpnd(ea, 0) == reg:
            if prev_mnem == "LDR" and GetOpnd(ea, 1)[0] == "=":
                bits = extract_bits(fields, Dword(GetOperandValue(ea, 1)))
                MakeComm(ea, "Set bits %s" % ", ".join([abbrev for (abbrev,name) in bits]))
                break
            elif prev_mnem == "MOV" and GetOpnd(ea, 1)[0] == "#":
                bits = extract_bits(fields, GetOperandValue(ea, 1))
                MakeComm(ea, "Set bits %s" % ", ".join([abbrev for (abbrev,name) in bits]))
                break
            elif prev_mnem == "ORR"  and GetOpnd(ea, 2)[0] == "#":
                bits = extract_bits(fields, GetOperandValue(ea, 2))
                MakeComm(ea, "Set bit %s" % ", ".join([name for (abbrev,name) in bits]))
            elif prev_mnem == "BIC"  and GetOpnd(ea, 2)[0] == "#":
                bits = extract_bits(fields, GetOperandValue(ea, 2))
                MakeComm(ea, "Clear bit %s" % ", ".join([name for (abbrev,name) in bits]))
            else:
                break
        else:
            break

def identify_register(ea, access, sig, known_regs, cpu_reg = None, known_fields = {}):
    desc = known_regs.get(sig, None)
    if desc:
        cmt = ("[%s] " + "\n or ".join(["%s (%s)"] * (len(desc) / 2))) % ((access,) + desc)
        MakeComm(ea, cmt)
        print(cmt)

        # Try to resolve fields during a write operation.
        if access == '>' and len(desc) == 2:
            fields = known_fields.get(desc[0], None)
            if fields:
                backtrack_fields(ea, cpu_reg, fields)
    else:
        print("Cannot identify system register.")
        MakeComm(ea, "[%s] Unknown system register." % access)

def markup_coproc_reg64_insn(ea):
    if GetMnem(ea)[1] == "R":
        access = '<'
    else:
        access = '>'
    op1 = GetOperandValue(ea, 0)
    cp = "p%d" % DecodeInstruction(ea).Op1.specflag1
    reg1, reg2, crm = GetOpnd(ea, 1).split(',')

    sig = ( cp, op1, crm )
    identify_register(ea, access, sig, COPROC_REGISTERS_64)

def markup_coproc_insn(ea):
    if GetMnem(ea)[1] == "R":
        access = '<'
    else:
        access = '>'
    op1, op2 = GetOperandValue(ea, 0), GetOperandValue(ea, 2)
    reg, crn, crm = GetOpnd(ea, 1).split(',')
    cp = "p%d" % DecodeInstruction(ea).Op1.specflag1

    sig = ( cp, crn, op1, crm, op2 )
    identify_register(ea, access, sig, COPROC_REGISTERS, reg, COPROC_FIELDS)

def markup_aarch64_sys_insn(ea):
    if GetMnem(ea)[1] == "R":
        reg_pos = 0
        access = '<'
    else:
        reg_pos = 4
        access = '>'
    base_args = (reg_pos + 1) % 5
    op0 = 2 + ((Dword(ea) >> 19) & 1)
    op1, op2 = GetOperandValue(ea, base_args), GetOperandValue(ea, base_args + 3)
    crn, crm = GetOpnd(ea, base_args + 1), GetOpnd(ea, base_args + 2)
    reg = GetOpnd(ea, reg_pos)

    sig = ( op0, op1, crn, crm, op2 )
    identify_register(ea, access, sig, SYSTEM_REGISTERS, reg, SYSREG_FIELDS)

def markup_psr_insn(ea):
    if GetOpnd(ea,1)[0] == "#": # immediate
        psr = GetOperandValue(ea, 1)
        mode = ARM_MODES.get(psr & 0b11111, "Unknown")
        e = (psr & (1 << 9)) and 'E' or '-'
        a = (psr & (1 << 8)) and 'A' or '-'
        i = (psr & (1 << 7)) and 'I' or '-'
        f = (psr & (1 << 6)) and 'F' or '-'
        t = (psr & (1 << 5)) and 'T' or '-'
        MakeComm(ea, "Set CPSR [%c%c%c%c%c], Mode: %s" % (e,a,i,f,t,mode))

def markup_system_insn(ea):
    mnem = GetMnem(ea)
    if mnem[0:4] in ("MRRC", "MCRR"):
        markup_coproc_reg64_insn(ea)
    elif mnem[0:3] in ("MRC", "MCR"):
        markup_coproc_insn(ea)
    elif current_arch == 'aarch32' and mnem[0:3] == "MSR":
        markup_psr_insn(ea)
    elif current_arch == 'aarch64' and mnem[0:3] in ("MSR", "MRS"):
        markup_aarch64_sys_insn(ea)
    SetColor(ea, CIC_ITEM, 0x00000000) # Black background, adjust to your own theme

def current_arch_size():
    _, t, _ = ParseType("void *", 0)
    return SizeOf(t) * 8

def run_script():
    for addr in Heads():
        if is_system_insn(addr):
            print("Found system instruction %s at %08x" % ( GetMnem(addr), addr ))
            markup_system_insn(addr)

#
# Check we are running this script on an ARM architecture.
#
if GetLongPrm(INF_PROCNAME) != 'ARM':
    Warning("This script can only work with ARM and AArch64 architectures.")
else:
    current_arch = 'aarch64' if current_arch_size() == 64 else 'aarch32'
    run_script()
