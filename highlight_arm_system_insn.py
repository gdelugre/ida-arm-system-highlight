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
        ( "p15", 2, "c14" )         : ( "CNTHP_CVAL", "Counter-timer Hyp Physical CompareValue register" ),
        ( "p15", 3, "c14" )         : ( "CNTV_CVAL", "Counter-timer Virtual Timer CompareValue register" ),
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
SYSTEM_REGISTERS = {
        # Special purpose registers.
        ( 0b000, "c4", "c2", 0b010 ) : ( "CurrentEL", "Current Exception Level" ),
        ( 0b011, "c4", "c2", 0b001 ) : ( "DAIF", "Interrupt Mask Bits" ),
        ( 0b000, "c4", "c0", 0b001 ) : ( "ELR_EL1", "Exception Link Register (EL1)" ),
        ( 0b100, "c4", "c0", 0b001 ) : ( "ELR_EL2", "Exception Link Register (EL2)" ),
        ( 0b110, "c4", "c0", 0b001 ) : ( "ELR_EL3", "Exception Link Register (EL3)" ),
        ( 0b011, "c4", "c4", 0b000 ) : ( "FPCR", "Floating-point Control Register" ),
        ( 0b011, "c4", "c4", 0b001 ) : ( "FPSR", "Floating-point Status Register" ),
        ( 0b011, "c4", "c2", 0b000 ) : ( "NZCV", "Condition Flags" ),
        ( 0b000, "c4", "c1", 0b000 ) : ( "SP_EL0", "Stack Pointer (EL0)" ),
        ( 0b100, "c4", "c1", 0b000 ) : ( "SP_EL1", "Stack Pointer (EL1)" ),
        ( 0b110, "c4", "c1", 0b000 ) : ( "SP_EL2", "Stack Pointer (EL2)" ),
        ( 0b000, "c4", "c2", 0b000 ) : ( "SPSel", "Stack Pointer Select" ),
        ( 0b100, "c4", "c3", 0b001 ) : ( "SPSR_abt", "Saved Program Status Register (Abort mode)" ),
        ( 0b000, "c4", "c0", 0b000 ) : ( "SPSR_EL1", "Saved Program Status Register (EL1)" ),
        ( 0b100, "c4", "c0", 0b000 ) : ( "SPSR_EL2", "Saved Program Status Register (EL2)" ),
        ( 0b110, "c4", "c0", 0b000 ) : ( "SPSR_EL3", "Saved Program Status Register (EL3)" ),
        ( 0b100, "c4", "c3", 0b011 ) : ( "SPSR_fiq", "Saved Program Status Register (FIQ mode)" ),
        ( 0b100, "c4", "c3", 0b000 ) : ( "SPSR_irq", "Saved Program Status Register (IRQ mode)" ),
        ( 0b100, "c4", "c3", 0b010 ) : ( "SPSR_und", "Saved Program Status Register (Undefined mode)" ),

        # General system control registers.
        ( 0b000, "c1", "c0", 0b001 ) : ( "ACTLR_EL1", "Auxiliary Control Register (EL1)" ),
        ( 0b100, "c1", "c0", 0b001 ) : ( "ACTLR_EL2", "Auxiliary Control Register (EL2)" ),
        ( 0b110, "c1", "c0", 0b001 ) : ( "ACTLR_EL3", "Auxiliary Control Register (EL3)" ),
        ( 0b000, "c5", "c1", 0b000 ) : ( "AFSR0_EL1", "Auxiliary Fault Status Register 0 (EL1)" ),
        ( 0b100, "c5", "c1", 0b000 ) : ( "AFSR0_EL2", "Auxiliary Fault Status Register 0 (EL2)" ),
        ( 0b110, "c5", "c1", 0b000 ) : ( "AFSR0_EL3", "Auxiliary Fault Status Register 0 (EL3)" ),
        ( 0b000, "c5", "c1", 0b001 ) : ( "AFSR1_EL1", "Auxiliary Fault Status Register 1 (EL1)" ),
        ( 0b100, "c5", "c1", 0b001 ) : ( "AFSR1_EL2", "Auxiliary Fault Status Register 1 (EL2)" ),
        ( 0b110, "c5", "c1", 0b001 ) : ( "AFSR1_EL3", "Auxiliary Fault Status Register 1 (EL3)" ),
        ( 0b001, "c0", "c0", 0b111 ) : ( "AIDR_EL1", "Auxiliary ID Register" ),
        ( 0b000, "c10", "c3", 0b000 ) : ( "AMAIR_EL1", "Auxiliary Memory Attribute Indirection Register (EL1)" ),
        ( 0b100, "c10", "c3", 0b000 ) : ( "AMAIR_EL2", "Auxiliary Memory Attribute Indirection Register (EL2)" ),
        ( 0b110, "c10", "c3", 0b000 ) : ( "AMAIR_EL3", "Auxiliary Memory Attribute Indirection Register (EL3)" ),
        ( 0b001, "c0", "c0", 0b000 ) : ( "CCSIDR_EL1", "Current Cache Size ID Register" ),
        ( 0b001, "c0", "c0", 0b001 ) : ( "CLIDR_EL1", "Current Cache Level ID Register" ),
        ( 0b000, "c13", "c0", 0b001 ) : ( "CONTEXTIDR_EL1", "Context ID Register" ),
        ( 0b000, "c1", "c0", 0b010 ) : ( "CPACR_EL1", "Architectural Feature Access Control Register" ),
        ( 0b100, "c1", "c1", 0b010 ) : ( "CPTR_EL2", "Architectural Feature Trap Register (EL2)" ),
        ( 0b110, "c1", "c1", 0b010 ) : ( "CPTR_EL3", "Architectural Feature Trap Register (EL3)" ),
        ( 0b010, "c0", "c0", 0b000 ) : ( "CSSELR_EL1", "Cache Size Selection Register" ),
        ( 0b011, "c0", "c0", 0b001 ) : ( "CTR_EL0", "Cache Type Register" ),
        ( 0b100, "c3", "c0", 0b000 ) : ( "DACR32_EL2", "Domain Access Control Register" ),
        ( 0b011, "c0", "c0", 0b111 ) : ( "DCZID_EL0", "Data Cache Zero ID Register" ),
        ( 0b000, "c5", "c2", 0b000 ) : ( "ESR_EL1", "Exception Syndrome Register (EL1)" ),
        ( 0b100, "c5", "c2", 0b000 ) : ( "ESR_EL2", "Exception Syndrome Register (EL2)" ),
        ( 0b110, "c5", "c2", 0b000 ) : ( "ESR_EL3", "Exception Syndrome Register (EL3)" ),
        ( 0b000, "c6", "c0", 0b000 ) : ( "FAR_EL1", "Fault Address Register (EL1)" ),
        ( 0b100, "c6", "c0", 0b000 ) : ( "FAR_EL2", "Fault Address Register (EL2)" ),
        ( 0b110, "c6", "c0", 0b000 ) : ( "FAR_EL3", "Fault Address Register (EL3)" ),
        ( 0b100, "c5", "c3", 0b000 ) : ( "FPEXC32_EL2", "Floating-point Exception Control Register" ),
        ( 0b100, "c1", "c1", 0b111 ) : ( "HACR_EL2", "Hypervisor Auxiliary Configuration Register" ),
        ( 0b100, "c1", "c1", 0b000 ) : ( "HCR_EL2", "Hypervisor Configuration Register" ),
        ( 0b100, "c6", "c0", 0b100 ) : ( "HPFAR_EL2", "Hypervisor IPA Fault Address Register" ),
        ( 0b100, "c1", "c1", 0b011 ) : ( "HSTR_EL2", "Hypervisor System Trap Register" ),
        ( 0b000, "c0", "c5", 0b100 ) : ( "ID_AA64AFR0_EL1", "AArch64 Auxiliary Feature Register 0" ),
        ( 0b000, "c0", "c5", 0b101 ) : ( "ID_AA64AFR1_EL1", "AArch64 Auxiliary Feature Register 1" ),
        ( 0b000, "c0", "c5", 0b000 ) : ( "ID_AA64DFR0_EL1", "AArch64 Debug Feature Register 0" ),
        ( 0b000, "c0", "c5", 0b001 ) : ( "ID_AA64DFR1_EL1", "AArch64 Debug Feature Register 1" ),
        ( 0b000, "c0", "c6", 0b000 ) : ( "ID_AA64ISAR0_EL1", "AArch64 Instruction Set Attribute Register 0" ),
        ( 0b000, "c0", "c6", 0b001 ) : ( "ID_AA64ISAR1_EL1", "AArch64 Instruction Set Attribute Register 1" ),
        ( 0b000, "c0", "c7", 0b000 ) : ( "ID_AA64MMFR0_EL1", "AArch64 Memory Model Feature Register 0" ),
        ( 0b000, "c0", "c7", 0b001 ) : ( "ID_AA64MMFR1_EL1", "AArch64 Memory Model Feature Register 1" ),
        ( 0b000, "c0", "c4", 0b000 ) : ( "ID_AA64PFR0_EL1", "AArch64 Process Feature Register 0" ),
        ( 0b000, "c0", "c4", 0b001 ) : ( "ID_AA64PFR1_EL1", "AArch64 Process Feature Register 1" ),
        ( 0b000, "c0", "c1", 0b011 ) : ( "ID_AFR0_EL1", "AArch32 Auxiliary Feature Register 0" ),
        ( 0b000, "c0", "c1", 0b010 ) : ( "ID_DFR0_EL1", "AArch32 Debug Feature Register 0" ),
        ( 0b000, "c0", "c2", 0b000 ) : ( "ID_ISAR0_EL1", "AArch32 Instruction Set Attribute Register 0" ),
        ( 0b000, "c0", "c2", 0b001 ) : ( "ID_ISAR1_EL1", "AArch32 Instruction Set Attribute Register 1" ),
        ( 0b000, "c0", "c2", 0b010 ) : ( "ID_ISAR2_EL1", "AArch32 Instruction Set Attribute Register 2" ),
        ( 0b000, "c0", "c2", 0b011 ) : ( "ID_ISAR3_EL1", "AArch32 Instruction Set Attribute Register 3" ),
        ( 0b000, "c0", "c2", 0b100 ) : ( "ID_ISAR4_EL1", "AArch32 Instruction Set Attribute Register 4" ),
        ( 0b000, "c0", "c2", 0b101 ) : ( "ID_ISAR5_EL1", "AArch32 Instruction Set Attribute Register 5" ),
        ( 0b000, "c0", "c1", 0b100 ) : ( "ID_MMFR0_EL1", "AArch32 Memory Model Feature Register 0" ),
        ( 0b000, "c0", "c1", 0b101 ) : ( "ID_MMFR1_EL1", "AArch32 Memory Model Feature Register 1" ),
        ( 0b000, "c0", "c1", 0b110 ) : ( "ID_MMFR2_EL1", "AArch32 Memory Model Feature Register 2" ),
        ( 0b000, "c0", "c1", 0b111 ) : ( "ID_MMFR3_EL1", "AArch32 Memory Model Feature Register 3" ),
        ( 0b000, "c0", "c1", 0b000 ) : ( "ID_PFR0_EL1", "AArch32 Processor Feature Register 0" ),
        ( 0b000, "c0", "c1", 0b001 ) : ( "ID_PFR1_EL1", "AArch32 Processor Feature Register 1" ),
        ( 0b100, "c5", "c0", 0b001 ) : ( "IFSR32_EL2", "Instruction Fault Status Register (EL2)" ),
        ( 0b000, "c12", "c1", 0b000 ) : ( "ISR_EL1", "Interrupt Status Register" ),
        ( 0b000, "c10", "c2", 0b000 ) : ( "MAIR_EL1", "Memory Attribute Indirection Register (EL1)" ),
        ( 0b100, "c10", "c2", 0b000 ) : ( "MAIR_EL2", "Memory Attribute Indirection Register (EL2)" ),
        ( 0b110, "c10", "c2", 0b000 ) : ( "MAIR_EL3", "Memory Attribute Indirection Register (EL3)" ),
        ( 0b000, "c0", "c0", 0b000 ) : ( "MIDR_EL1", "Main ID Register" ),
        ( 0b000, "c0", "c0", 0b101 ) : ( "MPIDR_EL1", "Multiprocessor Affinity Register" ),
        ( 0b000, "c0", "c3", 0b000 ) : ( "MVFR0_EL1", "Media and VFP Feature Register 0" ),
        ( 0b000, "c0", "c3", 0b001 ) : ( "MVFR1_EL1", "Media and VFP Feature Register 1" ),
        ( 0b000, "c0", "c3", 0b010 ) : ( "MVFR2_EL1", "Media and VFP Feature Register 2" ),
        ( 0b000, "c7", "c4", 0b000 ) : ( "PAR_EL1", "Physical Address Register" ),
        ( 0b000, "c0", "c0", 0b110 ) : ( "REVIDR_EL1", "Revision ID Register" ),
        ( 0b000, "c12", "c0", 0b010 ) : ( "RMR_EL1", "Reset Management Register (if EL2 and EL3 not implemented)" ),
        ( 0b100, "c12", "c0", 0b010 ) : ( "RMR_EL2", "Reset Management Register (if EL3 not implemented)" ),
        ( 0b110, "c12", "c0", 0b010 ) : ( "RMR_EL3", "Reset Management Register (if EL3 implemented)" ),
        ( 0b000, "c12", "c0", 0b001 ) : ( "RVBAR_EL1", "Reset Vector Base Address Register (if EL2 and EL3 not implemented)" ),
        ( 0b100, "c12", "c0", 0b001 ) : ( "RVBAR_EL2", "Reset Vector Base Address Register (if EL3 not implemented)" ),
        ( 0b110, "c12", "c0", 0b001 ) : ( "RVBAR_EL3", "Reset Vector Base Address Register (if EL3 implemented)" ),
        ( 0b110, "c1", "c1", 0b000 ) : ( "SCR_EL3", "Secure Configuration Register" ),
        ( 0b000, "c1", "c0", 0b000 ) : ( "SCTLR_EL1", "System Control Register (EL1)" ),
        ( 0b100, "c1", "c0", 0b000 ) : ( "SCTLR_EL2", "System Control Register (EL2)" ),
        ( 0b110, "c1", "c0", 0b000 ) : ( "SCTLR_EL3", "System Control Register (EL3)" ),
        ( 0b000, "c2", "c0", 0b010 ) : ( "TCR_EL1", "Translation Control Register (EL1)" ),
        ( 0b100, "c2", "c0", 0b010 ) : ( "TCR_EL2", "Translation Control Register (EL2)" ),
        ( 0b110, "c2", "c0", 0b010 ) : ( "TCR_EL3", "Translation Control Register (EL3)" ),
        ( 0b010, "c0", "c0", 0b000 ) : ( "TEECR32_EL1", "T32EE Configuration Register" ),
        ( 0b010, "c1", "c0", 0b000 ) : ( "TEEHBR32_EL1", "T32EE Handler Base Register" ),
        ( 0b011, "c13", "c0", 0b010 ) : ( "TPIDR_EL0", "Thread Pointer / ID Register (EL0)" ),
        ( 0b000, "c13", "c0", 0b100 ) : ( "TPIDR_EL1", "Thread Pointer / ID Register (EL1)" ),
        ( 0b100, "c13", "c0", 0b010 ) : ( "TPIDR_EL2", "Thread Pointer / ID Register (EL2)" ),
        ( 0b110, "c13", "c0", 0b010 ) : ( "TPIDR_EL3", "Thread Pointer / ID Register (EL3)" ),
        ( 0b011, "c13", "c0", 0b011 ) : ( "TPIDRRO_EL0", "Thread Pointer / ID Register, Read-Only (EL0)" ),
        ( 0b000, "c2", "c0", 0b000 ) : ( "TTBR0_EL1", "Translation Table Base Register 0 (EL1)" ),
        ( 0b100, "c2", "c0", 0b000 ) : ( "TTBR0_EL2", "Translation Table Base Register 0 (EL2)" ),
        ( 0b110, "c2", "c0", 0b000 ) : ( "TTBR0_EL3", "Translation Table Base Register 0 (EL3)" ),
        ( 0b000, "c2", "c0", 0b001 ) : ( "TTBR1_EL1", "Translation Table Base Register 1 (EL1)" ),
        ( 0b000, "c12", "c0", 0b000 ) : ( "VBAR_EL1", "Vector Base Address Register (EL1)" ),
        ( 0b100, "c12", "c0", 0b000 ) : ( "VBAR_EL2", "Vector Base Address Register (EL2)" ),
        ( 0b110, "c12", "c0", 0b000 ) : ( "VBAR_EL3", "Vector Base Address Register (EL3)" ),
        ( 0b100, "c0", "c0", 0b101 ) : ( "VMPIDR_EL2", "Virtualization Multiprocessor ID Register" ),
        ( 0b100, "c0", "c0", 0b000 ) : ( "VPIDR_EL2", "Virtualization Processor ID Register" ),
        ( 0b100, "c2", "c1", 0b010 ) : ( "VTCR_EL2", "Virtualization Translation Control Register" ),
        ( 0b100, "c2", "c1", 0b000 ) : ( "VTTBR_EL2", "Virtualization Translation Table Base Register" ),

        # Debug registers. Not implemented, may conflict with general registers (the only difference is op0).

        # Performance monitor registers.
        ( 0b011, "c14", "c15", 0b111 ) : ( "PMCCFILTR_EL0", "Performance Monitors Cycle Count Filter Register" ),
        ( 0b011, "c9", "c13", 0b000 ) : ( "PMCCNTR_EL0", "Performance Monitors Cycle Count Register" ),
        ( 0b011, "c9", "c12", 0b110 ) : ( "PMCEID0_EL0", "Performance Monitors Common Event Identification Register 0" ),
        ( 0b011, "c9", "c12", 0b111 ) : ( "PMCEID1_EL0", "Performance Monitors Common Event Identification Register 1" ),
        ( 0b011, "c9", "c12", 0b010 ) : ( "PMCNTENCLR_EL0", "Performance Monitors Count Enable Clear Register" ),
        ( 0b011, "c9", "c12", 0b001 ) : ( "PMCNTENSET_EL0", "Performance Monitors Count Enable Set Register" ),
        ( 0b011, "c9", "c12", 0b000 ) : ( "PMCR_EL0", "Performance Monitors Control Register" ),
        ( 0b011, "c14", "c8", 0b000 ) : ( "PMEVCNTR0_EL0", "Performance Monitors Event Count Register 0" ),
        ( 0b011, "c14", "c8", 0b001 ) : ( "PMEVCNTR0_EL1", "Performance Monitors Event Count Register 1" ),
        ( 0b011, "c14", "c8", 0b010 ) : ( "PMEVCNTR0_EL2", "Performance Monitors Event Count Register 2" ),
        ( 0b011, "c14", "c8", 0b011 ) : ( "PMEVCNTR0_EL3", "Performance Monitors Event Count Register 3" ),
        ( 0b011, "c14", "c8", 0b100 ) : ( "PMEVCNTR0_EL4", "Performance Monitors Event Count Register 4" ),
        ( 0b011, "c14", "c8", 0b101 ) : ( "PMEVCNTR0_EL5", "Performance Monitors Event Count Register 5" ),
        ( 0b011, "c14", "c8", 0b110 ) : ( "PMEVCNTR0_EL6", "Performance Monitors Event Count Register 6" ),
        ( 0b011, "c14", "c8", 0b111 ) : ( "PMEVCNTR0_EL7", "Performance Monitors Event Count Register 7" ),
        ( 0b011, "c14", "c9", 0b000 ) : ( "PMEVCNTR0_EL8", "Performance Monitors Event Count Register 8" ),
        ( 0b011, "c14", "c9", 0b001 ) : ( "PMEVCNTR0_EL9", "Performance Monitors Event Count Register 9" ),
        ( 0b011, "c14", "c9", 0b010 ) : ( "PMEVCNTR0_EL10", "Performance Monitors Event Count Register 10" ),
        ( 0b011, "c14", "c9", 0b011 ) : ( "PMEVCNTR0_EL11", "Performance Monitors Event Count Register 11" ),
        ( 0b011, "c14", "c9", 0b100 ) : ( "PMEVCNTR0_EL12", "Performance Monitors Event Count Register 12" ),
        ( 0b011, "c14", "c9", 0b101 ) : ( "PMEVCNTR0_EL13", "Performance Monitors Event Count Register 13" ),
        ( 0b011, "c14", "c9", 0b110 ) : ( "PMEVCNTR0_EL14", "Performance Monitors Event Count Register 14" ),
        ( 0b011, "c14", "c9", 0b111 ) : ( "PMEVCNTR0_EL15", "Performance Monitors Event Count Register 15" ),
        ( 0b011, "c14", "c10", 0b000 ) : ( "PMEVCNTR0_EL16", "Performance Monitors Event Count Register 16" ),
        ( 0b011, "c14", "c10", 0b001 ) : ( "PMEVCNTR0_EL17", "Performance Monitors Event Count Register 17" ),
        ( 0b011, "c14", "c10", 0b010 ) : ( "PMEVCNTR0_EL18", "Performance Monitors Event Count Register 18" ),
        ( 0b011, "c14", "c10", 0b011 ) : ( "PMEVCNTR0_EL19", "Performance Monitors Event Count Register 19" ),
        ( 0b011, "c14", "c10", 0b100 ) : ( "PMEVCNTR0_EL20", "Performance Monitors Event Count Register 20" ),
        ( 0b011, "c14", "c10", 0b101 ) : ( "PMEVCNTR0_EL21", "Performance Monitors Event Count Register 21" ),
        ( 0b011, "c14", "c10", 0b110 ) : ( "PMEVCNTR0_EL22", "Performance Monitors Event Count Register 22" ),
        ( 0b011, "c14", "c10", 0b111 ) : ( "PMEVCNTR0_EL23", "Performance Monitors Event Count Register 23" ),
        ( 0b011, "c14", "c11", 0b000 ) : ( "PMEVCNTR0_EL24", "Performance Monitors Event Count Register 24" ),
        ( 0b011, "c14", "c11", 0b001 ) : ( "PMEVCNTR0_EL25", "Performance Monitors Event Count Register 25" ),
        ( 0b011, "c14", "c11", 0b010 ) : ( "PMEVCNTR0_EL26", "Performance Monitors Event Count Register 26" ),
        ( 0b011, "c14", "c11", 0b011 ) : ( "PMEVCNTR0_EL27", "Performance Monitors Event Count Register 27" ),
        ( 0b011, "c14", "c11", 0b100 ) : ( "PMEVCNTR0_EL28", "Performance Monitors Event Count Register 28" ),
        ( 0b011, "c14", "c11", 0b101 ) : ( "PMEVCNTR0_EL29", "Performance Monitors Event Count Register 29" ),
        ( 0b011, "c14", "c11", 0b110 ) : ( "PMEVCNTR0_EL30", "Performance Monitors Event Count Register 30" ),
        ( 0b011, "c14", "c12", 0b000 ) : ( "PMEVTYPER0_EL0", "Performance Monitors Event Type Register 0" ),
        ( 0b011, "c14", "c12", 0b001 ) : ( "PMEVTYPER0_EL1", "Performance Monitors Event Type Register 1" ),
        ( 0b011, "c14", "c12", 0b010 ) : ( "PMEVTYPER0_EL2", "Performance Monitors Event Type Register 2" ),
        ( 0b011, "c14", "c12", 0b011 ) : ( "PMEVTYPER0_EL3", "Performance Monitors Event Type Register 3" ),
        ( 0b011, "c14", "c12", 0b100 ) : ( "PMEVTYPER0_EL4", "Performance Monitors Event Type Register 4" ),
        ( 0b011, "c14", "c12", 0b101 ) : ( "PMEVTYPER0_EL5", "Performance Monitors Event Type Register 5" ),
        ( 0b011, "c14", "c12", 0b110 ) : ( "PMEVTYPER0_EL6", "Performance Monitors Event Type Register 6" ),
        ( 0b011, "c14", "c12", 0b111 ) : ( "PMEVTYPER0_EL7", "Performance Monitors Event Type Register 7" ),
        ( 0b011, "c14", "c13", 0b000 ) : ( "PMEVTYPER0_EL8", "Performance Monitors Event Type Register 8" ),
        ( 0b011, "c14", "c13", 0b001 ) : ( "PMEVTYPER0_EL9", "Performance Monitors Event Type Register 9" ),
        ( 0b011, "c14", "c13", 0b010 ) : ( "PMEVTYPER0_EL10", "Performance Monitors Event Type Register 10" ),
        ( 0b011, "c14", "c13", 0b011 ) : ( "PMEVTYPER0_EL11", "Performance Monitors Event Type Register 11" ),
        ( 0b011, "c14", "c13", 0b100 ) : ( "PMEVTYPER0_EL12", "Performance Monitors Event Type Register 12" ),
        ( 0b011, "c14", "c13", 0b101 ) : ( "PMEVTYPER0_EL13", "Performance Monitors Event Type Register 13" ),
        ( 0b011, "c14", "c13", 0b110 ) : ( "PMEVTYPER0_EL14", "Performance Monitors Event Type Register 14" ),
        ( 0b011, "c14", "c13", 0b111 ) : ( "PMEVTYPER0_EL15", "Performance Monitors Event Type Register 15" ),
        ( 0b011, "c14", "c14", 0b000 ) : ( "PMEVTYPER0_EL16", "Performance Monitors Event Type Register 16" ),
        ( 0b011, "c14", "c14", 0b001 ) : ( "PMEVTYPER0_EL17", "Performance Monitors Event Type Register 17" ),
        ( 0b011, "c14", "c14", 0b010 ) : ( "PMEVTYPER0_EL18", "Performance Monitors Event Type Register 18" ),
        ( 0b011, "c14", "c14", 0b011 ) : ( "PMEVTYPER0_EL19", "Performance Monitors Event Type Register 19" ),
        ( 0b011, "c14", "c14", 0b100 ) : ( "PMEVTYPER0_EL20", "Performance Monitors Event Type Register 20" ),
        ( 0b011, "c14", "c14", 0b101 ) : ( "PMEVTYPER0_EL21", "Performance Monitors Event Type Register 21" ),
        ( 0b011, "c14", "c14", 0b110 ) : ( "PMEVTYPER0_EL22", "Performance Monitors Event Type Register 22" ),
        ( 0b011, "c14", "c14", 0b111 ) : ( "PMEVTYPER0_EL23", "Performance Monitors Event Type Register 23" ),
        ( 0b011, "c14", "c15", 0b000 ) : ( "PMEVTYPER0_EL24", "Performance Monitors Event Type Register 24" ),
        ( 0b011, "c14", "c15", 0b001 ) : ( "PMEVTYPER0_EL25", "Performance Monitors Event Type Register 25" ),
        ( 0b011, "c14", "c15", 0b010 ) : ( "PMEVTYPER0_EL26", "Performance Monitors Event Type Register 26" ),
        ( 0b011, "c14", "c15", 0b011 ) : ( "PMEVTYPER0_EL27", "Performance Monitors Event Type Register 27" ),
        ( 0b011, "c14", "c15", 0b100 ) : ( "PMEVTYPER0_EL28", "Performance Monitors Event Type Register 28" ),
        ( 0b011, "c14", "c15", 0b101 ) : ( "PMEVTYPER0_EL29", "Performance Monitors Event Type Register 29" ),
        ( 0b011, "c14", "c15", 0b110 ) : ( "PMEVTYPER0_EL30", "Performance Monitors Event Type Register 30" ),
        ( 0b000, "c9", "c14", 0b010 ) : ( "PMINTENCLR_EL1", "Performance Monitors Interrupt Enable Clear Register" ),
        ( 0b000, "c9", "c14", 0b001 ) : ( "PMINTENSET_EL1", "Performance Monitors Interrupt Enable Set Register" ),
        ( 0b011, "c9", "c12", 0b011 ) : ( "PMOVSCLR_EL0", "Performance Monitors Overflow Flag Status Clear Register" ),
        ( 0b011, "c9", "c14", 0b011 ) : ( "PMOVSSET_EL0", "Performance Monitors Overflow Flag Status Set Register" ),
        ( 0b011, "c9", "c12", 0b101 ) : ( "PMSELR_EL0", "Performance Monitors Event Counter Selection Register" ),
        ( 0b011, "c9", "c12", 0b100 ) : ( "PMSWINC_EL0", "Performance Monitors Software Increment Register" ),
        ( 0b011, "c9", "c14", 0b000 ) : ( "PMUSERENR_EL0", "Performance Monitors User Enable Register" ),
        ( 0b011, "c9", "c13", 0b010 ) : ( "PMXEVCNTR_EL0", "Performance Monitors Selected Event Count Register" ),
        ( 0b011, "c9", "c13", 0b001 ) : ( "PMXEVTYPER_EL0", "Performance Monitors Selected Event Type Register" ),

        # Generic Timer registers.
        ( 0b011, "c14", "c0", 0b000 ) : ( "CNTFRQ_EL0", "Counter-timer Frequency Register" ),
        ( 0b100, "c14", "c1", 0b000 ) : ( "CNTHCTL_EL2", "Counter-timer Hypervisor Control Register" ),
        ( 0b100, "c14", "c2", 0b001 ) : ( "CNTHP_CTL_EL2", "Counter-timer Hypervisor Physical Timer Control Register" ),
        ( 0b100, "c14", "c2", 0b010 ) : ( "CNTHP_CVAL_EL2", "Counter-timer Hypervisor Physical Timer CompareValue Register" ),
        ( 0b100, "c14", "c2", 0b000 ) : ( "CNTHP_TVAL_EL2", "Counter-timer Hypervisor Physical Timer TimerValue Register" ),
        ( 0b000, "c14", "c1", 0b000 ) : ( "CNTKCTL_EL1", "Counter-timer Kernel Control Register" ),
        ( 0b011, "c14", "c2", 0b001 ) : ( "CNTP_CTL_EL0", "Counter-timer Physical Timer Control Register" ),
        ( 0b011, "c14", "c2", 0b010 ) : ( "CNTP_CVAL_EL0", "Counter-timer Physical Timer CompareValue Register" ),
        ( 0b011, "c14", "c2", 0b000 ) : ( "CNTP_TVAL_EL0", "Counter-timer Physical TImer TimerValue Register" ),
        ( 0b011, "c14", "c0", 0b001 ) : ( "CNTPCT_EL0", "Counter-timer Physical Count Register" ),
        ( 0b111, "c14", "c2", 0b001 ) : ( "CNTPS_CTL_EL1", "Counter-timer Physical Secure Timer Control Register" ),
        ( 0b111, "c14", "c2", 0b010 ) : ( "CNTPS_CVAL_EL1", "Counter-timer Physical Secure Timer CompareValue Register" ),
        ( 0b111, "c14", "c2", 0b000 ) : ( "CNTPS_TVAL_EL1", "Counter-timer Physical Secure Timer TimerValue Register" ),
        ( 0b011, "c14", "c3", 0b001 ) : ( "CNTV_CTL_EL0", "Counter-timer Virtual Timer Control Register" ),
        ( 0b011, "c14", "c3", 0b010 ) : ( "CNTV_CVAL_EL0", "Counter-timer Virtual Timer CompareValue Register" ),
        ( 0b011, "c14", "c3", 0b000 ) : ( "CNTV_TVAL_EL0", "Counter-timer Virtual Timer TimerValue Register" ),
        ( 0b011, "c14", "c0", 0b010 ) : ( "CNTVCT_EL0", "Counter-timer Virtual Count Register" ),
        ( 0b100, "c14", "c0", 0b011 ) : ( "CNTVOFF_EL2", "Counter-timer Virtual Offset Register" ),

        # Generic Interrupt Controller CPU interface registers.
        ( 0b000, "c12", "c8", 0b100 ) : ( "ICC_AP0R0_EL1", "Interrupt Controller Active Priorities Register (0,0)" ),
        ( 0b000, "c12", "c8", 0b101 ) : ( "ICC_AP0R1_EL1", "Interrupt Controller Active Priorities Register (0,1)" ),
        ( 0b000, "c12", "c8", 0b110 ) : ( "ICC_AP0R2_EL1", "Interrupt Controller Active Priorities Register (0,2)" ),
        ( 0b000, "c12", "c8", 0b111 ) : ( "ICC_AP0R3_EL1", "Interrupt Controller Active Priorities Register (0,3)" ),
        ( 0b000, "c12", "c9", 0b000 ) : ( "ICC_AP1R0_EL1", "Interrupt Controller Active Priorities Register (1,0)" ),
        ( 0b000, "c12", "c9", 0b001 ) : ( "ICC_AP1R1_EL1", "Interrupt Controller Active Priorities Register (1,1)" ),
        ( 0b000, "c12", "c9", 0b010 ) : ( "ICC_AP1R2_EL1", "Interrupt Controller Active Priorities Register (1,2)" ),
        ( 0b000, "c12", "c9", 0b011 ) : ( "ICC_AP1R3_EL1", "Interrupt Controller Active Priorities Register (1,3)" ),
        ( 0b000, "c12", "c11", 0b110 ) : ( "ICC_ASGI1R_EL1", "Interrupt Controller Alias Software Generated Interrupt Group 1 Register" ),
        ( 0b000, "c12", "c8", 0b011 ) : ( "ICC_BPR0_EL1", "Interrupt Controller Binary Point Register 0" ),
        ( 0b000, "c12", "c12", 0b011 ) : ( "ICC_BPR1_EL1", "Interrupt Controller Binary Point Register 1" ),
        ( 0b000, "c12", "c12", 0b100 ) : ( "ICC_CTRL_EL1", "Interrupt Controller Control Register (EL1)" ),
        ( 0b110, "c12", "c12", 0b100 ) : ( "ICC_CTRL_EL1", "Interrupt Controller Control Register (EL3)" ),
        ( 0b000, "c12", "c11", 0b001 ) : ( "ICC_DIR_EL1", "Interrupt Controller Deactivate Interrupt Register" ),
        ( 0b000, "c12", "c8", 0b001 ) : ( "ICC_EOIR0_EL1", "Interrupt Controller End Of Interrupt Register 0" ),
        ( 0b000, "c12", "c12", 0b001 ) : ( "ICC_EOIR1_EL1", "Interrupt Controller End Of Interrupt Register 1" ),
        ( 0b000, "c12", "c8", 0b010 ) : ( "ICC_HPPIR0_EL1", "Interrupt Controller Highest Priority Pending Interrupt Register 0" ),
        ( 0b000, "c12", "c12", 0b010 ) : ( "ICC_HPPIR1_EL1", "Interrupt Controller Highest Priority Pending Interrupt Register 1" ),
        ( 0b000, "c12", "c8", 0b000 ) : ( "ICC_IAR0_EL1", "Interrupt Controller Acknowledge Register 0" ),
        ( 0b000, "c12", "c12", 0b000 ) : ( "ICC_IAR1_EL1", "Interrupt Controller Acknowledge Register 1" ),
        ( 0b000, "c12", "c12", 0b110 ) : ( "ICC_IGRPEN0_EL1", "Interrupt Controller Interrupt Group 0 Enable Register" ),
        ( 0b000, "c12", "c12", 0b111 ) : ( "ICC_IGRPEN1_EL1", "Interrupt Controller Interrupt Group 1 Enable Register" ),
        ( 0b110, "c12", "c12", 0b111 ) : ( "ICC_IGRPEN1_EL3", "Interrupt Controller Interrupt Group 1 Enable Register (EL3)" ),
        ( 0b000, "c4", "c6", 0b000 ) : ( "ICC_PMR_EL1", "Interrupt Controller Interrupt Priority Mask Register" ),
        ( 0b000, "c12", "c11", 0b011 ) : ( "ICC_RPR_EL1", "Interrupt Controller Running Priority Register" ),
        ( 0b000, "c12", "c11", 0b000 ) : ( "ICC_SEIEN_EL1", "Interrupt Controller System Error Interrupt Enable Register" ),
        ( 0b000, "c12", "c11", 0b111 ) : ( "ICC_SGI0R_EL1", "Interrupt Controller Software Generated Interrupt group 0 Register" ),
        ( 0b000, "c12", "c11", 0b101 ) : ( "ICC_SGI1R_EL1", "Interrupt Controller Software Generated Interrupt group 1 Register" ),
        ( 0b000, "c12", "c12", 0b101 ) : ( "ICC_SRE_EL1", "Interrupt Controller System Register Enable Register (EL1)" ),
        ( 0b100, "c12", "c9", 0b101 ) : ( "ICC_SRE_EL2", "Interrupt Controller System Register Enable Register (EL2)" ),
        ( 0b110, "c12", "c12", 0b101 ) : ( "ICC_SRE_EL3", "Interrupt Controller System Register Enable Register (EL3)" ),
        ( 0b100, "c12", "c8", 0b000 ) : ( "ICH_AP0R0_EL2", "Interrupt Controller Hyp Active Priorities Register (0,0)" ),
        ( 0b100, "c12", "c8", 0b001 ) : ( "ICH_AP0R1_EL2", "Interrupt Controller Hyp Active Priorities Register (0,1)" ),
        ( 0b100, "c12", "c8", 0b010 ) : ( "ICH_AP0R2_EL2", "Interrupt Controller Hyp Active Priorities Register (0,2)" ),
        ( 0b100, "c12", "c8", 0b011 ) : ( "ICH_AP0R3_EL2", "Interrupt Controller Hyp Active Priorities Register (0,3)" ),
        ( 0b100, "c12", "c9", 0b000 ) : ( "ICH_AP1R0_EL2", "Interrupt Controller Hyp Active Priorities Register (1,0)" ),
        ( 0b100, "c12", "c9", 0b001 ) : ( "ICH_AP1R1_EL2", "Interrupt Controller Hyp Active Priorities Register (1,1)" ),
        ( 0b100, "c12", "c9", 0b010 ) : ( "ICH_AP1R2_EL2", "Interrupt Controller Hyp Active Priorities Register (1,2)" ),
        ( 0b100, "c12", "c9", 0b011 ) : ( "ICH_AP1R3_EL2", "Interrupt Controller Hyp Active Priorities Register (1,3)" ),
        ( 0b100, "c12", "c11", 0b011 ) : ( "ICH_EISR_EL2", "Interrupt Controller End of Interrupt Status Register" ),
        ( 0b100, "c12", "c11", 0b101 ) : ( "ICH_ELSR_EL2", "Interrupt Controller Empty List Register Status Register" ),
        ( 0b100, "c12", "c11", 0b000 ) : ( "ICH_HCR_EL2", "Interrupt Controller Hyp Control Register" ),
        ( 0b100, "c12", "c12", 0b000 ) : ( "ICH_LR0_EL2", "Interrupt Controller List Register 0" ),
        ( 0b100, "c12", "c12", 0b001 ) : ( "ICH_LR1_EL2", "Interrupt Controller List Register 1" ),
        ( 0b100, "c12", "c12", 0b010 ) : ( "ICH_LR2_EL2", "Interrupt Controller List Register 2" ),
        ( 0b100, "c12", "c12", 0b011 ) : ( "ICH_LR3_EL2", "Interrupt Controller List Register 3" ),
        ( 0b100, "c12", "c12", 0b100 ) : ( "ICH_LR4_EL2", "Interrupt Controller List Register 4" ),
        ( 0b100, "c12", "c12", 0b101 ) : ( "ICH_LR5_EL2", "Interrupt Controller List Register 5" ),
        ( 0b100, "c12", "c12", 0b110 ) : ( "ICH_LR6_EL2", "Interrupt Controller List Register 6" ),
        ( 0b100, "c12", "c12", 0b111 ) : ( "ICH_LR7_EL2", "Interrupt Controller List Register 7" ),
        ( 0b100, "c12", "c13", 0b000 ) : ( "ICH_LR8_EL2", "Interrupt Controller List Register 8" ),
        ( 0b100, "c12", "c13", 0b001 ) : ( "ICH_LR9_EL2", "Interrupt Controller List Register 9" ),
        ( 0b100, "c12", "c13", 0b010 ) : ( "ICH_LR10_EL2", "Interrupt Controller List Register 10" ),
        ( 0b100, "c12", "c13", 0b011 ) : ( "ICH_LR11_EL2", "Interrupt Controller List Register 11" ),
        ( 0b100, "c12", "c13", 0b100 ) : ( "ICH_LR12_EL2", "Interrupt Controller List Register 12" ),
        ( 0b100, "c12", "c13", 0b101 ) : ( "ICH_LR13_EL2", "Interrupt Controller List Register 13" ),
        ( 0b100, "c12", "c13", 0b110 ) : ( "ICH_LR14_EL2", "Interrupt Controller List Register 14" ),
        ( 0b100, "c12", "c13", 0b111 ) : ( "ICH_LR15_EL2", "Interrupt Controller List Register 15" ),
        ( 0b100, "c12", "c11", 0b010 ) : ( "ICH_MISR_EL2", "Interrupt Controller Maintenance Interrupt State Register" ),
        ( 0b100, "c12", "c11", 0b111 ) : ( "ICH_VMCR_EL2", "Interrupt Controller Virtual Machine Control Register" ),
        ( 0b100, "c12", "c9", 0b100 ) : ( "ICH_VSEIR_EL2", "Interrupt Controller Virtual System Error Interrupt Register" ),
        ( 0b100, "c12", "c11", 0b001 ) :  ( "ICH_VTR_EL2", "Interrupt Controller VGIC Type Register" ),
}

COPROC_FIELDS = {
        "SCTLR" : {
            0 : ( "M", "MMU Enable" ),
            1 : ( "A", "Alignment" ),
            2 : ( "C", "Cache Enable" ),
            10 : ( "SW", "SWP/SWPB Enable" ),
            11 : ( "Z", "Branch Prediction Enable" ),
            12 : ( "I", "Instruction cache Enable" ),
            13 : ( "V", "High exception vectors" ),
            14 : ( "RR", "Round-robin cache" ),
            17 : ( "HA", "Hardware Access Enable" ),
            21 : ( "FI", "Fast Interrupts configuration" ),
            24 : ( "VE", "Interrupt Vectors Enable" ),
            25 : ( "EE", "Exception Endianness" ),
            27 : ( "NMFI", "Non-maskable Fast Interrupts" ),
            28 : ( "TRE", "TEX Remap Enable" ),
            29 : ( "AFE", "Access Flag Enable" ),
            30 : ( "TE", "Thumb Exception Enable" )
        }
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


def extract_bits(bitmap, field):
    bits = []
    for b in bitmap:
        if field & (1 << b) != 0:
            bits.append(bitmap[b])
    return bits

def is_system_insn(ea):
    mnem = GetMnem(ea)
    if len(mnem) > 0:
        if mnem in SYSTEM_INSN:
            return True
        if mnem[0:3] == "LDM" and GetOpnd(ea, 1)[-1:] == "^":
            return True
        if mnem in ("SUBS", "MOVS") and GetOpnd(ea, 0) == "PC" and GetOpnd(ea, 1) == "LR":
            return True
    return False

def markup_coproc_reg64_insn(ea):
    if GetMnem(ea)[1] == "R":
        direction = '<'
    else:
        direction = '>'
    op1 = GetOperandValue(ea, 0)
    cp = "p%d" % DecodeInstruction(ea).Op1.specflag1
    reg1, reg2, crm = GetOpnd(ea, 1).split(',')
    sig = ( cp, op1, crm )
    desc = COPROC_REGISTERS_64.get(sig, None)
    if desc:
        print("Identified as '%s'" % desc[1])
        MakeComm(ea, "[%s] %s (%s)" % (direction, desc[1], desc[0]))
    else:
        print("Cannot identify coprocessor register.")
        MakeComm(ea, "[%s] Unknown coprocessor register." % direction)
    
def markup_coproc_insn(ea):
    if GetMnem(ea)[1] == "R":
        direction = '<'
    else:
        direction = '>'
    op1, op2 = GetOperandValue(ea, 0), GetOperandValue(ea, 2)
    reg, crn, crm = GetOpnd(ea, 1).split(',')
    cp = "p%d" % DecodeInstruction(ea).Op1.specflag1
    sig = ( cp, crn, op1, crm, op2 ) 
    desc = COPROC_REGISTERS.get(sig, None)
    if desc:
        print("Identified as '%s'" % desc[1])
        MakeComm(ea, "[%s] %s (%s)" % (direction, desc[1], desc[0]))
       
        # Try to resolve fields at a write operation
        if direction == '>':
            fields = COPROC_FIELDS.get(desc[0], None)
            if fields:
                while True:
                    ea -= 4
                    prev_mnem = GetMnem(ea)
                    if prev_mnem in ("LDR", "MOV", "ORR", "BIC") and GetOpnd(ea, 0) == reg:
                        if prev_mnem == "LDR" and GetOpnd(ea, 1)[0] == "=":
                            bits = extract_bits(fields, Dword(GetOperandValue(ea, 1)))
                            MakeComm(ea, "Set bits %s" % ", ".join([abbrev for (abbrev,name) in bits]))
                            break
                        elif prev_mnem[0:3]  == "MOV" and GetOpnd(ea, 1)[0] == "#":
                            bits = extract_bits(fields, GetOperandValue(ea, 1))
                            MakeComm(ea, "Set bits %s" % ", ".join([abbrev for (abbrev,name) in bits]))
                            break
                        elif prev_mnem[0:3] == "ORR"  and GetOpnd(ea, 2)[0] == "#":
                            bits = extract_bits(fields, GetOperandValue(ea, 2))
                            MakeComm(ea, "Set bit %s" % ", ".join([name for (abbrev,name) in bits]))
                        elif prev_mnem[0:3] == "BIC"  and GetOpnd(ea, 2)[0] == "#":
                            bits = extract_bits(fields, GetOperandValue(ea, 2))
                            MakeComm(ea, "Clear bit %s" % ", ".join([name for (abbrev,name) in bits]))
                        else:
                            break
                    else:
                        break
    else:
        print("Cannot identify coprocessor register.")
        MakeComm(ea, "[%s] Unknown coprocessor register." % direction)

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

def markup_aarch64_sys_insn(ea):
    if GetMnem(ea)[1] == "R":
        reg_pos = 0
        direction = '<'
    else:
        reg_pos = 4
        direction = '>'

    base_args = (reg_pos + 1) % 5
    op1, op2 = GetOperandValue(ea, base_args), GetOperandValue(ea, base_args + 3)
    crn, crm = GetOpnd(ea, base_args + 1), GetOpnd(ea, base_args + 2)

    sig = ( op1, crn, crm, op2 )
    desc = SYSTEM_REGISTERS.get(sig, None)
    if desc:
        print("Identified as '%s'" % desc[1])
        MakeComm(ea, "[%s] %s (%s)" % (direction, desc[1], desc[0]))
        # TODO: backtrack bitfields
    else:
        print("Cannot identify system register")
        MakeComm(ea, "[%s] Unknown system register." % direction)


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
