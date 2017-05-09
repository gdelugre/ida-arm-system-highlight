## Decoding system instructions

This script will give you the list of ARM system instructions used in your IDA
database. This is useful for locating specific low-level pieces of code
(setting up the MMU, caches, fault handlers, etc.).

One hassle of reverse engineering low-level ARM code is that IDA Pro does not
decode the internal registers accessed by co-processor instructions
(``MCR``/``MRC`` and ``MSR``/``MRS`` on AArch64).

After applying the script, the system registers accessed will be automatically
commented in the database, as defined in the official ARM reference manuals.


![AArch32 decoding](/img/aarch32_hl.png)
![AArch64 decoding](/img/aarch64_hl.png)

## Usage

``Alt-F7`` in IDA Pro, then run the script on your open database.

## Compatibility

Should work with ARMv7 and ARMv8 processors.
