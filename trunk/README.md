Polychaos
=========

# PE permutation library #

## Features ##
- Reconstruct and reorder execution branches
- Alter jcc branch paths
- Swap, replace instructions
- Generate trash
- Randomize instruction position

- Support for custom mutation implementation

- Fixup relocations, TLS callbacks, exports, SAFESEH pointers

## Limitations ##
- No data in mutated code section (only code is allowed)
- No CRT entrypoint
- No external pointers to functions in code section (e.g. VTables, exception handler unwind tables)
- No statically linked CRT
- No .NET stuff
 
## License ##
Polychaos is licensed under the MIT License. Dependencies are under their respective licenses.