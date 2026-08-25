from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class PspContainerHeader:
    module_attribute: int
    compression_attribute: int
    module_version: tuple[int, int]
    module_name: str
    module_version_byte: int
    segment_count: int
    elf_size: int
    psp_size: int
    boot_entry: int
    module_info_offset: int
    bss_size: int
    segment_alignments: list[int] = field(default_factory=list)
    segment_addresses: list[int] = field(default_factory=list)
    segment_sizes: list[int] = field(default_factory=list)
    devkit_version: int = 0
    decrypt_mode: int = 0
    overlap_size: int = 0
    compressed_size: int = 0
    subtype: int = 0

@dataclass(slots=True)
class ElfHeader:
    file_type: int
    machine: int
    version: int
    entry: int
    phoff: int
    shoff: int
    flags: int
    ehsize: int
    phentsize: int
    phnum: int
    shentsize: int
    shnum: int
    shstrndx: int


@dataclass(slots=True)
class ProgramHeader:
    index: int
    type: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    flags: int
    align: int


@dataclass(slots=True)
class Section:
    index: int
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    addralign: int
    entsize: int
    kind: str


@dataclass(slots=True)
class ElfImage:
    header: ElfHeader
    endianness: str
    program_headers: list[ProgramHeader]
    sections: list[Section]
    raw_data: bytes = field(repr=False)

    def vaddr_to_offset(self, address: int) -> int | None:
        for ph in self.program_headers:
            if ph.type != 1:
                continue
            if ph.vaddr <= address < ph.vaddr + ph.filesz:
                return ph.offset + (address - ph.vaddr)
        for section in self.sections:
            if section.type == 8:
                continue
            if section.addr <= address < section.addr + section.size:
                return section.offset + (address - section.addr)
        return None

@dataclass(slots=True)
class ModuleInfo:
    attributes: int
    version: tuple[int, int]
    name: str
    gp_value: int
    exports_start: int
    exports_end: int
    imports_start: int
    imports_end: int
    address: int
    location: str


@dataclass(slots=True)
class NidEntry:
    nid: int
    address: int
    kind: str
    nid_address: int


@dataclass(slots=True)
class LibraryImport:
    name: str
    flags: int
    entry_length: int
    function_count: int
    variable_count: int
    address: int
    functions: list[NidEntry] = field(default_factory=list)
    variables: list[NidEntry] = field(default_factory=list)


@dataclass(slots=True)
class LibraryExport:
    name: str
    flags: int
    entry_length: int
    function_count: int
    variable_count: int
    address: int
    functions: list[NidEntry] = field(default_factory=list)
    variables: list[NidEntry] = field(default_factory=list)


@dataclass(slots=True)
class Relocation:
    section: str
    offset: int
    info: int
    type: int
    type_name: str
    symbol_index: int
    target_section_index: int | None
    source: str = "section"


@dataclass(slots=True)
class PrxAnalysis:
    module_info: ModuleInfo | None
    imports: list[LibraryImport] = field(default_factory=list)
    exports: list[LibraryExport] = field(default_factory=list)
    relocations: list[Relocation] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

@dataclass(slots=True)
class ExecutableModel:
    source_name: str
    input_kind: str
    executable_kind: str
    needs_decryption: bool
    endianness: str | None = None
    elf_header: ElfHeader | None = None
    program_headers: list[ProgramHeader] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    container_header: PspContainerHeader | None = None
    module_info: ModuleInfo | None = None
    imports: list[LibraryImport] = field(default_factory=list)
    exports: list[LibraryExport] = field(default_factory=list)
    relocations: list[Relocation] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class EngineInfo:
    name: str
    version: str


@dataclass(slots=True)
class InstructionRecord:
    address: int
    word: int
    text: str
    valid: bool
    implemented: bool


@dataclass(slots=True)
class FunctionRecord:
    name: str
    address: int
    size: int
    section: str
    assembly: str
    instruction_count: int
    instructions: list[InstructionRecord] = field(default_factory=list)


@dataclass(slots=True)
class SymbolRecord:
    name: str
    address: int
    section: str | None
    kind: str
    source: str


@dataclass(slots=True)
class ReferenceRecord:
    source_address: int
    target_address: int
    kind: str
    source_function: str | None
    target_section: str | None


@dataclass(slots=True)
class StringRecord:
    address: int
    value: str
    section: str
    referenced_by: list[int] = field(default_factory=list)


@dataclass(slots=True)
class AssemblySection:
    name: str
    address: int
    size: int
    assembly: str


@dataclass(slots=True)
class DisassemblyResult:
    source_name: str
    engines: list[EngineInfo] = field(default_factory=list)
    functions: list[FunctionRecord] = field(default_factory=list)
    symbols: list[SymbolRecord] = field(default_factory=list)
    references: list[ReferenceRecord] = field(default_factory=list)
    strings: list[StringRecord] = field(default_factory=list)
    assembly_sections: list[AssemblySection] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
