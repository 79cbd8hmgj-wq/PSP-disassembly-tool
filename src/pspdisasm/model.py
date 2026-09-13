from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


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
class NidSymbol:
    library: str
    nid: int
    name: str
    kind: str
    source: str


@dataclass(slots=True)
class NidResolution:
    module: str
    library: str
    nid: int
    name: str
    kind: str
    address: int
    direction: str
    source: str


@dataclass(slots=True)
class ModuleLink:
    importing_module: str
    exporting_module: str
    library: str
    nid: int
    name: str
    kind: str
    import_address: int
    export_address: int
    name_source: str


@dataclass(slots=True)
class PropagatedSymbol:
    module: str
    address: int
    name: str
    kind: str
    library: str
    nid: int
    source: str
    confidence: float


@dataclass(slots=True)
class ModuleLinkAnalysis:
    modules: list[str] = field(default_factory=list)
    resolutions: list[NidResolution] = field(default_factory=list)
    links: list[ModuleLink] = field(default_factory=list)
    propagated_symbols: list[PropagatedSymbol] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


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
    source_segment_index: int | None = None
    target_segment_index: int | None = None
    stream_offset: int | None = None
    addend: int | None = None
    encoding_flags: int | None = None


@dataclass(slots=True)
class PrxAnalysis:
    module_info: ModuleInfo | None
    imports: list[LibraryImport] = field(default_factory=list)
    exports: list[LibraryExport] = field(default_factory=list)
    relocations: list[Relocation] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RecoveryProvenance:
    outcome: str
    original_sha256: str | None = None
    recovered_sha256: str | None = None
    recovery_backend: str | None = None
    backend_version: str | None = None
    verification: str | None = None
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
    recovery: RecoveryProvenance | None = None


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
class JumpTableRecord:
    address: int
    source_function: str
    source_address: int
    targets: list[int] = field(default_factory=list)


@dataclass(slots=True)
class CallGraphEdge:
    source_function: str
    target_function: str
    source_address: int
    target_address: int
    kind: str


@dataclass(slots=True)
class FunctionConfidence:
    name: str
    address: int
    score: float
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AdvancedAnalysisResult:
    source_name: str
    call_edges: list[CallGraphEdge] = field(default_factory=list)
    function_confidence: list[FunctionConfidence] = field(default_factory=list)
    jump_tables: list[JumpTableRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class TypedFieldRecord:
    offset: int
    type_name: str
    target_address: int | None
    confidence: float
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DataTypeRecord:
    address: int
    section: str
    type_name: str
    size: int
    target_address: int | None = None
    count: int | None = None
    element_type: str | None = None
    element_size: int | None = None
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    fields: list[TypedFieldRecord] = field(default_factory=list)


@dataclass(slots=True)
class TypedReferenceRecord:
    source_address: int
    target_address: int
    kind: str
    source_function: str | None
    target_section: str | None
    target_type: str
    confidence: float
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class TypedCallEdge:
    source_function: str
    target_function: str
    source_address: int
    target_address: int
    kind: str
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DataTypingResult:
    source_name: str
    data_types: list[DataTypeRecord] = field(default_factory=list)
    typed_references: list[TypedReferenceRecord] = field(default_factory=list)
    call_edges: list[TypedCallEdge] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AssetRecord:
    address: int
    file_offset: int
    section: str
    format: str
    kind: str
    size: int | None
    confidence: float
    evidence: list[str] = field(default_factory=list)
    extractable: bool = False
    suggested_extension: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class AssetReferenceRecord:
    source_address: int
    asset_address: int
    source_function: str | None
    reference_kind: str
    asset_format: str
    confidence: float
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AssetDiscoveryResult:
    source_name: str
    assets: list[AssetRecord] = field(default_factory=list)
    references: list[AssetReferenceRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


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
    jump_tables: list[JumpTableRecord] = field(default_factory=list)
    assembly_sections: list[AssemblySection] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DecompilationResult:
    project_dir: Path
    function_name: str
    function_address: int
    output_path: Path
    assembly_path: Path
    metadata_path: Path
    backend_name: str
    backend_version: str | None
    target: str
    warnings: list[str] = field(default_factory=list)
    unsupported_instructions: list[str] = field(default_factory=list)


class RuntimeAddressDomain(str, Enum):
    """The distinct address spaces Phase 8C runtime evidence moves between.

    Never collapse these into a bare int: RUNTIME is only ever produced by an
    actual PPSSPP observation, ANALYSIS is the space pspdisasm's own
    FunctionRecord/placement.load_address already uses, ELF_VIRTUAL is the
    original file's pre-placement vaddr, and MODULE_RELATIVE is an offset
    from one RuntimeModule's observed runtime base.
    """

    RUNTIME = "runtime"
    ANALYSIS = "analysis"
    ELF_VIRTUAL = "elf_virtual"
    MODULE_RELATIVE = "module_relative"


@dataclass(frozen=True, slots=True)
class RuntimeAddress:
    domain: str
    value: int
    module_path: str | None = None


@dataclass(slots=True)
class RuntimeSessionInfo:
    session_id: str
    host: str
    port: int
    ppsspp_revision: str | None = None
    workspace_source_identity: str | None = None


@dataclass(slots=True)
class RuntimeRegisterSnapshot:
    session_id: str
    sequence: int
    registers: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class RuntimeMemoryObservation:
    session_id: str
    sequence: int
    address: RuntimeAddress
    size: int
    sha256: str


@dataclass(slots=True)
class RuntimeBacktrace:
    session_id: str
    sequence: int
    frames: list[RuntimeAddress] = field(default_factory=list)


@dataclass(slots=True)
class RuntimeBreakpointObservation:
    session_id: str
    sequence: int
    breakpoint_address: RuntimeAddress
    hit_count: int
    registers: RuntimeRegisterSnapshot | None = None
    memory: list[RuntimeMemoryObservation] = field(default_factory=list)
    backtrace: RuntimeBacktrace | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RuntimeModule:
    name: str | None
    runtime_base: RuntimeAddress
    runtime_size: int | None
    static_module_path: str | None
    resolution_status: str
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RuntimeEvidenceSet:
    session: RuntimeSessionInfo
    modules: list[RuntimeModule] = field(default_factory=list)
    observations: list[RuntimeBreakpointObservation] = field(default_factory=list)


@dataclass(slots=True)
class RuntimeReconciliation:
    static_kind: str
    static_address: RuntimeAddress | None
    static_evidence: list[str]
    runtime_address: RuntimeAddress
    resolved_module_offset: RuntimeAddress | None
    observation_count: int
    status: str
    conflicts: list[str] = field(default_factory=list)
