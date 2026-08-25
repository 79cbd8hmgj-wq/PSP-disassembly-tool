from __future__ import annotations

from dataclasses import dataclass
import importlib
from types import ModuleType

from ..errors import DisassemblyError, EngineUnavailableError
from ..model import (
    AssemblySection,
    DisassemblyResult,
    EngineInfo,
    ExecutableModel,
    FunctionRecord,
    InstructionRecord,
    ReferenceRecord,
    SymbolRecord,
    StringRecord,
    ElfImage,
    Section,
)


@dataclass(slots=True)
class EngineModules:
    spimdisasm: ModuleType
    rabbitizer: ModuleType


def load_engines() -> EngineModules:
    try:
        spimdisasm = importlib.import_module("spimdisasm")
        rabbitizer = importlib.import_module("rabbitizer")
    except ModuleNotFoundError as exc:
        raise EngineUnavailableError(
            "PSP instruction analysis requires the optional engines; install with "
            "`pip install 'pspdisasm[analysis]'`."
        ) from exc
    return EngineModules(spimdisasm=spimdisasm, rabbitizer=rabbitizer)


class SpimdisasmAdapter:
    def __init__(self, engines: EngineModules | None = None) -> None:
        self.engines = engines or load_engines()

    def analyze(self, elf: ElfImage, model: ExecutableModel) -> DisassemblyResult:
        spimdisasm = self.engines.spimdisasm
        rabbitizer = self.engines.rabbitizer
        common = spimdisasm.common
        mips = spimdisasm.mips

        mapped_sections = [section for section in elf.sections if section.addr and section.size]
        if not mapped_sections:
            return DisassemblyResult(
                source_name=model.source_name,
                engines=self._engine_info(),
                warnings=["ELF contains no mapped sections to analyze."],
            )

        context = common.Context()
        vram_start = min(section.addr for section in mapped_sections)
        vram_end = max(section.addr + section.size for section in mapped_sections)
        context.changeGlobalSegmentRanges(0, len(elf.raw_data), vram_start, vram_end)
        seed_addresses = self._seed_known_functions(context, elf, model)

        old_endian = common.GlobalConfig.ENDIAN
        old_abi = common.GlobalConfig.ABI
        common.GlobalConfig.ENDIAN = common.InputEndian.LITTLE
        common.GlobalConfig.ABI = common.Abi.O32

        functions: list[FunctionRecord] = []
        references: list[ReferenceRecord] = []
        assembly_sections: list[AssemblySection] = []
        warnings: list[str] = []
        try:
            for section in elf.sections:
                if section.kind != "executable" or section.size == 0:
                    continue
                analyzed_size = section.size - (section.size % 4)
                if analyzed_size != section.size:
                    warnings.append(
                        f"Executable section {section.name or section.index} has {section.size % 4} trailing byte(s) "
                        "that are not complete instructions."
                    )
                if analyzed_size == 0:
                    continue
                try:
                    text = mips.sections.SectionText(
                        context,
                        section.offset,
                        section.offset + analyzed_size,
                        section.addr,
                        section.name or f"section_{section.index}",
                        elf.raw_data,
                        0,
                        None,
                    )
                    text.instrCat = rabbitizer.InstrCategory.R4000ALLEGREX
                    text.analyze()
                except Exception as exc:  # upstream engine boundary
                    raise DisassemblyError(
                        f"spimdisasm failed while analyzing executable section "
                        f"{section.name or section.index} at 0x{section.addr:08X}: {exc}"
                    ) from exc

                section_assembly = text.disassemble()
                assembly_sections.append(
                    AssemblySection(
                        name=section.name or f"section_{section.index}",
                        address=section.addr,
                        size=analyzed_size,
                        assembly=section_assembly,
                    )
                )
                functions.extend(self._normalize_functions(text, section))
                references.extend(self._normalize_references(text, elf))
        finally:
            common.GlobalConfig.ENDIAN = old_endian
            common.GlobalConfig.ABI = old_abi

        functions.sort(key=lambda item: (item.address, item.name))
        references = self._deduplicate_references(references)
        symbols = self._normalize_symbols(context, elf, seed_addresses)
        strings = self._detect_strings(elf, references)
        assembly_sections.sort(key=lambda item: (item.address, item.name))
        return DisassemblyResult(
            source_name=model.source_name,
            engines=self._engine_info(),
            functions=functions,
            symbols=symbols,
            references=references,
            strings=strings,
            assembly_sections=assembly_sections,
            warnings=warnings,
        )

    def _engine_info(self) -> list[EngineInfo]:
        return [
            EngineInfo("spimdisasm", str(getattr(self.engines.spimdisasm, "__version__", "unknown"))),
            EngineInfo("rabbitizer", str(getattr(self.engines.rabbitizer, "__version__", "unknown"))),
        ]

    def _seed_known_functions(self, context, elf: ElfImage, model: ExecutableModel) -> set[int]:
        seeded: set[int] = set()
        entry = elf.header.entry
        if entry and self._find_section(elf, entry) is not None:
            vrom = elf.vaddr_to_offset(entry)
            context.globalSegment.addFunction(entry, isAutogenerated=False, vromAddress=vrom)
            seeded.add(entry)

        for library in [*model.imports, *model.exports]:
            for entry_record in library.functions:
                address = entry_record.address
                target_section = self._find_section(elf, address)
                if target_section is None or target_section.kind != "executable":
                    continue
                vrom = elf.vaddr_to_offset(address)
                context.globalSegment.addFunction(address, isAutogenerated=False, vromAddress=vrom)
                seeded.add(address)
        return seeded

    @staticmethod
    def _find_section(elf: ElfImage, address: int) -> Section | None:
        for section in elf.sections:
            if section.addr <= address < section.addr + section.size:
                return section
        return None



    @classmethod
    def _detect_strings(cls, elf: ElfImage, references: list[ReferenceRecord]) -> list[StringRecord]:
        by_address: dict[int, StringRecord] = {}
        for reference in references:
            if reference.kind not in {"data", "pointer"}:
                continue
            section = cls._find_section(elf, reference.target_address)
            if section is None or section.kind == "executable" or section.type == 8:
                continue
            value = cls._decode_referenced_string(elf, section, reference.target_address)
            if value is None:
                continue
            existing = by_address.get(reference.target_address)
            if existing is None:
                existing = StringRecord(
                    address=reference.target_address,
                    value=value,
                    section=section.name or f"section_{section.index}",
                )
                by_address[reference.target_address] = existing
            existing.referenced_by.append(reference.source_address)

        for record in by_address.values():
            record.referenced_by = sorted(set(record.referenced_by))
        return sorted(by_address.values(), key=lambda item: (item.address, item.value))

    @staticmethod
    def _decode_referenced_string(elf: ElfImage, section: Section, address: int) -> str | None:
        offset = elf.vaddr_to_offset(address)
        if offset is None:
            return None
        section_end = section.offset + section.size
        end_limit = min(section_end, offset + 256)
        terminator = elf.raw_data.find(b"\0", offset, end_limit)
        if terminator < 0 or terminator - offset < 4:
            return None
        raw = elf.raw_data[offset:terminator]
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if not value or not all(character.isprintable() for character in value):
            return None
        return value

    @classmethod
    def _normalize_references(cls, text, elf: ElfImage) -> list[ReferenceRecord]:
        records: list[ReferenceRecord] = []
        for function in text.symbolList:
            name = function.getNameUnquoted()
            analyzer = function.instrAnalyzer
            for local_offset, target in analyzer.funcCallInstrOffsets.items():
                records.append(cls._make_reference(function.vram + local_offset, target, "call", name, elf))
            for local_offset, target in analyzer.branchInstrOffsets.items():
                records.append(cls._make_reference(function.vram + local_offset, target, "branch", name, elf))
            for local_offset, target in analyzer.symbolInstrOffset.items():
                records.append(cls._make_reference(function.vram + local_offset, target, "data", name, elf))
        return records

    @classmethod
    def _make_reference(
        cls,
        source_address: int,
        target_address: int,
        kind: str,
        source_function: str,
        elf: ElfImage,
    ) -> ReferenceRecord:
        target_section = cls._find_section(elf, target_address)
        return ReferenceRecord(
            source_address=source_address,
            target_address=target_address,
            kind=kind,
            source_function=source_function,
            target_section=(target_section.name or f"section_{target_section.index}") if target_section else None,
        )

    @staticmethod
    def _deduplicate_references(records: list[ReferenceRecord]) -> list[ReferenceRecord]:
        unique: dict[tuple[int, int, str, str | None], ReferenceRecord] = {}
        for record in records:
            key = (record.source_address, record.target_address, record.kind, record.source_function)
            unique[key] = record
        return sorted(unique.values(), key=lambda item: (item.source_address, item.target_address, item.kind))

    @classmethod
    def _normalize_symbols(cls, context, elf: ElfImage, seed_addresses: set[int]) -> list[SymbolRecord]:
        records: list[SymbolRecord] = []
        for address, symbol in context.globalSegment.symbols.items():
            target_section = cls._find_section(elf, address)
            special = symbol.getTypeSpecial()
            if special is not None:
                type_name = symbol.getType().lstrip("@")
            elif target_section is not None and target_section.kind == "executable":
                type_name = "code"
            else:
                type_name = "data"
            if type_name == "branchlabel":
                type_name = "label"
            records.append(
                SymbolRecord(
                    name=symbol.getNameUnquoted(),
                    address=address,
                    section=(target_section.name or f"section_{target_section.index}") if target_section else None,
                    kind=type_name or "symbol",
                    source="phase1" if address in seed_addresses else "spimdisasm",
                )
            )
        records.sort(key=lambda item: (item.address, item.name, item.kind))
        return records

    @staticmethod
    def _normalize_functions(text, section: Section) -> list[FunctionRecord]:
        records: list[FunctionRecord] = []
        for function in text.symbolList:
            instructions = [
                InstructionRecord(
                    address=instruction.vram,
                    word=instruction.getRaw(),
                    text=instruction.disassemble(),
                    valid=instruction.isValid(),
                    implemented=instruction.isImplemented(),
                )
                for instruction in function.instructions
            ]
            records.append(
                FunctionRecord(
                    name=function.getNameUnquoted(),
                    address=function.vram,
                    size=function.sizew * 4,
                    section=section.name or f"section_{section.index}",
                    assembly=function.disassemble(),
                    instruction_count=len(instructions),
                    instructions=instructions,
                )
            )
        return records
