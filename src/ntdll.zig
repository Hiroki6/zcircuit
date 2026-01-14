const std = @import("std");
const windows = std.os.windows;

const ImageDosSignature = 0x5A4D;
const ImageNtSignature = 0x00004550;
const PEB_LDR_DATA = windows.PEB_LDR_DATA;
const PEB = windows.PEB;
const TEB = windows.TEB;
const LDR_DATA_TABLE_ENTRY = windows.LDR_DATA_TABLE_ENTRY;
const PVOID = windows.PVOID;

pub const NtDll = struct {
    table_entry: *LDR_DATA_TABLE_ENTRY,
    export_directory: *ImageExportDirectory,

    pub fn init() ?NtDll {
        const teb = rtlGetThreadEnvironmentBlock();
        const peb = teb.ProcessEnvironmentBlock;
        if (peb.OSMajorVersion != 0xA) {
            return null;
        }
        const load_module = peb.Ldr.InMemoryOrderModuleList.Flink.Flink;
        const table_entry: *LDR_DATA_TABLE_ENTRY = @fieldParentPtr("InMemoryOrderLinks", load_module);
        const image_export_directory = getImageExportDirectory(table_entry.DllBase).?;
        return .{
            .table_entry = table_entry,
            .export_directory = image_export_directory,
        };
    }

    fn rtlGetThreadEnvironmentBlock() *TEB {
        if (@import("builtin").target.cpu.arch == .x86_64) {
            return @ptrFromInt(@as(usize, asm volatile ("mov %%gs:0x30, %[ret]"
                : [ret] "=r" (-> usize),
            )));
        } else {
            return @ptrFromInt(@as(usize, asm volatile ("mov %%fs:0x16, %[ret]"
                : [ret] "=r" (-> usize),
            )));
        }
    }

    fn getImageExportDirectory(module_base: PVOID) ?*ImageExportDirectory {
        const module_address = @intFromPtr(module_base);
        const dos = @as(*ImageDosHeader, @ptrCast(@alignCast(module_base)));
        if (dos.e_magic != ImageDosSignature) {
            return null;
        }
        const nt: *ImageNtHeaders64 = @ptrCast(@alignCast(@as(*u8, @ptrFromInt(module_address + @as(usize, @intCast(dos.e_lfanew))))));
        if (nt.Signature != ImageNtSignature) {
            return null;
        }
        if (nt.OptionalHeader.DataDirectory.len < 1) {
            return null;
        }

        const exportRva = nt.OptionalHeader.DataDirectory[0].VirtualAddress;
        if (exportRva == 0) {
            return null;
        }
        return @as(*ImageExportDirectory, @ptrFromInt(module_address + exportRva));
    }
};

const ImageDosHeader = extern struct {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [4]u16,
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [10]u16,
    e_lfanew: i32,
};

const ImageFileHeader = extern struct {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
};

const ImageDataDirectory = extern struct {
    VirtualAddress: u32,
    Size: u32,
};

const ImageOptionalHeader64 = extern struct {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]ImageDataDirectory,
};

const ImageNtHeaders64 = extern struct {
    Signature: u32,
    FileHeader: ImageFileHeader,
    OptionalHeader: ImageOptionalHeader64,
};

pub const ImageExportDirectory = extern struct {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    Name: u32,
    Base: u32,
    NumberOfFunctions: u32,
    NumberOfNames: u32,
    AddressOfFunctions: u32,
    AddressOfNames: u32,
    AddressOfNameOrdinals: u32,
};
