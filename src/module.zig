const std = @import("std");
const windows = std.os.windows;

const pe = @import("pe.zig");
const utils = @import("utils.zig");
const ImageDosSignature = 0x5A4D;
const ImageNtSignature = 0x00004550;
const PEB_LDR_DATA = windows.PEB_LDR_DATA;
const PEB = windows.PEB;
const TEB = windows.TEB;
const LDR_DATA_TABLE_ENTRY = windows.LDR_DATA_TABLE_ENTRY;
const PVOID = windows.PVOID;

pub const ModuleError = error{
    // Obfuscate enum strings
    E1, //UnsupportedWindowsVersion,
    E2, //InvalidPeHeader,
    E3, //ExportDirectoryNotFound,
    E4, //ModuleNotFound,
};

pub const Module = struct {
    table_entry: *LDR_DATA_TABLE_ENTRY,
    export_directory: *pe.ImageExportDirectory,

    pub fn init(dll_name_hash: u32, seed: u32) ModuleError!Module {
        const teb = rtlGetThreadEnvironmentBlock();
        const peb = teb.ProcessEnvironmentBlock;
        if (peb.OSMajorVersion != 0xA) {
            return ModuleError.E1;
        }

        const table_entry = try findModuleByHash(peb, dll_name_hash, seed);
        const image_export_directory = try getImageExportDirectory(table_entry.DllBase);
        return .{
            .table_entry = table_entry,
            .export_directory = image_export_directory,
        };
    }

    fn findModuleByHash(peb: *PEB, dll_name_hash: u32, seed: u32) ModuleError!*LDR_DATA_TABLE_ENTRY {
        var current = peb.Ldr.InMemoryOrderModuleList.Flink;
        var utf8_buffer: [257]u8 = undefined;

        while (@intFromPtr(current) != @intFromPtr(&peb.Ldr.InMemoryOrderModuleList)) {
            const entry: *LDR_DATA_TABLE_ENTRY = @fieldParentPtr("InMemoryOrderLinks", current);

            const base_name = entry.BaseDllName;
            const buffer = base_name.Buffer orelse {
                current = current.Flink;
                continue;
            };
            const entry_name_utf16 = buffer[0..(base_name.Length / 2)];

            const utf8_len = std.unicode.utf16LeToUtf8(&utf8_buffer, entry_name_utf16) catch {
                current = current.Flink;
                continue;
            };
            utf8_buffer[utf8_len] = 0;

            if (utils.crc32(@ptrCast(&utf8_buffer), seed) == dll_name_hash) {
                return entry;
            }

            current = current.Flink;
        }

        return ModuleError.E4;
    }

    fn rtlGetThreadEnvironmentBlock() *TEB {
        return @ptrFromInt(@as(usize, asm volatile ("mov %%gs:0x30, %[ret]"
            : [ret] "=r" (-> usize),
        )));
    }

    fn getImageExportDirectory(module_base: PVOID) ModuleError!*pe.ImageExportDirectory {
        const module_address = @intFromPtr(module_base);
        const dos = @as(*pe.ImageDosHeader, @ptrCast(@alignCast(module_base)));
        if (dos.e_magic != ImageDosSignature) {
            return ModuleError.E2;
        }
        const nt: *pe.ImageNtHeaders64 = @ptrCast(@alignCast(@as(*u8, @ptrFromInt(module_address + @as(usize, @intCast(dos.e_lfanew))))));
        if (nt.Signature != ImageNtSignature) {
            return ModuleError.E2;
        }
        if (nt.OptionalHeader.DataDirectory.len < 1) {
            return ModuleError.E3;
        }

        const exportRva = nt.OptionalHeader.DataDirectory[0].VirtualAddress;
        if (exportRva == 0) {
            return ModuleError.E3;
        }
        return @as(*pe.ImageExportDirectory, @ptrFromInt(module_address + exportRva));
    }
};
