const std = @import("std");
const Crc32 = std.hash.crc.Crc32;
const testing = std.testing;

pub inline fn crc32(name: [*:0]const u8, seed: u32) u32 {
    var crc = Crc32.init();
    crc.crc = seed;
    const name_slice = std.mem.span(name);
    crc.update(name_slice);
    return crc.final();
}

test "CRC32 seed consistency" {
    const name = "NtAllocateVirtualMemory";
    const hash1 = crc32(name, 0x1234);
    const hash2 = crc32(name, 0x1234);
    const hash3 = crc32(name, 0x5678);

    try testing.expectEqual(hash1, hash2); // Same seed = same hash
    try testing.expect(hash1 != hash3); // Different seed = different hash
}
