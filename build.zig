const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zcircuit_mod = b.addModule("zcircuit", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const example_step = b.step("examples", "Build examples");
    for ([_][]const u8{
        "virtual_alloc",
    }) |example_name| {
        const example = b.addExecutable(.{
            .name = example_name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(b.fmt("examples/{s}.zig", .{example_name})),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "zcircuit", .module = zcircuit_mod },
                },
            }),
        });
        const install_example = b.addInstallArtifact(example, .{});
        example_step.dependOn(&example.step);
        example_step.dependOn(&install_example.step);
    }

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "zcircuit",
        .root_module = zcircuit_mod,
    });

    b.installArtifact(lib);
}
