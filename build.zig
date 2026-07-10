const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const upstream = b.dependency("av", .{
        .target = target,
        .optimize = optimize,
    });

    const c_mod = blk: {
        const c = b.addTranslateC(.{
            .root_source_file = b.path("src/av_all.h"),
            .target = target,
            .optimize = optimize,
        });
        c.addIncludePath(upstream.path(""));
        break :blk c.createModule();
    };

    _ = b.addModule("av", .{
        .root_source_file = b.path("src/av.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "cdef", .module = c_mod }},
    });
}
