const std = @import("std");
const Translator = @import("translate_c").Translator;

pub fn build(b: *std.Build) void {
	const target = b.standardTargetOptions(.{});
	const optimize = b.standardOptimizeOption(.{});

	const c: Translator = .init(b.dependency("translate_c", .{}), .{
		.c_source_file = b.path("src/av_all.h"),
		.target = target,
		.optimize = optimize,
	});
	c.addIncludePath(b.dependency("ffmpeg", .{}).path(""));

	_ = b.addModule("av", .{
		.root_source_file = b.path("src/av.zig"),
		.target = target,
		.optimize = optimize,
		.imports = &.{ .{ .name = "c", .module = c.mod } },
	});
}
