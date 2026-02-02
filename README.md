# FFmpeg Bindings for Zig

[Zig](https://ziglang.org/) API bindings for [FFmpeg](https://ffmpeg.org/).

This does not build FFmpeg or implicitly link with any of its libraries. It's just the bindings.

## How to use it

First, update your `build.zig.zon`:

```
zig fetch --save git+https://github.com/myQwil/ffmpeg#v7.0.1-8
```

Next, add this snippet to your `build.zig` script:

```zig
const av = b.dependency("ffmpeg", .{}).module("av");
my_module.addImport("av", av);
```
