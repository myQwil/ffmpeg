const std = @import("std");
const assert = std.debug.assert;

pub fn malloc(size: usize) error{OutOfMemory}![]u8 {
    const ptr = av_malloc(size) orelse return error.OutOfMemory;
    return ptr[0..size];
}
extern fn av_malloc(size: usize) ?[*]u8;

pub const free = av_free;
extern fn av_free(ptr: ?*anyopaque) void;

/// Undefined timestamp value.
///
/// Usually reported by demuxer that work on containers that do not provide
/// either pts or dts.
pub const nopts_value: i64 = @bitCast(@as(u64, 0x8000000000000000));

pub const Log = enum(c_int) {
    quiet = -8,
    panic = 0,
    fatal = 8,
    err = 16,
    warning = 24,
    info = 32,
    verbose = 40,
    debug = 48,
    trace = 56,

    pub fn setLevel(level: Log) void {
        av_log_set_level(level);
    }
    extern fn av_log_set_level(level: Log) void;
};

fn wrap(averror: c_int) Error!c_uint {
    if (averror >= 0) return @intCast(averror);
    const E = std.posix.E;
    return switch (averror) {
        0 => unreachable, // handled above

        -@as(c_int, @intFromEnum(E.INVAL)) => return error.FFmpegInvalid,
        -@as(c_int, @intFromEnum(E.NOENT)) => return error.FileNotFound,
        -@as(c_int, @intFromEnum(E.NOMEM)) => return error.OutOfMemory,
        -@as(c_int, @intFromEnum(E.PERM)) => return error.PermissionDenied,
        -@as(c_int, @intFromEnum(E.AGAIN)) => return error.WouldBlock,
        -@as(c_int, @intFromEnum(E.RANGE)) => return error.OutOfRange,

        @intFromEnum(ErrorCode.bsf_not_found) => return error.BsfNotFound,
        @intFromEnum(ErrorCode.bug) => return error.FFmpegBug,
        @intFromEnum(ErrorCode.bug2) => return error.FFmpegBug,
        @intFromEnum(ErrorCode.buffer_too_small) => return error.BufferTooSmall,
        @intFromEnum(ErrorCode.decoder_not_found) => return error.DecoderNotFound,
        @intFromEnum(ErrorCode.demuxer_not_found) => return error.DemuxerNotFound,
        @intFromEnum(ErrorCode.encoder_not_found) => return error.EncoderNotFound,
        @intFromEnum(ErrorCode.eof) => return error.EndOfFile,
        @intFromEnum(ErrorCode.exit) => return error.FFmpegExit,
        @intFromEnum(ErrorCode.external) => return error.FFmpegDependencyFailure,
        @intFromEnum(ErrorCode.unknown) => return error.FFmpegDependencyFailure,
        @intFromEnum(ErrorCode.filter_not_found) => return error.FilterNotFound,
        @intFromEnum(ErrorCode.invaliddata) => return error.InvalidData,
        @intFromEnum(ErrorCode.muxer_not_found) => return error.MuxerNotFound,
        @intFromEnum(ErrorCode.option_not_found) => return error.OptionNotFound,
        @intFromEnum(ErrorCode.patchwelcome) => return error.FFmpegUnimplemented,
        @intFromEnum(ErrorCode.protocol_not_found) => return error.ProtocolNotFound,
        @intFromEnum(ErrorCode.stream_not_found) => return error.StreamNotFound,
        @intFromEnum(ErrorCode.experimental) => return error.FFmpegExperimentalFeature,
        @intFromEnum(ErrorCode.input_changed) => unreachable, // not legal to use with wrap()
        @intFromEnum(ErrorCode.output_changed) => unreachable, // not legal to use with wrap()
        @intFromEnum(ErrorCode.http_bad_request) => return error.HttpBadRequest,
        @intFromEnum(ErrorCode.http_unauthorized) => return error.HttpUnauthorized,
        @intFromEnum(ErrorCode.http_forbidden) => return error.HttpForbidden,
        @intFromEnum(ErrorCode.http_not_found) => return error.HttpNotFound,
        @intFromEnum(ErrorCode.http_other_4xx) => return error.HttpOther4xx,
        @intFromEnum(ErrorCode.http_server_error) => return error.Http5xx,

        else => {
            std.log.debug("unexpected ffmpeg error code: {d}", .{averror});
            return error.Unexpected;
        },
    };
}

pub const Error = error{
    FileNotFound,
    OutOfMemory,
    PermissionDenied,
    OutOfRange,

    /// Bitstream filter not found
    BsfNotFound,
    /// Internal FFmpeg bug
    FFmpegBug,
    /// Usually indicates invalid API usage, which would have been an assertion
    /// rather than an error, but is also returned for input files that failed
    /// to demux or decode.
    FFmpegInvalid,
    BufferTooSmall,
    DecoderNotFound,
    DemuxerNotFound,
    EncoderNotFound,
    /// * The decoder has been flushed, and no new packets can be sent to it
    ///   (also returned if more than 1 flush packet is sent)
    /// * The codec has been fully flushed, and there will be no more output
    ///   frames.
    EndOfFile,
    /// Immediate exit was requested; the called function should not be restarted.
    FFmpegExit,
    /// Generic error in an external library.
    FFmpegDependencyFailure,
    FilterNotFound,
    /// Invalid data found when processing input
    InvalidData,
    MuxerNotFound,
    OptionNotFound,
    /// Not yet implemented in FFmpeg, patches welcome.
    FFmpegUnimplemented,
    ProtocolNotFound,
    StreamNotFound,
    /// Requested feature is flagged experimental. Set strict_std_compliance if you really want to use it.
    FFmpegExperimentalFeature,

    /// * input is not accepted in the current state - user must read output with
    ///   `Codec.Context.receive_frame` (once all output is read, the packet
    ///   should be resent, and the call will not fail with WouldBlock).
    /// * output is not available in this state - user must try to send new input.
    WouldBlock,

    HttpBadRequest,
    HttpUnauthorized,
    HttpForbidden,
    HttpNotFound,
    HttpOther4xx,
    Http5xx,

    /// FFmpeg returned an undocumented error code.
    Unexpected,
};

pub const ErrorCode = enum(c_int) {
    bsf_not_found = tag(0xF8, 'B', 'S', 'F'),
    bug = tag('B', 'U', 'G', '!'),
    buffer_too_small = tag('B', 'U', 'F', 'S'),
    decoder_not_found = tag(0xF8, 'D', 'E', 'C'),
    demuxer_not_found = tag(0xF8, 'D', 'E', 'M'),
    encoder_not_found = tag(0xF8, 'E', 'N', 'C'),
    eof = tag('E', 'O', 'F', ' '),
    exit = tag('E', 'X', 'I', 'T'),
    external = tag('E', 'X', 'T', ' '),
    filter_not_found = tag(0xF8, 'F', 'I', 'L'),
    invaliddata = tag('I', 'N', 'D', 'A'),
    muxer_not_found = tag(0xF8, 'M', 'U', 'X'),
    option_not_found = tag(0xF8, 'O', 'P', 'T'),
    patchwelcome = tag('P', 'A', 'W', 'E'),
    protocol_not_found = tag(0xF8, 'P', 'R', 'O'),
    stream_not_found = tag(0xF8, 'S', 'T', 'R'),
    bug2 = tag('B', 'U', 'G', ' '),
    unknown = tag('U', 'N', 'K', 'N'),
    experimental = -@as(i32, @bitCast(@as(u32, 0x2bb2afa8))),
    input_changed = -@as(i32, @bitCast(@as(u32, 0x636e6701))),
    output_changed = -@as(i32, @bitCast(@as(u32, 0x636e6702))),
    http_bad_request = tag(0xF8, '4', '0', '0'),
    http_unauthorized = tag(0xF8, '4', '0', '1'),
    http_forbidden = tag(0xF8, '4', '0', '3'),
    http_not_found = tag(0xF8, '4', '0', '4'),
    http_other_4xx = tag(0xF8, '4', 'X', 'X'),
    http_server_error = tag(0xF8, '5', 'X', 'X'),

    pub fn tag(a: u8, b: u8, c: u8, d: u8) i32 {
        const aw: u32 = a;
        const bw: u32 = b;
        const cw: u32 = c;
        const dw: u32 = d;
        const signed: i32 = (aw << 0) | (bw << 8) | (cw << 16) | (dw << 24);
        return -signed;
    }
};

/// Format I/O context.
///
/// New fields can be added to the end with minor version bumps.
/// Removal, reordering and changes to existing fields require a major
/// version bump.
/// `@sizeOf(FormatContext)` must not be used outside libav*, use
/// `FormatContext.alloc` to create a `FormatContext`.
///
/// Fields can be accessed through AVOptions (av_opt*),
/// the name string used matches the associated command line parameter name and
/// can be found in libavformat/options_table.h.
/// The AVOption/command line parameter names differ in some cases from the C
/// structure field names for historic reasons or brevity.
pub const FormatContext = extern struct {
    /// A class for logging and @ref avoptions. Set by
    /// avformat_alloc_context(). Exports (de)muxer private options if they
    /// exist.
    av_class: *const Class,

    /// The input container format.
    ///
    /// Demuxing only, set by `open_input`.
    iformat: *const InputFormat,

    /// The output container format.
    ///
    /// Muxing only, must be set by the caller before avformat_write_header().
    oformat: *const OutputFormat,

    /// Format private data. This is an AVOptions-enabled struct
    /// if and only if iformat/oformat.priv_class is not NULL.
    ///
    /// - muxing: set by avformat_write_header()
    /// - demuxing: set by `open_input`
    priv_data: ?*anyopaque,

    /// I/O context.
    ///
    /// - demuxing: either set by the user before `open_input` (then
    ///             the user must close it manually) or set by `open_input`.
    /// - muxing: set by the user before avformat_write_header(). The caller must
    ///           take care of closing / freeing the IO context.
    ///
    /// Do NOT set this field if AVFMT_NOFILE flag is set in
    /// iformat/oformat.flags. In such a case, the (de)muxer will handle
    /// I/O in some other way and this field will be NULL.
    pb: ?*IOContext,

    /// Flags signalling stream properties. A combination of AVFMTCTX_*.
    /// Set by libavformat.
    ctx_flags: c_int,

    /// Number of elements in AVFormatContext.streams.
    ///
    /// Set by avformat_new_stream(), must not be modified by any other code.
    nb_streams: c_uint,
    /// A list of all streams in the file. New streams are created with
    /// avformat_new_stream().
    ///
    /// - demuxing: streams are created by libavformat in `open_input`.
    ///             If AVFMTCTX_NOHEADER is set in ctx_flags, then new streams may also
    ///             appear in av_read_frame().
    /// - muxing: streams are created by the user before avformat_write_header().
    ///
    /// Freed by libavformat in avformat_free_context().
    streams: [*]*Stream,

    /// Number of elements in `stream_groups`.
    ///
    /// Set by avformat_stream_group_create(); must not be modified by any other code.
    nb_stream_groups: c_uint,
    /// A list of all stream groups in the file.
    ///
    /// New groups are created with avformat_stream_group_create(), and filled
    /// with avformat_stream_group_add_stream().
    ///
    /// - demuxing: groups may be created by libavformat in avformat_open_input().
    ///             If AVFMTCTX_NOHEADER is set in ctx_flags, then new groups may also
    ///             appear in av_read_frame().
    /// - muxing: groups may be created by the user before avformat_write_header().
    ///
    /// Freed by libavformat in `free`.
    stream_groups: [*]*StreamGroup,

    /// Number of chapters in `Chapter` array.
    /// When muxing, chapters are normally written in the file header,
    /// so nb_chapters should normally be initialized before write_header
    /// is called. Some muxers (e.g. mov and mkv) can also write chapters
    /// in the trailer.  To write chapters in the trailer, nb_chapters
    /// must be zero when write_header is called and non-zero when
    /// write_trailer is called.
    /// - muxing: set by user
    /// - demuxing: set by libavformat
    nb_chapters: c_uint,
    chapters: [*]*Chapter,

    /// input or output URL. Unlike the old filename field, this field has no
    /// length restriction.
    ///
    /// - demuxing: set by `open_input`, initialized to an empty
    ///             string if url parameter was NULL in `open_input`.
    /// - muxing: may be set by the caller before calling avformat_write_header()
    ///           (or avformat_init_output() if that is called first) to a string
    ///           which is freeable by av_free(). Set to an empty string if it
    ///           was NULL in avformat_init_output().
    ///
    /// Freed by libavformat in avformat_free_context().
    url: [*:0]u8,

    /// Position of the first frame of the component, in
    /// AV_TIME_BASE fractional seconds. NEVER set this value directly:
    /// It is deduced from the AVStream values.
    ///
    /// Demuxing only, set by libavformat.
    start_time: i64,

    /// Duration of the stream, in AV_TIME_BASE fractional
    /// seconds. Only set this value if you know none of the individual stream
    /// durations and also do not set any of them. This is deduced from the
    /// AVStream values if not set.
    ///
    /// Demuxing only, set by libavformat.
    duration: i64,

    /// Total stream bitrate in bit/s, 0 if not
    /// available. Never set it directly if the file_size and the
    /// duration are known as FFmpeg can compute it automatically.
    bit_rate: i64,

    packet_size: c_uint,
    max_delay: c_int,

    /// Flags modifying the (de)muxer behaviour. A combination of AVFMT_FLAG_*.
    /// Set by the user before `open_input` / avformat_write_header().
    flags: c_int,
    /// Maximum number of bytes read from input in order to determine stream
    /// properties. Used when reading the global header and in
    /// avformat_find_stream_info().
    ///
    /// Demuxing only, set by the caller before `open_input`.
    ///
    /// @note this is \e not  used for determining the \ref AVInputFormat
    ///       "input format"
    /// @sa format_probesize
    probesize: i64,
    /// Maximum duration (in AV_TIME_BASE units) of the data read
    /// from input in avformat_find_stream_info().
    /// Demuxing only, set by the caller before avformat_find_stream_info().
    /// Can be set to 0 to let avformat choose using a heuristic.
    max_analyze_duration: i64,
    key: [*]const u8,
    keylen: c_int,
    nb_programs: c_uint,
    programs: [*]*Program,
    /// Forced video codec_id.
    /// Demuxing: Set by user.
    video_codec_id: Codec.ID,
    /// Forced audio codec_id.
    /// Demuxing: Set by user.
    audio_codec_id: Codec.ID,
    /// Forced subtitle codec_id.
    /// Demuxing: Set by user.
    subtitle_codec_id: Codec.ID,
    /// Forced Data codec_id.
    /// Demuxing: Set by user.
    data_codec_id: Codec.ID,
    /// Metadata that applies to the whole file.
    ///
    /// - demuxing: set by libavformat in `open_input`
    /// - muxing: may be set by the caller before avformat_write_header()
    ///
    /// Freed by libavformat in avformat_free_context().
    metadata: Dictionary.Mutable,
    /// Start time of the stream in real world time, in microseconds
    /// since the Unix epoch (00:00 1st January 1970). That is, pts=0 in the
    /// stream was captured at this real world time.
    /// - muxing: Set by the caller before avformat_write_header(). If set to
    ///           either 0 or AV_NOPTS_VALUE, then the current wall-time will
    ///           be used.
    /// - demuxing: Set by libavformat. AV_NOPTS_VALUE if unknown. Note that
    ///             the value may become known after some number of frames
    ///             have been received.
    start_time_realtime: i64,
    /// The number of frames used for determining the framerate in
    /// avformat_find_stream_info().
    /// Demuxing only, set by the caller before avformat_find_stream_info().
    fps_probe_size: c_int,
    /// Error recognition; higher values will detect more errors but may
    /// misdetect some more or less valid parts as errors.
    /// Demuxing only, set by the caller before `open_input`.
    error_recognition: c_int,
    /// Custom interrupt callbacks for the I/O layer.
    ///
    /// demuxing: set by the user before `open_input`.
    /// muxing: set by the user before avformat_write_header()
    /// (mainly useful for AVFMT_NOFILE formats). The callback
    /// should also be passed to avio_open2() if it's used to
    /// open the file.
    interrupt_callback: IOInterruptCB,
    /// Flags to enable debugging.
    debug: c_int,
    /// The maximum number of streams.
    /// - encoding: unused
    /// - decoding: set by user
    max_streams: c_int,
    /// Maximum amount of memory in bytes to use for the index of each stream.
    /// If the index exceeds this size, entries will be discarded as
    /// needed to maintain a smaller size. This can lead to slower or less
    /// accurate seeking (depends on demuxer).
    /// Demuxers for which a full in-memory index is mandatory will ignore
    /// this.
    /// - muxing: unused
    /// - demuxing: set by user
    max_index_size: c_uint,
    /// Maximum amount of memory in bytes to use for buffering frames
    /// obtained from realtime capture devices.
    max_picture_buffer: c_uint,
    /// Maximum buffering duration for interleaving.
    ///
    /// To ensure all the streams are interleaved correctly,
    /// av_interleaved_write_frame() will wait until it has at least one packet
    /// for each stream before actually writing any packets to the output file.
    /// When some streams are "sparse" (i.e. there are large gaps between
    /// successive packets), this can result in excessive buffering.
    ///
    /// This field specifies the maximum difference between the timestamps of the
    /// first and the last packet in the muxing queue, above which libavformat
    /// will output a packet regardless of whether it has queued a packet for all
    /// the streams.
    ///
    /// Muxing only, set by the caller before avformat_write_header().
    max_interleave_delta: i64,
    /// Maximum number of packets to read while waiting for the first timestamp.
    /// Decoding only.
    max_ts_probe: c_int,
    /// Max chunk time in microseconds.
    /// Note, not all formats support this and unpredictable things may happen if it is used when not supported.
    /// - encoding: Set by user
    /// - decoding: unused
    max_chunk_duration: c_int,
    /// Max chunk size in bytes
    /// Note, not all formats support this and unpredictable things may happen if it is used when not supported.
    /// - encoding: Set by user
    /// - decoding: unused
    max_chunk_size: c_int,
    /// Maximum number of packets that can be probed
    /// - encoding: unused
    /// - decoding: set by user
    max_probe_packets: c_int,
    /// Allow non-standard and experimental extension
    /// See `Codec.Context.strict_std_compliance`
    strict_std_compliance: c_int,
    /// Flags indicating events happening on the file, a combination of
    /// AVFMT_EVENT_FLAG_*.
    ///
    /// - demuxing: may be set by the demuxer in `open_input`,
    ///   avformat_find_stream_info() and av_read_frame(). Flags must be cleared
    ///   by the user once the event has been handled.
    /// - muxing: may be set by the user after avformat_write_header() to
    ///   indicate a user-triggered event.  The muxer will clear the flags for
    ///   events it has handled in av_[interleaved]_write_frame().
    event_flags: c_int,
    /// Avoid negative timestamps during muxing.
    /// Any value of the AVFMT_AVOID_NEG_TS_* constants.
    /// Note, this works better when using av_interleaved_write_frame().
    /// - muxing: Set by user
    /// - demuxing: unused
    avoid_negative_ts: c_int,
    /// Audio preload in microseconds.
    /// Note, not all formats support this and unpredictable things may happen if it is used when not supported.
    /// - encoding: Set by user
    /// - decoding: unused
    audio_preload: c_int,
    /// forces the use of wallclock timestamps as pts/dts of packets
    /// This has undefined results in the presence of B frames.
    /// - encoding: unused
    /// - decoding: Set by user
    use_wallclock_as_timestamps: c_int,
    /// Skip duration calcuation in estimate_timings_from_pts.
    /// - encoding: unused
    /// - decoding: set by user
    skip_estimate_duration_from_pts: c_int,
    /// used to force AVIO_FLAG_DIRECT.
    /// - encoding: unused
    /// - decoding: Set by user
    avio_flags: c_int,
    /// The duration field can be estimated through various ways, and this field can be used
    /// to know how the duration was estimated.
    /// - encoding: unused
    /// - decoding: Read by user
    duration_estimation_method: DurationEstimationMethod,
    /// Skip initial bytes when opening stream
    /// - encoding: unused
    /// - decoding: Set by user
    skip_initial_bytes: i64,
    /// Correct single timestamp overflows
    /// - encoding: unused
    /// - decoding: Set by user
    correct_ts_overflow: c_uint,
    /// Force seeking to any (also non key) frames.
    /// - encoding: unused
    /// - decoding: Set by user
    seek2any: c_int,
    /// Flush the I/O context after each packet.
    /// - encoding: Set by user
    /// - decoding: unused
    flush_packets: c_int,
    /// format probing score.
    ///
    /// The maximal score is AVPROBE_SCORE_MAX, its set when the demuxer probes
    /// the format.
    /// - encoding: unused
    /// - decoding: set by avformat, read by user
    probe_score: c_int,
    /// Maximum number of bytes read from input in order to identify the
    /// \ref AVInputFormat "input format". Only used when the format is not set
    /// explicitly by the caller.
    ///
    /// Demuxing only, set by the caller before `open_input`.
    ///
    /// @sa probesize
    format_probesize: c_int,
    /// ',' separated list of allowed decoders.
    /// If NULL then all are allowed
    /// - encoding: unused
    /// - decoding: set by user
    codec_whitelist: [*:0]u8,
    /// ',' separated list of allowed demuxers.
    /// If NULL then all are allowed
    /// - encoding: unused
    /// - decoding: set by user
    format_whitelist: [*:0]u8,
    /// ',' separated list of allowed protocols.
    /// - encoding: unused
    /// - decoding: set by user
    protocol_whitelist: [*:0]u8,
    /// ',' separated list of disallowed protocols.
    /// - encoding: unused
    /// - decoding: set by user
    protocol_blacklist: [*:0]u8,
    /// IO repositioned flag.
    /// This is set by avformat when the underlaying IO context read pointer
    /// is repositioned, for example when doing byte based seeking.
    /// Demuxers can use the flag to detect such changes.
    io_repositioned: c_int,
    /// Forced video codec.
    ///
    /// This allows forcing a specific decoder, even when there are multiple with
    /// the same codec_id.
    /// Demuxing: Set by user
    video_codec: *const Codec,
    /// Forced audio codec.
    ///
    /// This allows forcing a specific decoder, even when there are multiple with
    /// the same codec_id.
    /// Demuxing: Set by user
    audio_codec: *const Codec,
    /// Forced subtitle codec.
    ///
    /// This allows forcing a specific decoder, even when there are multiple with
    /// the same codec_id.
    /// Demuxing: Set by user
    subtitle_codec: *const Codec,
    /// Forced data codec.
    ///
    /// This allows forcing a specific decoder, even when there are multiple with
    /// the same codec_id.
    /// Demuxing: Set by user
    data_codec: *const Codec,
    /// Number of bytes to be written as padding in a metadata header.
    ///
    /// Demuxing: Unused.
    /// Muxing: Set by user via av_format_set_metadata_header_padding.
    metadata_header_padding: c_int,
    /// User data.
    /// This is a place for some private data of the user.
    @"opaque": ?*anyopaque,
    /// Callback used by devices to communicate with application.
    control_message_cb: FormatControlMessage,
    /// Output timestamp offset, in microseconds.
    /// Muxing: set by user
    output_ts_offset: i64,
    /// dump format separator.
    /// can be ", " or "\n      " or anything else
    /// - muxing: Set by user.
    /// - demuxing: Set by user.
    dump_separator: *u8,
    /// A callback for opening new IO streams.
    ///
    /// Whenever a muxer or a demuxer needs to open an IO stream (typically from
    /// `open_input` for demuxers, but for certain formats can happen at
    /// other times as well), it will call this callback to obtain an IO context.
    ///
    /// @param s the format context
    /// @param pb on success, the newly opened IO context should be returned here
    /// @param url the url to open
    /// @param flags a combination of AVIO_FLAG_*
    /// @param options a dictionary of additional options, with the same
    ///                semantics as in avio_open2()
    /// @return 0 on success, a negative AVERROR code on failure
    ///
    /// @note Certain muxers and demuxers do nesting, i.e. they open one or more
    /// additional internal format contexts. Thus the AVFormatContext pointer
    /// passed to this callback may be different from the one facing the caller.
    /// It will, however, have the same 'opaque' field.
    io_open: ?*const fn (*FormatContext, **IOContext, [*]const u8, c_int, *Dictionary.Mutable) callconv(.c) c_int,
    /// A callback for closing the streams opened with AVFormatContext.io_open().
    ///
    /// Using this is preferred over io_close, because this can return an error.
    /// Therefore this callback is used instead of io_close by the generic
    /// libavformat code if io_close is NULL or the default.
    ///
    /// @param s the format context
    /// @param pb IO context to be closed and freed
    /// @return 0 on success, a negative AVERROR code on failure
    io_close2: ?*const fn (*FormatContext, *IOContext) callconv(.c) c_int,

    /// `free` can be used to free the context and everything
    /// allocated by the framework within it.
    pub fn alloc() error{OutOfMemory}!*FormatContext {
        return avformat_alloc_context() orelse return error.OutOfMemory;
    }
    extern fn avformat_alloc_context() ?*FormatContext;

    // Free a `FormatContext` and all its streams.
    pub const free = avformat_free_context;
    extern fn avformat_free_context(?*FormatContext) void;

    /// Open an input stream and read the header.
    ///
    /// The codecs are not opened. The stream must be closed with
    /// `close_input`.
    pub fn init(
        /// URL of the stream to open.
        url: [*:0]const u8,
        /// If non-NULL, this parameter forces a specific input format.
        /// Otherwise the format is autodetected.
        fmt: ?*const InputFormat,
        /// A dictionary filled with `FormatContext` and demuxer-private
        /// options.
        ///
        /// On return this parameter will be destroyed and replaced with
        /// a dict containing options that were not found. May be NULL.
        options: ?*Dictionary.Mutable,
        pb: ?*IOContext,
    ) Error!*FormatContext {
        var ps: ?*FormatContext = try alloc();
        ps.?.pb = pb;
        // avformat_open_input takes ownership of the allocation.
        _ = try wrap(avformat_open_input(&ps, url, fmt, options));
        return ps.?;
    }
    extern fn avformat_open_input(ps: *?*FormatContext, url: [*:0]const u8, fmt: ?*const InputFormat, options: ?*Dictionary.Mutable) c_int;

    /// Close an opened input `FormatContext`. Free it and all its contents.
    pub fn deinit(s: *FormatContext) void {
        var keep_your_dirty_hands_off_my_pointers_ffmpeg: ?*FormatContext = s;
        avformat_close_input(&keep_your_dirty_hands_off_my_pointers_ffmpeg);
    }
    extern fn avformat_close_input(s: *?*FormatContext) void;

    /// Read packets of a media file to get stream information.
    ///
    /// This is useful for file formats with no headers such as MPEG. This
    /// function also computes the real framerate in case of MPEG-2 repeat
    /// frame mode.
    ///
    /// The logical file position is not changed by this function; examined
    /// packets may be buffered for later processing.
    ///
    /// This function isn't guaranteed to open all the codecs, so
    /// options being non-empty at return is a perfectly normal behavior.
    ///
    /// Does not let the user decide somehow what information is needed;
    /// sometimes wastes time getting stuff the user does not need.
    pub fn findStreamInfo(
        ic: *FormatContext,
        /// If non-NULL, an ic.nb_streams long array of pointers to
        /// dictionaries, where i-th member contains options for codec
        /// corresponding to i-th stream.
        ///
        /// On return each dictionary will be filled with options that were not found.
        options: ?[*]Dictionary.Mutable,
    ) Error!void {
        _ = try wrap(avformat_find_stream_info(ic, options));
    }
    extern fn avformat_find_stream_info(ic: *FormatContext, options: ?[*]Dictionary.Mutable) c_int;

    /// Find the "best" stream in the file.
    ///
    /// The best stream is determined according to various heuristics as the most
    /// likely to be what the user expects.
    ///
    /// If the decoder parameter is non-NULL, `find_best_stream` will find the
    /// default decoder for the stream's codec; streams for which no decoder can
    /// be found are ignored.
    ///
    /// Returns the non-negative stream number in case of success,
    /// AVERROR_STREAM_NOT_FOUND if no stream with the requested type could be
    /// found, AVERROR_DECODER_NOT_FOUND if streams were found but no decoder
    ///
    pub fn findBestStream(
        ic: *FormatContext,
        /// stream type: video, audio, subtitles, etc.
        media_type: MediaType,
        /// user-requested stream number, or -1 for automatic selection
        wanted_stream_nb: c_int,
        /// try to find a stream related (eg. in the same program) to this one,
        /// or -1 if none
        related_stream: c_int,
    ) Error!struct { c_uint, *const Codec } {
        var decoder: ?*const Codec = undefined;
        const n = try wrap(av_find_best_stream(ic, media_type, wanted_stream_nb, related_stream, &decoder, 0));
        return .{ n, decoder.? };
    }
    extern fn av_find_best_stream(
        ic: *FormatContext,
        media_type: MediaType,
        wanted_stream_nb: c_int,
        related_stream: c_int,
        decoder_ret: ?*?*const Codec,
        flags: c_int,
    ) c_int;

    /// Return the next frame of a stream.
    ///
    /// This function returns what is stored in the file, and does not validate
    /// that what is there are valid frames for the decoder. It will split what
    /// is stored in the file into frames and return one for each call. It will
    /// not omit invalid data between valid frames so as to give the decoder
    /// the maximum information possible for decoding.
    ///
    /// On success, the returned packet is reference-counted (pkt->buf is set)
    /// and valid indefinitely. The packet must be freed with av_packet_unref()
    /// when it is no longer needed. For video, the packet contains exactly one
    /// frame. For audio, it contains an integer number of frames if each frame
    /// has a known fixed size (e.g. PCM or ADPCM data). If the audio frames
    /// have a variable size (e.g. MPEG audio), then it contains one frame.
    ///
    /// pkt->pts, pkt->dts and pkt->duration are always set to correct values
    /// in `Stream.time_base` units (and guessed if the format cannot provide
    /// them). pkt->pts can be `NOPTS_VALUE` if the video format has B-frames,
    /// so it is better to rely on pkt->dts if you do not decompress the
    /// payload.
    ///
    /// Returns 0 if OK, < 0 on error or end of file. On error, pkt will be
    /// blank (as if it came from `Packet.alloc`).
    ///
    /// `pkt` will be initialized, so it may be uninitialized, but it must not
    /// contain data that needs to be freed.
    pub fn readFrame(s: *FormatContext, pkt: *Packet) Error!void {
        _ = try wrap(av_read_frame(s, pkt));
    }
    extern fn av_read_frame(s: *FormatContext, pkt: *Packet) c_int;

    pub const SeekFlags = packed struct(c_int) {
        /// this flag is ignored.
        backward: bool = false,
        /// all timestamps are in bytes and are the file position
        /// (this may not be supported by all demuxers).
        byte: bool = false,
        /// non-keyframes are treated as keyframes
        /// (this may not be supported by all demuxers).
        any: bool = false,
        /// all timestamps are in frames
        /// in the stream with stream_index (this may not be supported by all demuxers).
        /// Otherwise all timestamps are in units of the stream selected by stream_index
        /// or if stream_index is -1, in AV_TIME_BASE units.
        frame: bool = false,
        unused: std.meta.Int(.unsigned, @bitSizeOf(c_int) - 4) = 0,
    };

    /// Seek to timestamp ts.
    ///
    /// Seeking will be done so that the point from which all active streams
    /// can be presented successfully will be closest to ts and within min/max_ts.
    /// Active streams are all streams that have AVStream.discard < AVDISCARD_ALL.
    ///
    /// note: This is part of the new seek API which is still under construction.
    pub fn seekFile(
        /// media file handle
        ic: *FormatContext,
        /// index of the stream which is used as time base reference
        stream_index: c_int,
        /// smallest acceptable timestamp
        min_ts: i64,
        /// target timestamp
        ts: i64,
        /// largest acceptable timestamp
        max_ts: i64,
        /// direction and seeking mode
        flags: SeekFlags,
    ) Error!void {
        _ = try wrap(avformat_seek_file(ic, stream_index, min_ts, ts, max_ts, @bitCast(flags)));
    }
    extern fn avformat_seek_file(ic: *FormatContext, stream_index: c_int, min_ts: i64, ts: i64, max_ts: i64, flags: c_int) c_int;

    /// Seek to the keyframe at timestamp in the specified stream.
    pub fn seekFrame(
        /// media file handle
        s: *FormatContext,
        /// If stream_index is (-1), a default stream is selected, and
        /// timestamp is automatically converted from AV_TIME_BASE units to the
        /// stream specific time_base.
        stream_index: c_int,
        /// In AVStream.time_base units or, if no stream is specified, in
        /// AV_TIME_BASE units.
        timestamp: i64,
        /// select direction and seeking mode
        flags: SeekFlags,
    ) Error!void {
        _ = try wrap(av_seek_frame(s, stream_index, timestamp, @bitCast(flags)));
    }
    extern fn av_seek_frame(s: *FormatContext, stream_index: c_int, timestamp: i64, flags: c_int) c_int;

    /// Discard all internally buffered data. This can be useful when dealing with
    /// discontinuities in the byte stream. Generally works only with formats that
    /// can resync. This includes headerless formats like MPEG-TS/TS but should also
    /// work with NUT, Ogg and in a limited way AVI for example.
    ///
    /// The set of streams, the detected duration, stream parameters and codecs do
    /// not change when calling this function. If you want a complete reset, it's
    /// better to open a new `FormatContext`.
    ///
    /// This does not flush the `IOContext` (s->pb). If necessary, call
    /// avio_flush(s->pb) before calling this function.
    ///
    /// @return >=0 on success, error code otherwise
    pub fn flush(s: *FormatContext) Error!void {
        _ = try wrap(avformat_flush(s));
    }
    extern fn avformat_flush(s: *FormatContext) c_int;

    /// Print detailed information about the input or output format, such as
    /// duration, bitrate, streams, container, programs, metadata, side data,
    /// codec and time base.
    pub const dump = av_dump_format;
    extern fn av_dump_format(ic: *FormatContext, index: c_uint, url: ?[*:0]const u8, is_output: enum(c_int) { input, output }) void;
};

pub const Class = extern struct {
    class_name: [*c]const u8,
    item_name: ?*const fn (?*anyopaque) callconv(.c) [*c]const u8,
    option: ?*const Option,
    version: c_int,
    log_level_offset_offset: c_int,
    parent_log_context_offset: c_int,
    category: ClassCategory,
    get_category: ?*const fn (?*anyopaque) callconv(.c) ClassCategory,
    query_ranges: ?*const fn ([*c]?*OptionRanges, ?*anyopaque, [*c]const u8, c_int) callconv(.c) c_int,
    child_next: ?*const fn (?*anyopaque, ?*anyopaque) callconv(.c) ?*anyopaque,
    child_class_iterate: ?*const fn ([*c]?*anyopaque) callconv(.c) [*c]const Class,

    pub const Option = opaque {};
};

pub const InputFormat = extern struct {
    name: [*c]const u8,
    long_name: [*c]const u8,
    flags: c_int,
    extensions: [*c]const u8,
    codec_tag: [*c]const ?*const CodecTag,
    priv_class: [*c]const Class,
    mime_type: [*c]const u8,
    raw_codec_id: c_int,
    priv_data_size: c_int,
    flags_internal: c_int,
    read_probe: ?*const fn ([*c]const ProbeData) callconv(.c) c_int,
    read_header: ?*const fn ([*c]FormatContext) callconv(.c) c_int,
    read_packet: ?*const fn ([*c]FormatContext, [*c]Packet) callconv(.c) c_int,
    read_close: ?*const fn ([*c]FormatContext) callconv(.c) c_int,
    read_seek: ?*const fn ([*c]FormatContext, c_int, i64, c_int) callconv(.c) c_int,
    read_timestamp: ?*const fn ([*c]FormatContext, c_int, [*c]i64, i64) callconv(.c) i64,
    read_play: ?*const fn ([*c]FormatContext) callconv(.c) c_int,
    read_pause: ?*const fn ([*c]FormatContext) callconv(.c) c_int,
    read_seek2: ?*const fn ([*c]FormatContext, c_int, i64, i64, i64, c_int) callconv(.c) c_int,
    get_device_list: ?*const fn ([*c]FormatContext, ?*DeviceInfoList) callconv(.c) c_int,
};

pub const OutputFormat = extern struct {
    name: [*c]const u8,
    long_name: [*c]const u8,
    mime_type: [*c]const u8,
    extensions: [*c]const u8,
    audio_codec: Codec.ID,
    video_codec: Codec.ID,
    subtitle_codec: Codec.ID,
    flags: c_int,
    codec_tag: [*c]const ?*const CodecTag,
    priv_class: [*c]const Class,
};

pub const IOContext = extern struct {
    av_class: *const Class,
    buffer: [*]u8,
    buffer_size: c_int,
    buf_ptr: [*]u8,
    buf_end: [*]u8,
    @"opaque": ?*anyopaque,
    read_packet: ?*const fn (?*anyopaque, [*c]u8, c_int) callconv(.c) c_int,
    write_packet: ?*const fn (?*anyopaque, [*c]const u8, c_int) callconv(.c) c_int,
    seek: ?*const fn (?*anyopaque, i64, Seek) callconv(.c) i64,
    pos: i64,
    eof_reached: c_int,
    @"error": c_int,
    write_flag: c_int,
    max_packet_size: c_int,
    min_packet_size: c_int,
    checksum: c_ulong,
    checksum_ptr: [*c]u8,
    update_checksum: ?*const fn (c_ulong, [*c]const u8, c_uint) callconv(.c) c_ulong,
    read_pause: ?*const fn (?*anyopaque, c_int) callconv(.c) c_int,
    read_seek: ?*const fn (?*anyopaque, c_int, i64, c_int) callconv(.c) i64,
    seekable: c_int,
    direct: c_int,
    protocol_whitelist: [*c]const u8,
    protocol_blacklist: [*c]const u8,
    write_data_type: ?*const fn (?*anyopaque, [*c]const u8, c_int, IODataMarkerType, i64) callconv(.c) c_int,
    ignore_boundary_point: c_int,
    buf_ptr_max: [*c]u8,
    bytes_read: i64,
    bytes_written: i64,

    pub const WriteFlag = enum(c_int) {
        read_only = 0,
        writable = 1,
    };

    /// Allocate and initialize an `IOContext` for buffered I/O. It must be later
    /// freed with `free`.
    pub fn alloc(
        /// Memory block for input/output operations via AVIOContext.
        /// The buffer must be allocated with av_malloc() and friends.
        /// It may be freed and replaced with a new buffer by libavformat.
        /// `IOContext.buffer` holds the buffer currently in use,
        /// which must be later freed with av_free().
        ///
        /// The buffer size is very important for performance.
        /// For protocols with fixed blocksize it should be set to this blocksize.
        /// For others a typical size is a cache page, e.g. 4kb.
        buffer: []u8,
        /// Whether the buffer should be writable.
        write_flag: WriteFlag,
        /// An opaque pointer to user-specific data.
        userdata: ?*anyopaque,
        /// A function for refilling the buffer.
        ///
        /// For stream protocols, must never return 0 but rather a proper AVERROR code.
        read_packet: ?*const fn (?*anyopaque, [*:0]u8, c_int) callconv(.c) c_int,
        /// A function for writing the buffer contents.
        ///
        /// The function may not change the input buffers content.
        write_packet: ?*const fn (?*anyopaque, [*:0]u8, c_int) callconv(.c) c_int,
        /// A function for seeking to specified byte position.
        seek: ?*const fn (?*anyopaque, i64, Seek) callconv(.c) i64,
    ) error{OutOfMemory}!*IOContext {
        return avio_alloc_context(
            buffer.ptr,
            @intCast(buffer.len),
            write_flag,
            userdata,
            read_packet,
            write_packet,
            seek,
        ) orelse return error.OutOfMemory;
    }
    extern fn avio_alloc_context(
        buffer: [*c]u8,
        buffer_size: c_int,
        write_flag: IOContext.WriteFlag,
        @"opaque": ?*anyopaque,
        read_packet: ?*const fn (?*anyopaque, [*:0]u8, c_int) callconv(.c) c_int,
        write_packet: ?*const fn (?*anyopaque, [*:0]u8, c_int) callconv(.c) c_int,
        seek: ?*const fn (?*anyopaque, i64, Seek) callconv(.c) i64,
    ) [*c]IOContext;

    pub fn free(ioc: *IOContext) void {
        var keep_your_dirty_hands_off_my_pointers_ffmpeg: ?*IOContext = ioc;
        avio_context_free(&keep_your_dirty_hands_off_my_pointers_ffmpeg);
    }
    extern fn avio_context_free(s: *?*IOContext) void;

    /// Close the resource accessed by the IOContext s and free it.
    ///
    /// This function can only be used if s was opened by avio_open().
    ///
    /// The internal buffer is automatically flushed before closing the
    /// resource.
    pub fn close(s: *IOContext) Error!void {
        _ = try wrap(avio_close(s));
    }
    extern fn avio_close(s: ?*IOContext) c_int;
};

pub const Stream = extern struct {
    av_class: *const Class,
    index: c_int,
    id: c_int,
    codecpar: *Codec.Parameters,
    priv_data: ?*anyopaque,
    time_base: Rational,
    start_time: i64,
    duration: i64,
    nb_frames: i64,
    disposition: c_int,
    discard: Discard,
    sample_aspect_ratio: Rational,
    metadata: Dictionary.Mutable,
    avg_frame_rate: Rational,
    attached_pic: Packet,
    side_data: [*]PacketSideData,
    nb_side_data: c_int,
    event_flags: c_int,
    r_frame_rate: Rational,
    pts_wrap_bits: c_int,
};

pub const Program = extern struct {
    id: c_int,
    flags: c_int,
    discard: Discard,
    stream_index: [*]c_uint,
    nb_stream_indexes: c_uint,
    metadata: Dictionary.Mutable,
    program_num: c_int,
    pmt_pid: c_int,
    pcr_pid: c_int,
    pmt_version: c_int,
    start_time: i64,
    end_time: i64,
    pts_wrap_reference: i64,
    pts_wrap_behavior: c_int,
};

pub const Chapter = extern struct {
    id: i64,
    time_base: Rational,
    start: i64,
    end: i64,
    metadata: Dictionary.Mutable,
};

pub const Dictionary = opaque {
    pub const Const = extern struct {
        dict: ?*const Dictionary,

        pub const empty: Const = .{ .dict = null };

        /// Get a dictionary entry with matching key.
        ///
        /// The returned entry key or value must not be changed, or it will
        /// cause undefined behavior.
        pub const get = av_dict_get;
        extern fn av_dict_get(m: Dictionary.Const, key: [*:0]const u8, prev: ?*const Dictionary.Entry, flags: Dictionary.Flags) ?*const Dictionary.Entry;

        /// Iterates through all entries in the dictionary.
        ///
        /// The returned `Entry` key/value must not be changed.
        ///
        /// As set() invalidates all previous entries returned by this function,
        /// it must not be called while iterating over the dict.
        pub const iterate = av_dict_iterate;
        extern fn av_dict_iterate(m: Dictionary.Const, prev: ?*const Dictionary.Entry) ?*const Dictionary.Entry;

        /// Get number of entries in dictionary.
        pub const count = av_dict_count;
        extern fn av_dict_count(m: Dictionary.Const) c_int;

        /// Free all the memory allocated for an Dictionary struct and all keys
        /// and values.
        pub fn free(dict: Const) void {
            var keep_your_dirty_hands_off_my_pointers_ffmpeg = dict;
            av_dict_free(&keep_your_dirty_hands_off_my_pointers_ffmpeg);
        }
        extern fn av_dict_free(pm: *Dictionary.Const) void;
    };

    pub const Mutable = extern struct {
        dict: ?*Dictionary,

        pub const empty: Mutable = .{ .dict = null };

        pub fn toConst(dict: Mutable) Const {
            return .{ .dict = dict.dict };
        }

        /// Get a dictionary entry with matching key.
        ///
        /// The returned entry key or value must not be changed, or it will
        /// cause undefined behavior.
        pub fn get(dict: Mutable, key: [*:0]const u8, prev: ?*const Entry, flags: Flags) ?*const Entry {
            return dict.toConst().get(key, prev, flags);
        }

        /// Iterates through all entries in the dictionary.
        ///
        /// The returned `Entry` key/value must not be changed.
        ///
        /// As set() invalidates all previous entries returned by this function,
        /// it must not be called while iterating over the dict.
        pub fn iterate(dict: Mutable, prev: ?*const Entry) ?*const Entry {
            return dict.toConst().iterate(prev);
        }

        /// Get number of entries in dictionary.
        pub fn count(dict: Mutable) c_int {
            return dict.toConst().count();
        }

        /// Set the given entry in *pm, overwriting an existing entry.
        ///
        /// If DONT_STRDUP_KEY or DONT_STRDUP_VAL is set, these arguments will be
        /// freed on error.
        ///
        /// Adding a new entry to a dictionary invalidates all existing entries
        /// previously returned with get() or iterate().
        pub fn set(dict: *Mutable, key: [*:0]const u8, value: ?[*:0]const u8, flags: Flags) error{OutOfMemory}!void {
            _ = wrap(av_dict_set(dict, key, value, flags)) catch |err| switch (err) {
                error.FFmpegInvalid => unreachable, // Zig prevents this by not making `key` nullable.
                error.OutOfMemory => |e| return e,
                else => unreachable, // I checked the source code, those are the only possible errors.
            };
        }
        extern fn av_dict_set(pm: *Dictionary.Mutable, key: [*:0]const u8, value: ?[*:0]const u8, flags: Dictionary.Flags) c_int;

        /// Set the given entry in *pm, overwriting an existing entry.
        ///
        /// If DONT_STRDUP_KEY or DONT_STRDUP_VAL is set, these arguments will be
        /// freed on error.
        ///
        /// Adding a new entry to a dictionary invalidates all existing entries
        /// previously returned with get() or iterate().
        pub fn setInt(dict: *Mutable, key: [*:0]const u8, value: i64, flags: Flags) error{OutOfMemory}!void {
            _ = wrap(av_dict_set_int(dict, key, value, flags)) catch |err| switch (err) {
                error.FFmpegInvalid => unreachable, // Zig prevents this by not making `key` nullable.
                error.OutOfMemory => |e| return e,
                else => unreachable, // I checked the source code, those are the only possible errors.
            };
        }
        extern fn av_dict_set_int(pm: *Dictionary.Mutable, key: [*:0]const u8, value: i64, flags: Dictionary.Flags) c_int;

        pub fn copy(dst: *Mutable, src: Const, flags: Flags) error{OutOfMemory}!void {
            _ = wrap(av_dict_copy(dst, src, flags)) catch |err| switch (err) {
                error.OutOfMemory => |e| return e,
                else => unreachable, // I checked the source code, those are the only possible errors.
            };
        }
        extern fn av_dict_copy(dst: *Dictionary.Mutable, src: Dictionary.Const, flags: Dictionary.Flags) void;

        /// Free all the memory allocated for an Dictionary struct and all keys
        /// and values.
        pub fn free(dict: Mutable) void {
            dict.toConst().free();
        }
    };

    /// Flags that influence behavior of the matching of keys or insertion to the dictionary.
    pub const Flags = packed struct(c_int) {
        /// Only get an entry with exact-case key match. Only relevant in get().
        match_case: bool = false,
        /// Return first entry in a dictionary whose first part corresponds to
        /// the search key.
        ignore_suffix: bool = false,
        /// Take ownership of a key that's been allocated with av_malloc() or
        /// another memory allocation function.
        dont_strdup_key: bool = false,
        /// Take ownership of a value that's been allocated with av_malloc() or
        /// another memory allocation function.
        dont_strdup_val: bool = false,
        /// Don't overwrite existing entries.
        dont_overwrite: bool = false,
        /// If the entry already exists, append to it.  Note that no delimiter
        /// is added, the strings are simply concatenated.
        append: bool = false,
        /// Allow to store several equal keys in the dictionary.
        multikey: bool = false,
        unused: std.meta.Int(.unsigned, @bitSizeOf(c_int) - 7) = 0,
    };

    pub const Entry = extern struct {
        key: [*:0]u8,
        value: [*:0]u8,
    };
};

pub const IOInterruptCB = extern struct {
    callback: ?*const fn (?*anyopaque) callconv(.c) c_int,
    @"opaque": ?*anyopaque,
};

pub const DurationEstimationMethod = enum(c_uint) {
    pts = 0,
    stream = 1,
    bitrate = 2,
};

pub const FormatControlMessage = ?*const fn ([*c]FormatContext, c_int, ?*anyopaque, usize) callconv(.c) c_int;

pub const ClassCategory = enum(c_uint) {
    na = 0,
    input = 1,
    output = 2,
    muxer = 3,
    demuxer = 4,
    encoder = 5,
    decoder = 6,
    filter = 7,
    bitstream_filter = 8,
    swscaler = 9,
    swresampler = 10,
    device_video_output = 40,
    device_video_input = 41,
    device_audio_output = 42,
    device_audio_input = 43,
    device_output = 44,
    device_input = 45,
};

pub const OptionRanges = opaque {};
pub const CodecTag = opaque {};

pub const ProbeData = extern struct {
    filename: [*c]const u8,
    buf: [*c]u8,
    buf_size: c_int,
    mime_type: [*c]const u8,
};

pub const Packet = extern struct {
    buf: *BufferRef,
    pts: i64,
    dts: i64,
    data: [*]u8,
    size: c_int,
    stream_index: c_int,
    flags: c_int,
    side_data: [*]PacketSideData,
    side_data_elems: c_int,
    duration: i64,
    pos: i64,
    @"opaque": ?*anyopaque,
    opaque_ref: *BufferRef,
    time_base: Rational,

    pub fn init() error{OutOfMemory}!*Packet {
        return av_packet_alloc() orelse return error.OutOfMemory;
    }
    extern fn av_packet_alloc() ?*Packet;

    pub fn deinit(p: *Packet) void {
        var keep_your_dirty_hands_off_my_pointers_ffmpeg: ?*Packet = p;
        av_packet_free(&keep_your_dirty_hands_off_my_pointers_ffmpeg);
    }
    extern fn av_packet_free(pkt: *?*Packet) void;

    pub fn ref(dst: *Packet, src: *const Packet) Error!void {
        _ = try wrap(av_packet_ref(dst, src));
    }
    extern fn av_packet_ref(dst: *Packet, src: *const Packet) c_int;

    /// Wipe the packet.
    ///
    /// Unreference the buffer referenced by the packet and reset the
    /// remaining packet fields to their default values.
    pub const unref = av_packet_unref;
    extern fn av_packet_unref(pkt: *Packet) void;
};

pub const DeviceInfoList = opaque {};

pub const IODataMarkerType = enum(c_uint) {
    header = 0,
    sync_point = 1,
    boundary_point = 2,
    unknown = 3,
    trailer = 4,
    flush_point = 5,
};

pub const Rational = extern struct {
    num: c_int,
    den: c_int,

    pub fn q2d(a: Rational) f64 {
        const num: f64 = @floatFromInt(a.num);
        const den: f64 = @floatFromInt(a.den);
        return num / den;
    }
};

pub const Discard = enum(c_int) {
    none = -16,
    default = 0,
    nonref = 8,
    bidir = 16,
    nonintra = 24,
    nonkey = 32,
    all = 48,
};

pub const PacketSideData = extern struct {
    data: [*c]u8,
    size: usize,
    type: PacketSideDataType,
};

pub const MediaType = enum(c_int) {
    unknown = -1,
    video = 0,
    audio = 1,
    data = 2,
    subtitle = 3,
    attachment = 4,
};

pub const PixelFormat = enum(c_int) {
    none = -1,
    yuv420p = 0,
    yuyv422 = 1,
    rgb24 = 2,
    bgr24 = 3,
    yuv422p = 4,
    yuv444p = 5,
    yuv410p = 6,
    yuv411p = 7,
    gray8 = 8,
    monowhite = 9,
    monoblack = 10,
    pal8 = 11,
    yuvj420p = 12,
    yuvj422p = 13,
    yuvj444p = 14,
    uyvy422 = 15,
    uyyvyy411 = 16,
    bgr8 = 17,
    bgr4 = 18,
    bgr4_byte = 19,
    rgb8 = 20,
    rgb4 = 21,
    rgb4_byte = 22,
    nv12 = 23,
    nv21 = 24,
    argb = 25,
    rgba = 26,
    abgr = 27,
    bgra = 28,
    gray16be = 29,
    gray16le = 30,
    yuv440p = 31,
    yuvj440p = 32,
    yuva420p = 33,
    rgb48be = 34,
    rgb48le = 35,
    rgb565be = 36,
    rgb565le = 37,
    rgb555be = 38,
    rgb555le = 39,
    bgr565be = 40,
    bgr565le = 41,
    bgr555be = 42,
    bgr555le = 43,
    vaapi = 44,
    yuv420p16le = 45,
    yuv420p16be = 46,
    yuv422p16le = 47,
    yuv422p16be = 48,
    yuv444p16le = 49,
    yuv444p16be = 50,
    dxva2_vld = 51,
    rgb444le = 52,
    rgb444be = 53,
    bgr444le = 54,
    bgr444be = 55,
    /// y400a = 56,
    /// gray8a = 56,
    ya8 = 56,
    bgr48be = 57,
    bgr48le = 58,
    yuv420p9be = 59,
    yuv420p9le = 60,
    yuv420p10be = 61,
    yuv420p10le = 62,
    yuv422p10be = 63,
    yuv422p10le = 64,
    yuv444p9be = 65,
    yuv444p9le = 66,
    yuv444p10be = 67,
    yuv444p10le = 68,
    yuv422p9be = 69,
    yuv422p9le = 70,
    /// gbr24p = 71,
    gbrp = 71,
    gbrp9be = 72,
    gbrp9le = 73,
    gbrp10be = 74,
    gbrp10le = 75,
    gbrp16be = 76,
    gbrp16le = 77,
    yuva422p = 78,
    yuva444p = 79,
    yuva420p9be = 80,
    yuva420p9le = 81,
    yuva422p9be = 82,
    yuva422p9le = 83,
    yuva444p9be = 84,
    yuva444p9le = 85,
    yuva420p10be = 86,
    yuva420p10le = 87,
    yuva422p10be = 88,
    yuva422p10le = 89,
    yuva444p10be = 90,
    yuva444p10le = 91,
    yuva420p16be = 92,
    yuva420p16le = 93,
    yuva422p16be = 94,
    yuva422p16le = 95,
    yuva444p16be = 96,
    yuva444p16le = 97,
    vdpau = 98,
    xyz12le = 99,
    xyz12be = 100,
    nv16 = 101,
    nv20le = 102,
    nv20be = 103,
    rgba64be = 104,
    rgba64le = 105,
    bgra64be = 106,
    bgra64le = 107,
    yvyu422 = 108,
    ya16be = 109,
    ya16le = 110,
    gbrap = 111,
    gbrap16be = 112,
    gbrap16le = 113,
    qsv = 114,
    mmal = 115,
    d3d11va_vld = 116,
    cuda = 117,
    @"0rgb" = 118,
    rgb0 = 119,
    @"0bgr" = 120,
    bgr0 = 121,
    yuv420p12be = 122,
    yuv420p12le = 123,
    yuv420p14be = 124,
    yuv420p14le = 125,
    yuv422p12be = 126,
    yuv422p12le = 127,
    yuv422p14be = 128,
    yuv422p14le = 129,
    yuv444p12be = 130,
    yuv444p12le = 131,
    yuv444p14be = 132,
    yuv444p14le = 133,
    gbrp12be = 134,
    gbrp12le = 135,
    gbrp14be = 136,
    gbrp14le = 137,
    yuvj411p = 138,
    bayer_bggr8 = 139,
    bayer_rggb8 = 140,
    bayer_gbrg8 = 141,
    bayer_grbg8 = 142,
    bayer_bggr16le = 143,
    bayer_bggr16be = 144,
    bayer_rggb16le = 145,
    bayer_rggb16be = 146,
    bayer_gbrg16le = 147,
    bayer_gbrg16be = 148,
    bayer_grbg16le = 149,
    bayer_grbg16be = 150,
    xvmc = 151,
    yuv440p10le = 152,
    yuv440p10be = 153,
    yuv440p12le = 154,
    yuv440p12be = 155,
    ayuv64le = 156,
    ayuv64be = 157,
    videotoolbox = 158,
    p010le = 159,
    p010be = 160,
    gbrap12be = 161,
    gbrap12le = 162,
    gbrap10be = 163,
    gbrap10le = 164,
    mediacodec = 165,
    gray12be = 166,
    gray12le = 167,
    gray10be = 168,
    gray10le = 169,
    p016le = 170,
    p016be = 171,
    d3d11 = 172,
    gray9be = 173,
    gray9le = 174,
    gbrpf32be = 175,
    gbrpf32le = 176,
    gbrapf32be = 177,
    gbrapf32le = 178,
    drm_prime = 179,
    opencl = 180,
    gray14be = 181,
    gray14le = 182,
    grayf32be = 183,
    grayf32le = 184,
    yuva422p12be = 185,
    yuva422p12le = 186,
    yuva444p12be = 187,
    yuva444p12le = 188,
    nv24 = 189,
    nv42 = 190,
    vulkan = 191,
    y210be = 192,
    y210le = 193,
    x2rgb10le = 194,
    x2rgb10be = 195,
    x2bgr10le = 196,
    x2bgr10be = 197,
    p210be = 198,
    p210le = 199,
    p410be = 200,
    p410le = 201,
    p216be = 202,
    p216le = 203,
    p416be = 204,
    p416le = 205,
    vuya = 206,
    rgbaf16be = 207,
    rgbaf16le = 208,
    vuyx = 209,
    p012le = 210,
    p012be = 211,
    y212be = 212,
    y212le = 213,
    xv30be = 214,
    xv30le = 215,
    xv36be = 216,
    xv36le = 217,
    rgbf32be = 218,
    rgbf32le = 219,
    rgbaf32be = 220,
    rgbaf32le = 221,
    p212be = 222,
    p212le = 223,
    p412be = 224,
    p412le = 225,
    gbrap14be = 226,
    gbrap14le = 227,
};

pub const SampleFormat = enum(c_int) {
    none = -1,
    u8 = 0,
    s16 = 1,
    s32 = 2,
    flt = 3,
    dbl = 4,
    u8p = 5,
    s16p = 6,
    s32p = 7,
    fltp = 8,
    dblp = 9,
    s64 = 10,
    s64p = 11,

    /// Return the name of sample_fmt, or NULL if sample_fmt is not recognized.
    pub const getName = av_get_sample_fmt_name;
    extern fn av_get_sample_fmt_name(sample_fmt: SampleFormat) ?[*:0]const u8;

    /// Return number of bytes per sample, or zero if unknown.
    pub const getBytesPerSample = av_get_bytes_per_sample;
    extern fn av_get_bytes_per_sample(sample_fmt: SampleFormat) c_int;

    /// Check if the sample format is planar.
    ///
    /// @param sample_fmt the sample format to inspect
    /// @return 1 if the sample format is planar, 0 if it is interleaved
    pub fn isPlanar(sample_fmt: SampleFormat) bool {
        return av_sample_fmt_is_planar(sample_fmt) != 0;
    }
    extern fn av_sample_fmt_is_planar(sample_fmt: SampleFormat) c_int;
};

pub const Profile = extern struct {
    profile: c_int,
    name: ?[*:0]const u8,
};

/// A set of channels ordered in a specific way.
///
/// If the channel order is AV_CHANNEL_ORDER_UNSPEC, this struct carries only
/// the channel count.
///
/// All orders may be treated as if they were AV_CHANNEL_ORDER_UNSPEC by
/// ignoring everything but the channel count, as long as `check` considers
/// they are valid.
///
/// Unlike most structures in FFmpeg, `@sizeOf(ChannelLayout)` is a part of the
/// public ABI and may be used by the caller. E.g. it may be allocated on stack
/// or embedded in caller-defined structs.
///
/// Can be initialized as follows:
/// - default initialization with {0}, followed by setting all used fields
///   correctly;
/// - by assigning one of the predefined AV_CHANNEL_LAYOUT_* initializers;
/// - with a constructor function, such as `default`, `from_mask` or
///   `from_string`.
///
/// The channel layout must be unitialized with `uninit`.
///
/// Copying a `ChannelLayout` via assigning is forbidden; `copy` must be used
/// instead.
///
/// No new fields may be added to it without a major version bump, except for
/// new elements of the union fitting in `@sizeOf(u64)`.
pub const ChannelLayout = extern struct {
    /// This is a mandatory field.
    order: ChannelOrder,
    /// Number of channels in this layout. Mandatory field.
    nb_channels: c_uint,
    /// Details about which channels are present in this layout.
    ///
    /// For `ChannelOrder.UNSPEC`, this field is undefined and must not be
    /// used.
    u: extern union {
        /// This member must be used for `ChannelOrder.NATIVE`, and may be used
        /// for `ChannelOrder.AMBISONIC` to signal non-diegetic channels.
        ///
        /// It is a bitmask, where the position of each set bit means that the
        /// AVChannel with the corresponding value is present.
        ///
        /// I.e. when (mask & (1 << AV_CHAN_FOO)) is non-zero, then AV_CHAN_FOO
        /// is present in the layout. Otherwise it is not present.
        ///
        /// When a channel layout using a bitmask is constructed or
        /// modified manually (i.e.  not using any of the av_channel_layout_*
        /// functions), the code doing it must ensure that the number of set
        /// bits is equal to nb_channels.
        mask: u64,

        /// This member must be used when the channel order is
        /// `ChannelOrder.CUSTOM`. It is a `nb_channels`-sized array, with each
        /// element signalling the presence of the `Channel` with the
        /// corresponding value in map[i].id.
        ///
        /// I.e. when map[i].id is equal to AV_CHAN_FOO, then AV_CH_FOO is the
        /// i-th channel in the audio data.
        ///
        /// When map[i].id is in the range between `Channel.AMBISONIC_BASE` and
        /// `Channel.AMBISONIC_END` (inclusive), the channel contains an ambisonic
        /// component with ACN index (as defined above)
        /// `n = map[i].id - Channel.AMBISONIC_BASE`.
        ///
        /// map[i].name may be filled with a 0-terminated string, in which case
        /// it will be used for the purpose of identifying the channel with the
        /// convenience functions below. Otherise it must be zeroed.
        map: [*]ChannelCustom,
    },
    /// For some private data of the user.
    @"opaque": ?*anyopaque,

    /// Check whether two channel layouts are semantically the same.
    ///
    /// i.e. the same channels are present on the same positions in both.
    ///
    /// If one of the channel layouts is `ChannelOrder.UNSPEC`, while the other
    /// is not, they are considered to be unequal. If both are
    /// `ChannelOrder.UNSPEC`, they are considered equal iff the channel counts
    /// are the same in both.
    ///
    /// Returns true if and only if they are equal.
    ///
    /// Asserts both channels are valid.
    /// @return 0 if chl and chl1 are equal, 1 if they are not equal. A negative
    ///         AVERROR code if one or both are invalid.
    pub fn compare(a: *const ChannelLayout, b: *const ChannelLayout) bool {
        return switch (av_channel_layout_compare(a, b)) {
            0 => true,
            1 => false,
            else => unreachable, // invalid channel layout
        };
    }
    extern fn av_channel_layout_compare(a: *const ChannelLayout, b: *const ChannelLayout) c_int;

    /// Free any allocated data in the channel layout and reset the channel
    /// count to 0.
    pub const uninit = av_channel_layout_uninit;
    extern fn av_channel_layout_uninit(channel_layout: *ChannelLayout) void;

    /// Get a human-readable string describing the channel layout properties.
    ///
    /// The string will be in the same format that is accepted by
    /// `from_string`, allowing to rebuild the same channel layout, except for
    /// opaque pointers.
    ///
    /// Asserts the channel layout is valid and `buf` is large enough to store
    /// the result.
    pub fn describe(
        cl: *const ChannelLayout,
        /// Pre-allocated buffer where to put the generated string.
        buf: []u8,
    ) [:0]u8 {
        const rc = av_channel_layout_describe(cl, buf.ptr, buf.len);
        std.debug.assert(rc >= 0); // invalid channel layout
        std.debug.assert(rc <= buf.len); // buffer too small
        return buf[0..@intCast(rc - 1) :0];
    }
    extern fn av_channel_layout_describe(channel_layout: *const ChannelLayout, buf: [*]u8, buf_size: usize) c_int;

    /// Initialize a native channel layout from a bitmask indicating which
    /// channels are present.
    pub fn setMask(
        /// The layout structure to be initialized.
        channel_layout: *ChannelLayout,
        /// Bitmask describing the channel layout.
        mask: u64,
    ) error{FFmpegInvalid}!void {
        if (av_channel_layout_from_mask(channel_layout, mask) != 0) {
            return error.FFmpegInvalid;
        }
    }
    extern fn av_channel_layout_from_mask(channel_layout: *ChannelLayout, mask: u64) c_int;

    /// Initialize a native channel layout from a bitmask indicating which
    /// channels are present.
    pub fn fromMask(mask: u64) error{FFmpegInvalid}!ChannelLayout {
        var channel_layout: ChannelLayout = undefined;
        try channel_layout.setMask(mask);
        return channel_layout;
    }

    /// Set to the default channel layout for a given number of channels.
    pub fn setDefault(
        /// The layout structure to be initialized.
        ch_layout: *ChannelLayout,
        /// The number of channels.
        nb_channels: c_uint,
    ) void {
        av_channel_layout_default(ch_layout, nb_channels);
    }
    extern fn av_channel_layout_default(channel_layout: *ChannelLayout, nb_channels: c_uint) void;

    /// Get the default channel layout for a given number of channels.
    pub fn default(nb_channels: c_uint) ChannelLayout {
        var ch_layout: ChannelLayout = undefined;
        ch_layout.setDefault(nb_channels);
        return ch_layout;
    }
};

pub const BufferRef = extern struct {
    buffer: ?*Buffer,
    data: [*]u8,
    size: usize,
};

pub const FieldOrder = enum(c_uint) {
    unknown = 0,
    progressive = 1,
    tt = 2,
    bb = 3,
    tb = 4,
    bt = 5,
};

pub const ColorRange = enum(c_uint) {
    unspecified = 0,
    mpeg = 1,
    jpeg = 2,
};

pub const ColorPrimaries = enum(c_uint) {
    reserved0 = 0,
    bt709 = 1,
    unspecified = 2,
    reserved = 3,
    bt470m = 4,
    bt470bg = 5,
    smpte170m = 6,
    smpte240m = 7,
    film = 8,
    bt2020 = 9,
    /// smptest428_1 = 10,
    smpte428 = 10,
    smpte431 = 11,
    smpte432 = 12,
    /// jedec_p22 = 22,
    ebu3213 = 22,
};

pub const ColorTransferCharacteristic = enum(c_uint) {
    reserved0 = 0,
    bt709 = 1,
    unspecified = 2,
    reserved = 3,
    gamma22 = 4,
    gamma28 = 5,
    smpte170m = 6,
    smpte240m = 7,
    linear = 8,
    log = 9,
    log_sqrt = 10,
    iec61966_2_4 = 11,
    bt1361_ecg = 12,
    iec61966_2_1 = 13,
    bt2020_10 = 14,
    bt2020_12 = 15,
    /// smptest2084 = 16,
    smpte2084 = 16,
    /// smptest428_1 = 17,
    smpte428 = 17,
    arib_std_b67 = 18,
};

pub const ColorSpace = enum(c_uint) {
    rgb = 0,
    bt709 = 1,
    unspecified = 2,
    reserved = 3,
    fcc = 4,
    bt470bg = 5,
    smpte170m = 6,
    smpte240m = 7,
    /// ycocg = 8,
    ycgco = 8,
    bt2020_ncl = 9,
    bt2020_cl = 10,
    smpte2085 = 11,
    chroma_derived_ncl = 12,
    chroma_derived_cl = 13,
    ictcp = 14,
};

pub const ChromaLocation = enum(c_uint) {
    unspecified = 0,
    left = 1,
    center = 2,
    topleft = 3,
    top = 4,
    bottomleft = 5,
    bottom = 6,
};

pub const PacketSideDataType = enum(c_uint) {
    palette = 0,
    new_extradata = 1,
    param_change = 2,
    h263_mb_info = 3,
    replaygain = 4,
    displaymatrix = 5,
    stereo3d = 6,
    audio_service_type = 7,
    quality_stats = 8,
    fallback_track = 9,
    cpb_properties = 10,
    skip_samples = 11,
    jp_dualmono = 12,
    strings_metadata = 13,
    subtitle_position = 14,
    matroska_blockadditional = 15,
    webvtt_identifier = 16,
    webvtt_settings = 17,
    metadata_update = 18,
    mpegts_stream_id = 19,
    mastering_display_metadata = 20,
    spherical = 21,
    content_light_level = 22,
    a53_cc = 23,
    encryption_init_info = 24,
    encryption_info = 25,
    afd = 26,
    prft = 27,
    icc_profile = 28,
    dovi_conf = 29,
    s12m_timecode = 30,
    dynamic_hdr10_plus = 31,
};

pub const ChannelOrder = enum(c_uint) {
    unspec = 0,
    native = 1,
    custom = 2,
    ambisonic = 3,
};

pub const ChannelCustom = extern struct {
    id: Channel,
    name: [16]u8,
    @"opaque": ?*anyopaque,
};

pub const Buffer = opaque {};

pub const Channel = enum(c_int) {
    none = -1,
    front_left = 0,
    front_right = 1,
    front_center = 2,
    low_frequency = 3,
    back_left = 4,
    back_right = 5,
    front_left_of_center = 6,
    front_right_of_center = 7,
    back_center = 8,
    side_left = 9,
    side_right = 10,
    top_center = 11,
    top_front_left = 12,
    top_front_center = 13,
    top_front_right = 14,
    top_back_left = 15,
    top_back_center = 16,
    top_back_right = 17,
    stereo_left = 29,
    stereo_right = 30,
    wide_left = 31,
    wide_right = 32,
    surround_direct_left = 33,
    surround_direct_right = 34,
    low_frequency_2 = 35,
    top_side_left = 36,
    top_side_right = 37,
    bottom_front_center = 38,
    bottom_front_left = 39,
    bottom_front_right = 40,
    unused = 512,
    unknown = 768,
    ambisonic_base = 1024,
    ambisonic_end = 2047,
};

pub const Seek = packed struct(c_int) {
    mode: Mode,
    padding1: u14 = 0,
    size: bool,
    force: bool,
    padding2: u14 = 0,

    pub const Mode = enum(u2) {
        set = std.posix.SEEK.SET,
        cur = std.posix.SEEK.CUR,
        end = std.posix.SEEK.END,
    };
};

pub const Codec = extern struct {
    pub const ID = enum(c_uint) {
        none = 0,
        mpeg1video = 1,
        mpeg2video = 2,
        h261 = 3,
        h263 = 4,
        rv10 = 5,
        rv20 = 6,
        mjpeg = 7,
        mjpegb = 8,
        ljpeg = 9,
        sp5x = 10,
        jpegls = 11,
        mpeg4 = 12,
        rawvideo = 13,
        msmpeg4v1 = 14,
        msmpeg4v2 = 15,
        msmpeg4v3 = 16,
        wmv1 = 17,
        wmv2 = 18,
        h263p = 19,
        h263i = 20,
        flv1 = 21,
        svq1 = 22,
        svq3 = 23,
        dvvideo = 24,
        huffyuv = 25,
        cyuv = 26,
        h264 = 27,
        indeo3 = 28,
        vp3 = 29,
        theora = 30,
        asv1 = 31,
        asv2 = 32,
        ffv1 = 33,
        @"4xm" = 34,
        vcr1 = 35,
        cljr = 36,
        mdec = 37,
        roq = 38,
        interplay_video = 39,
        xan_wc3 = 40,
        xan_wc4 = 41,
        rpza = 42,
        cinepak = 43,
        ws_vqa = 44,
        msrle = 45,
        msvideo1 = 46,
        idcin = 47,
        @"8bps" = 48,
        smc = 49,
        flic = 50,
        truemotion1 = 51,
        vmdvideo = 52,
        mszh = 53,
        zlib = 54,
        qtrle = 55,
        tscc = 56,
        ulti = 57,
        qdraw = 58,
        vixl = 59,
        qpeg = 60,
        png = 61,
        ppm = 62,
        pbm = 63,
        pgm = 64,
        pgmyuv = 65,
        pam = 66,
        ffvhuff = 67,
        rv30 = 68,
        rv40 = 69,
        vc1 = 70,
        wmv3 = 71,
        loco = 72,
        wnv1 = 73,
        aasc = 74,
        indeo2 = 75,
        fraps = 76,
        truemotion2 = 77,
        bmp = 78,
        cscd = 79,
        mmvideo = 80,
        zmbv = 81,
        avs = 82,
        smackvideo = 83,
        nuv = 84,
        kmvc = 85,
        flashsv = 86,
        cavs = 87,
        jpeg2000 = 88,
        vmnc = 89,
        vp5 = 90,
        vp6 = 91,
        vp6f = 92,
        targa = 93,
        dsicinvideo = 94,
        tiertexseqvideo = 95,
        tiff = 96,
        gif = 97,
        dxa = 98,
        dnxhd = 99,
        thp = 100,
        sgi = 101,
        c93 = 102,
        bethsoftvid = 103,
        ptx = 104,
        txd = 105,
        vp6a = 106,
        amv = 107,
        vb = 108,
        pcx = 109,
        sunrast = 110,
        indeo4 = 111,
        indeo5 = 112,
        mimic = 113,
        rl2 = 114,
        escape124 = 115,
        dirac = 116,
        bfi = 117,
        cmv = 118,
        motionpixels = 119,
        tgv = 120,
        tgq = 121,
        tqi = 122,
        aura = 123,
        aura2 = 124,
        v210x = 125,
        tmv = 126,
        v210 = 127,
        dpx = 128,
        mad = 129,
        frwu = 130,
        flashsv2 = 131,
        cdgraphics = 132,
        r210 = 133,
        anm = 134,
        binkvideo = 135,
        iff_ilbm = 136,
        kgv1 = 137,
        yop = 138,
        vp8 = 139,
        pictor = 140,
        ansi = 141,
        a64_multi = 142,
        a64_multi5 = 143,
        r10k = 144,
        mxpeg = 145,
        lagarith = 146,
        prores = 147,
        jv = 148,
        dfa = 149,
        wmv3image = 150,
        vc1image = 151,
        utvideo = 152,
        bmv_video = 153,
        vble = 154,
        dxtory = 155,
        v410 = 156,
        xwd = 157,
        cdxl = 158,
        xbm = 159,
        zerocodec = 160,
        mss1 = 161,
        msa1 = 162,
        tscc2 = 163,
        mts2 = 164,
        cllc = 165,
        mss2 = 166,
        vp9 = 167,
        aic = 168,
        escape130 = 169,
        g2m = 170,
        webp = 171,
        hnm4_video = 172,
        hevc = 173,
        fic = 174,
        alias_pix = 175,
        brender_pix = 176,
        paf_video = 177,
        exr = 178,
        vp7 = 179,
        sanm = 180,
        sgirle = 181,
        mvc1 = 182,
        mvc2 = 183,
        hqx = 184,
        tdsc = 185,
        hq_hqa = 186,
        hap = 187,
        dds = 188,
        dxv = 189,
        screenpresso = 190,
        rscc = 191,
        avs2 = 192,
        pgx = 193,
        avs3 = 194,
        msp2 = 195,
        vvc = 196,
        y41p = 197,
        avrp = 198,
        @"012v" = 199,
        avui = 200,
        targa_y216 = 201,
        v308 = 202,
        v408 = 203,
        yuv4 = 204,
        avrn = 205,
        cpia = 206,
        xface = 207,
        snow = 208,
        smvjpeg = 209,
        apng = 210,
        daala = 211,
        cfhd = 212,
        truemotion2rt = 213,
        m101 = 214,
        magicyuv = 215,
        sheervideo = 216,
        ylc = 217,
        psd = 218,
        pixlet = 219,
        speedhq = 220,
        fmvc = 221,
        scpr = 222,
        clearvideo = 223,
        xpm = 224,
        av1 = 225,
        bitpacked = 226,
        mscc = 227,
        srgc = 228,
        svg = 229,
        gdv = 230,
        fits = 231,
        imm4 = 232,
        prosumer = 233,
        mwsc = 234,
        wcmv = 235,
        rasc = 236,
        hymt = 237,
        arbc = 238,
        agm = 239,
        lscr = 240,
        vp4 = 241,
        imm5 = 242,
        mvdv = 243,
        mvha = 244,
        cdtoons = 245,
        mv30 = 246,
        notchlc = 247,
        pfm = 248,
        mobiclip = 249,
        photocd = 250,
        ipu = 251,
        argo = 252,
        cri = 253,
        simbiosis_imx = 254,
        sga_video = 255,
        gem = 256,
        vbn = 257,
        jpegxl = 258,
        qoi = 259,
        phm = 260,
        radiance_hdr = 261,
        wbmp = 262,
        media100 = 263,
        vqc = 264,
        pdv = 265,
        evc = 266,
        rtv1 = 267,
        vmix = 268,
        lead = 269,
        pcm_s16le = 65536,
        pcm_s16be = 65537,
        pcm_u16le = 65538,
        pcm_u16be = 65539,
        pcm_s8 = 65540,
        pcm_u8 = 65541,
        pcm_mulaw = 65542,
        pcm_alaw = 65543,
        pcm_s32le = 65544,
        pcm_s32be = 65545,
        pcm_u32le = 65546,
        pcm_u32be = 65547,
        pcm_s24le = 65548,
        pcm_s24be = 65549,
        pcm_u24le = 65550,
        pcm_u24be = 65551,
        pcm_s24daud = 65552,
        pcm_zork = 65553,
        pcm_s16le_planar = 65554,
        pcm_dvd = 65555,
        pcm_f32be = 65556,
        pcm_f32le = 65557,
        pcm_f64be = 65558,
        pcm_f64le = 65559,
        pcm_bluray = 65560,
        pcm_lxf = 65561,
        s302m = 65562,
        pcm_s8_planar = 65563,
        pcm_s24le_planar = 65564,
        pcm_s32le_planar = 65565,
        pcm_s16be_planar = 65566,
        pcm_s64le = 65567,
        pcm_s64be = 65568,
        pcm_f16le = 65569,
        pcm_f24le = 65570,
        pcm_vidc = 65571,
        pcm_sga = 65572,
        adpcm_ima_qt = 69632,
        adpcm_ima_wav = 69633,
        adpcm_ima_dk3 = 69634,
        adpcm_ima_dk4 = 69635,
        adpcm_ima_ws = 69636,
        adpcm_ima_smjpeg = 69637,
        adpcm_ms = 69638,
        adpcm_4xm = 69639,
        adpcm_xa = 69640,
        adpcm_adx = 69641,
        adpcm_ea = 69642,
        adpcm_g726 = 69643,
        adpcm_ct = 69644,
        adpcm_swf = 69645,
        adpcm_yamaha = 69646,
        adpcm_sbpro_4 = 69647,
        adpcm_sbpro_3 = 69648,
        adpcm_sbpro_2 = 69649,
        adpcm_thp = 69650,
        adpcm_ima_amv = 69651,
        adpcm_ea_r1 = 69652,
        adpcm_ea_r3 = 69653,
        adpcm_ea_r2 = 69654,
        adpcm_ima_ea_sead = 69655,
        adpcm_ima_ea_eacs = 69656,
        adpcm_ea_xas = 69657,
        adpcm_ea_maxis_xa = 69658,
        adpcm_ima_iss = 69659,
        adpcm_g722 = 69660,
        adpcm_ima_apc = 69661,
        adpcm_vima = 69662,
        adpcm_afc = 69663,
        adpcm_ima_oki = 69664,
        adpcm_dtk = 69665,
        adpcm_ima_rad = 69666,
        adpcm_g726le = 69667,
        adpcm_thp_le = 69668,
        adpcm_psx = 69669,
        adpcm_aica = 69670,
        adpcm_ima_dat4 = 69671,
        adpcm_mtaf = 69672,
        adpcm_agm = 69673,
        adpcm_argo = 69674,
        adpcm_ima_ssi = 69675,
        adpcm_zork = 69676,
        adpcm_ima_apm = 69677,
        adpcm_ima_alp = 69678,
        adpcm_ima_mtf = 69679,
        adpcm_ima_cunning = 69680,
        adpcm_ima_moflex = 69681,
        adpcm_ima_acorn = 69682,
        adpcm_xmd = 69683,
        amr_nb = 73728,
        amr_wb = 73729,
        ra_144 = 77824,
        ra_288 = 77825,
        roq_dpcm = 81920,
        interplay_dpcm = 81921,
        xan_dpcm = 81922,
        sol_dpcm = 81923,
        sdx2_dpcm = 81924,
        gremlin_dpcm = 81925,
        derf_dpcm = 81926,
        wady_dpcm = 81927,
        cbd2_dpcm = 81928,
        mp2 = 86016,
        mp3 = 86017,
        aac = 86018,
        ac3 = 86019,
        dts = 86020,
        vorbis = 86021,
        dvaudio = 86022,
        wmav1 = 86023,
        wmav2 = 86024,
        mace3 = 86025,
        mace6 = 86026,
        vmdaudio = 86027,
        flac = 86028,
        mp3adu = 86029,
        mp3on4 = 86030,
        shorten = 86031,
        alac = 86032,
        westwood_snd1 = 86033,
        gsm = 86034,
        qdm2 = 86035,
        cook = 86036,
        truespeech = 86037,
        tta = 86038,
        smackaudio = 86039,
        qcelp = 86040,
        wavpack = 86041,
        dsicinaudio = 86042,
        imc = 86043,
        musepack7 = 86044,
        mlp = 86045,
        gsm_ms = 86046,
        atrac3 = 86047,
        ape = 86048,
        nellymoser = 86049,
        musepack8 = 86050,
        speex = 86051,
        wmavoice = 86052,
        wmapro = 86053,
        wmalossless = 86054,
        atrac3p = 86055,
        eac3 = 86056,
        sipr = 86057,
        mp1 = 86058,
        twinvq = 86059,
        truehd = 86060,
        mp4als = 86061,
        atrac1 = 86062,
        binkaudio_rdft = 86063,
        binkaudio_dct = 86064,
        aac_latm = 86065,
        qdmc = 86066,
        celt = 86067,
        g723_1 = 86068,
        g729 = 86069,
        @"8svx_exp" = 86070,
        @"8svx_fib" = 86071,
        bmv_audio = 86072,
        ralf = 86073,
        iac = 86074,
        ilbc = 86075,
        opus = 86076,
        comfort_noise = 86077,
        tak = 86078,
        metasound = 86079,
        paf_audio = 86080,
        on2avc = 86081,
        dss_sp = 86082,
        codec2 = 86083,
        ffwavesynth = 86084,
        sonic = 86085,
        sonic_ls = 86086,
        evrc = 86087,
        smv = 86088,
        dsd_lsbf = 86089,
        dsd_msbf = 86090,
        dsd_lsbf_planar = 86091,
        dsd_msbf_planar = 86092,
        @"4gv" = 86093,
        interplay_acm = 86094,
        xma1 = 86095,
        xma2 = 86096,
        dst = 86097,
        atrac3al = 86098,
        atrac3pal = 86099,
        dolby_e = 86100,
        aptx = 86101,
        aptx_hd = 86102,
        sbc = 86103,
        atrac9 = 86104,
        hcom = 86105,
        acelp_kelvin = 86106,
        mpegh_3d_audio = 86107,
        siren = 86108,
        hca = 86109,
        fastaudio = 86110,
        msnsiren = 86111,
        dfpwm = 86112,
        bonk = 86113,
        misc4 = 86114,
        apac = 86115,
        ftr = 86116,
        wavarc = 86117,
        rka = 86118,
        ac4 = 86119,
        osq = 86120,
        qoa = 86121,
        dvd_subtitle = 94208,
        dvb_subtitle = 94209,
        text = 94210,
        xsub = 94211,
        ssa = 94212,
        mov_text = 94213,
        hdmv_pgs_subtitle = 94214,
        dvb_teletext = 94215,
        srt = 94216,
        microdvd = 94217,
        eia_608 = 94218,
        jacosub = 94219,
        sami = 94220,
        realtext = 94221,
        stl = 94222,
        subviewer1 = 94223,
        subviewer = 94224,
        subrip = 94225,
        webvtt = 94226,
        mpl2 = 94227,
        vplayer = 94228,
        pjs = 94229,
        ass = 94230,
        hdmv_text_subtitle = 94231,
        ttml = 94232,
        arib_caption = 94233,
        ttf = 98304,
        scte_35 = 98305,
        epg = 98306,
        bintext = 98307,
        xbin = 98308,
        idf = 98309,
        otf = 98310,
        smpte_klv = 98311,
        dvd_nav = 98312,
        timed_id3 = 98313,
        bin_data = 98314,
        smpte_2038 = 98315,
        probe = 102400,
        mpeg2ts = 131072,
        mpeg4systems = 131073,
        ffmetadata = 135168,
        wrapped_avframe = 135169,
        vnull = 135170,
        anull = 135171,

        pub const first_audio: ID = .pcm_s16le;
        pub const first_subtitle: ID = .dvd_subtitle;
        pub const first_unknown: ID = .ttf;

        pub const decoder = Codec.findDecoder;
    };

    pub const Descriptor = extern struct {
        id: ID,
        type: MediaType,
        name: [*:0]const u8,
        long_name: ?[*:0]const u8,
        props: c_int,
        mime_types: ?[*:null]const ?[*:0]const u8,
        profiles: ?[*]const Profile,
    };

    pub const Parameters = extern struct {
        codec_type: MediaType,
        codec_id: ID,
        codec_tag: u32,
        extradata: [*]u8,
        extradata_size: c_int,
        coded_side_data: [*]PacketSideData,
        nb_coded_side_data: c_int,
        format: c_int,
        bit_rate: i64,
        bits_per_coded_sample: c_int,
        bits_per_raw_sample: c_int,
        profile: c_int,
        level: c_int,
        width: c_int,
        height: c_int,
        sample_aspect_ratio: Rational,
        framerate: Rational,
        field_order: FieldOrder,
        color_range: ColorRange,
        color_primaries: ColorPrimaries,
        color_trc: ColorTransferCharacteristic,
        color_space: ColorSpace,
        chroma_location: ChromaLocation,
        video_delay: c_int,
        ch_layout: ChannelLayout,
        sample_rate: c_int,
        block_align: c_int,
        frame_size: c_int,
        initial_padding: c_int,
        trailing_padding: c_int,
        seek_preroll: c_int,
    };

    pub const Context = extern struct {
        av_class: *const Class,
        log_level_offset: c_int,
        codec_type: MediaType,
        codec: ?*const Codec,
        codec_id: ID,
        codec_tag: c_uint,
        priv_data: ?*anyopaque,
        internal: ?*opaque {},
        @"opaque": ?*anyopaque,
        bit_rate: i64,
        flags: c_int,
        flags2: c_int,
        extradata: [*]u8,
        extradata_size: c_int,
        time_base: Rational,
        pkt_timebase: Rational,
        framerate: Rational,
        ticks_per_frame: c_int,
        delay: c_int,
        width: c_int,
        height: c_int,
        coded_width: c_int,
        coded_height: c_int,
        sample_aspect_ratio: Rational,
        pix_fmt: PixelFormat,
        sw_pix_fmt: PixelFormat,
        color_primaries: ColorPrimaries,
        color_trc: ColorTransferCharacteristic,
        colorspace: ColorSpace,
        color_range: ColorRange,
        chroma_sample_location: ChromaLocation,
        field_order: FieldOrder,
        refs: c_int,
        has_b_frames: c_int,
        slice_flags: c_int,
        draw_horiz_band: ?*const fn (s: *Context, src: *const Frame, offset: *[Frame.num_data_pointers]c_int, y: c_int, @"type": c_int, height: c_int) callconv(.c) void,
        get_format: *const fn (s: *Context, fmt: *const PixelFormat) callconv(.c) PixelFormat,
        max_b_frames: c_int,
        b_quant_factor: f32,
        b_quant_offset: f32,
        i_quant_factor: f32,
        i_quant_offset: f32,
        lumi_masking: f32,
        temporal_cplx_masking: f32,
        spatial_cplx_masking: f32,
        p_masking: f32,
        dark_masking: f32,
        nsse_weight: c_int,
        me_cmp: c_int,
        me_sub_cmp: c_int,
        mb_cmp: c_int,
        ildct_cmp: c_int,
        dia_size: c_int,
        last_predictor_count: c_int,
        me_pre_cmp: c_int,
        pre_dia_size: c_int,
        me_subpel_quality: c_int,
        me_range: c_int,
        mb_decision: c_int,
        intra_matrix: [*]u16,
        inter_matrix: [*]u16,
        chroma_intra_matrix: [*]u16,
        intra_dc_precision: c_int,
        mb_lmin: c_int,
        mb_lmax: c_int,
        bidir_refine: c_int,
        keyint_min: c_int,
        gop_size: c_int,
        mv0_threshold: c_int,
        slices: c_int,
        sample_rate: c_int,
        sample_fmt: SampleFormat,
        ch_layout: ChannelLayout,
        frame_size: c_int,
        block_align: c_int,
        cutoff: c_int,
        audio_service_type: AudioServiceType,
        request_sample_fmt: SampleFormat,
        initial_padding: c_int,
        trailing_padding: c_int,
        seek_preroll: c_int,
        get_buffer2: *const fn (s: *Context, frame: *Frame, flags: c_int) callconv(.c) c_int,
        bit_rate_tolerance: c_int,
        global_quality: c_int,
        compression_level: c_int,
        qcompress: f32,
        qblur: f32,
        qmin: c_int,
        qmax: c_int,
        max_qdiff: c_int,
        rc_buffer_size: c_int,
        rc_override_count: c_int,
        rc_override: [*]RcOverride,
        rc_max_rate: i64,
        rc_min_rate: i64,
        rc_max_available_vbv_use: f32,
        rc_min_vbv_overflow_use: f32,
        rc_initial_buffer_occupancy: c_int,
        trellis: c_int,
        stats_out: [*]u8,
        stats_in: [*]u8,
        workaround_bugs: c_int,
        strict_std_compliance: c_int,
        error_concealment: c_int,
        debug: c_int,
        err_recognition: c_int,
        hwaccel: ?*const HWAccel,
        hwaccel_context: ?*anyopaque,
        hw_frames_ctx: ?*BufferRef,
        hw_device_ctx: ?*BufferRef,
        hwaccel_flags: c_int,
        extra_hw_frames: c_int,
        @"error": [Frame.num_data_pointers]u64,
        dct_algo: c_int,
        idct_algo: c_int,
        bits_per_coded_sample: c_int,
        bits_per_raw_sample: c_int,
        thread_count: c_int,
        thread_type: c_int,
        active_thread_type: c_int,
        execute: *const fn (c: *Context, *const fn (c2: *Context, arg: [*]u8) callconv(.c) c_int, arg2: [*]u8, ret: ?[*]c_int, count: c_int, size: c_int) callconv(.c) c_int,
        execute2: *const fn (c: *Context, *const fn (c2: *Context, arg: [*]u8, jobnr: c_int, threadnr: c_int) callconv(.c) c_int, arg2: [*]u8, ret: ?[*]c_int, count: c_int) callconv(.c) c_int,
        profile: c_int,
        level: c_int,
        properties: c_uint,
        skip_loop_filter: Discard,
        skip_idct: Discard,
        skip_frame: Discard,
        skip_alpha: c_int,
        skip_top: c_int,
        skip_bottom: c_int,
        lowres: c_int,
        codec_descriptor: ?*const Descriptor,
        sub_charenc: ?[*:0]u8,
        sub_charenc_mode: c_int,
        subtitle_header_size: c_int,
        subtitle_header: ?[*]u8,
        dump_separator: ?[*:0]u8,
        codec_whitelist: ?[*:0]u8,
        coded_side_data: ?[*]PacketSideData,
        nb_coded_side_data: c_int,
        export_side_data: c_int,
        max_pixels: i64,
        apply_cropping: c_int,
        discard_damaged_percentage: c_int,
        max_samples: i64,
        get_encode_buffer: *const fn (s: *Context, pkt: *Packet, flags: c_int) callconv(.c) c_int,
        frame_num: i64,
        side_data_prefer_packet: ?[*]c_int,
        nb_side_data_prefer_packet: c_uint,
        decoded_side_data: ?[*]*FrameSideData,
        nb_decoded_side_data: c_int,

        /// Allocate an `AVCodecContext` and set its fields to default values. The
        /// resulting struct should be freed with avcodec_free_context().
        ///
        /// Returns an `AVCodecContext` filled with default values or null on failure.
        pub fn init(codec: *const Codec) error{OutOfMemory}!*Context {
            return avcodec_alloc_context3(codec) orelse return error.OutOfMemory;
        }
        extern fn avcodec_alloc_context3(codec: *const Codec) ?*Codec.Context;

        pub fn deinit(self: *@This()) void {
            var keep_your_dirty_hands_off_my_pointers_ffmpeg: ?*@This() = self;
            avcodec_free_context(&keep_your_dirty_hands_off_my_pointers_ffmpeg);
        }
        extern fn avcodec_free_context(avctx: *?*Codec.Context) void;

        /// Fill the codec context based on the values from the supplied codec
        /// parameters.
        ///
        /// Any allocated fields in codec that have a corresponding field in par
        /// are freed and replaced with duplicates of the corresponding field in
        /// par. Fields in codec that do not have a counterpart in par are not
        /// touched.
        pub fn parametersToContext(codec: *Context, par: *const Codec.Parameters) Error!void {
            _ = try wrap(avcodec_parameters_to_context(codec, par));
        }
        extern fn avcodec_parameters_to_context(codec: *Codec.Context, par: *const Codec.Parameters) c_int;

        /// Initialize the `AVCodecContext` to use the given `AVCodec`. Prior to using this
        /// function the context has to be allocated with `avcodec_alloc_context3()`.
        ///
        /// The functions `avcodec_find_decoder_by_name()`, `avcodec_find_encoder_by_name()`,
        /// `avcodec_find_decoder()` and `avcodec_find_encoder()` provide an easy way for
        /// retrieving a codec.
        ///
        /// Depending on the codec, you might need to set options in the codec context
        /// also for decoding (e.g. width, height, or the pixel or audio sample format in
        /// the case the information is not available in the bitstream, as when decoding
        /// raw audio or video).
        ///
        /// Options in the codec context can be set either by setting them in the options
        /// AVDictionary, or by setting the values in the context itself, directly or by
        /// using the av_opt_set() API before calling this function.
        ///
        /// Example:
        /// ```
        /// try opts.set("b", "2.5M", .{});
        /// context = try init(try av.Codec.ID.h264.decoder());
        /// errdefer context.deinit();
        /// try context.open(null, opts);
        /// ```
        ///
        /// In the case `AVCodecParameters` are available (e.g. when demuxing a stream
        /// using libavformat, and accessing the `AVStream` contained in the demuxer), the
        /// codec parameters can be copied to the codec context using
        /// `avcodec_parameters_to_context()`, as in the following example:
        ///
        /// ```
        /// const stream: *Stream = ...;
        /// context = try init(codec);
        /// try context.setParameters(stream.codecpar);
        /// try context.open(codec, null);
        /// ```
        ///
        /// @note Always call this function before using decoding routines (such as
        /// `avcodec_receive_frame()`).
        pub fn open(
            /// The context to initialize.
            avctx: *Context,
            /// The codec to open this context for. If a non-null codec has been
            /// previously passed to `avcodec_alloc_context3()` or
            /// for this context, then this parameter MUST be either null or
            /// equal to the previously passed codec.
            codec: ?*const Codec,
            /// A dictionary filled with `AVCodecContext` and codec-private
            /// options, which are set on top of the options already set in
            /// `avctx`, can be null. On return this object will be filled with
            /// options that were not found in the `avctx` codec context.
            options: ?*Dictionary.Mutable,
        ) Error!void {
            _ = try wrap(avcodec_open2(avctx, codec, options));
        }
        extern fn avcodec_open2(avctx: *Codec.Context, codec: ?*const Codec, options: ?*Dictionary.Mutable) c_int;

        /// Supply raw packet data as input to a decoder.
        ///
        /// Internally, this call will copy relevant `CodecContext` fields, which
        /// can influence decoding per-packet, and apply them when the packet is
        /// actually decoded. (For example `CodecContext.skip_frame`, which might
        /// direct the decoder to drop the frame contained by the packet sent with
        /// this function.)
        ///
        /// Warning: The input buffer, avpkt->data must be
        /// AV_INPUT_BUFFER_PADDING_SIZE larger than the actual read bytes because
        /// some optimized bitstream readers read 32 or 64 bits at once and could
        /// read over the end.
        ///
        /// The `CodecContext` MUST have been opened with `open` before packets may
        /// be fed to the decoder.
        ///
        /// Notable error codes:
        /// * `Error.WouldBlock`
        /// * `Error.EndOfFile`
        /// * others are also possible
        pub fn sendPacket(
            cc: *Context,
            /// The input `Packet`.
            ///
            /// Usually, this will be a single video frame, or several complete
            /// audio frames.
            ///
            /// Ownership of the packet remains with the caller, and the decoder
            /// will not write to the packet.
            ///
            /// The decoder may create a reference to the packet data (or copy it
            /// if the packet is not reference-counted).
            ///
            /// Unlike with older APIs, the packet is always fully consumed, and if
            /// it contains multiple frames (e.g. some audio codecs), will require
            /// you to call `CodecContext.receive_frame` multiple times afterwards
            /// before you can send a new packet. It can be NULL (or an AVPacket
            /// with data set to NULL and size set to 0); in this case, it is
            /// considered a flush packet, which signals the end of the stream.
            /// Sending the first flush packet will return success. Subsequent ones
            /// are unnecessary and will return AVERROR_EOF. If the decoder still
            /// has frames buffered, it will return them after sending a flush
            /// packet.
            packet: ?*const Packet,
        ) Error!void {
            _ = try wrap(avcodec_send_packet(cc, packet));
        }
        extern fn avcodec_send_packet(avctx: *Codec.Context, avpkt: ?*const Packet) c_int;

        /// Return decoded output data from a decoder or encoder (when the
        /// AV_CODEC_FLAG_RECON_FRAME flag is used).
        ///
        /// Notable error codes:
        /// * `Error.WouldBlock`
        /// * `Error.EndOfFile`
        /// * others are also possible
        pub fn receiveFrame(
            avctx: *Context,
            /// This will be set to a reference-counted video or audio frame
            /// (depending on the decoder type) allocated by the codec. Note that
            /// the function will always call `Frame.unref` before doing anything
            /// else.
            frame: *Frame,
        ) Error!void {
            _ = try wrap(avcodec_receive_frame(avctx, frame));
        }
        extern fn avcodec_receive_frame(avctx: *Codec.Context, frame: *Frame) c_int;

        /// Reset the internal codec state / flush internal buffers. Should be called
        /// e.g. when seeking or when switching to a different stream.
        ///
        /// For decoders, this function just releases any references the decoder
        /// might keep internally, but the caller's references remain valid.
        ///
        /// For encoders, this function will only do something if the encoder
        /// declares support for AV_CODEC_CAP_ENCODER_FLUSH. When called, the encoder
        /// will drain any remaining packets, and can then be re-used for a different
        /// stream (as opposed to sending a null frame which will leave the encoder
        /// in a permanent EOF state after draining). This can be desirable if the
        /// cost of tearing down and replacing the encoder instance is high.
        ///
        pub const flushBuffers = avcodec_flush_buffers;
        extern fn avcodec_flush_buffers(avctx: *Codec.Context) void;

        pub fn decodeSubtitle(
            avctx: *Context,
            sub: *Subtitle,
            avpkt: *Packet
        ) Error!bool {
            var got_sub_ptr: c_int = 0;
            _ = try wrap(avcodec_decode_subtitle2(avctx, sub, &got_sub_ptr, avpkt));
            return (got_sub_ptr != 0);
        }
        extern fn avcodec_decode_subtitle2(*Codec.Context, *Subtitle, *c_int, *Packet) c_int;
    };

    name: [*:0]const u8,
    long_name: ?[*:0]const u8,
    type: MediaType,
    id: ID,
    capabilities: c_int,
    max_lowres: u8,
    supported_framerates: ?[*]const Rational,
    pix_fmts: ?[*:.none]const PixelFormat,
    supported_samplerates: ?[*:0]const c_int,
    sample_fmts: ?[*:.none]const SampleFormat,
    priv_class: *const Class,
    profiles: ?[*]const Profile,
    wrapper_name: ?[*:0]const u8,
    ch_layouts: [*]const ChannelLayout,

    /// Iterate over all registered codecs.
    pub const iterate = av_codec_iterate;
    extern fn av_codec_iterate(@"opaque": *?*Codec.Iterator) ?*const Codec;

    /// Find a registered decoder with a matching codec ID.
    pub fn findDecoder(id: ID) error{DecoderNotFound}!*const Codec {
        return avcodec_find_decoder(id) orelse error.DecoderNotFound;
    }
    extern fn avcodec_find_decoder(id: Codec.ID) ?*const Codec;

    /// Find a registered decoder with the specified name.
    pub fn findDecoderByName(name: [*:0]const u8) error{DecoderNotFound}!*const Codec {
        return avcodec_find_decoder_by_name(name) orelse error.DecoderNotFound;
    }
    extern fn avcodec_find_decoder_by_name(name: [*:0]const u8) ?*const Codec;

    /// Find a registered encoder with a matching codec ID.
    pub fn findEncoder(id: ID) error{EncoderNotFound}!*const Codec {
        return avcodec_find_encoder(id) orelse error.EncoderNotFound;
    }
    extern fn avcodec_find_encoder(id: Codec.ID) ?*const Codec;

    /// Find a registered encoder with the specified name.
    pub fn findEncoderByName(name: [*:0]const u8) error{EncoderNotFound}!*const Codec {
        return avcodec_find_encoder_by_name(name) orelse error.EncoderNotFound;
    }
    extern fn avcodec_find_encoder_by_name(name: [*:0]const u8) ?*const Codec;

    pub fn isEncoder(codec: *const Codec) bool {
        return av_codec_is_encoder(codec) != 0;
    }
    extern fn av_codec_is_encoder(codec: *const Codec) c_int;

    pub fn isDecoder(codec: *const Codec) bool {
        return av_codec_is_decoder(codec) != 0;
    }
    extern fn av_codec_is_decoder(codec: *const Codec) c_int;

    /// Return a name for the specified profile, if available.
    pub fn getProfileName(codec: *const Codec, profile: c_int) error{ProfileNotFound}![*:0]const u8 {
        return av_get_profile_name(codec, profile) orelse error.ProfileNotFound;
    }
    extern fn av_get_profile_name(codec: *const Codec, profile: c_int) ?[*:0]const u8;
};

/// Decoded (raw) audio or video data.
///
/// `Frame` must be allocated using `Frame.alloc`. Note that this only
/// allocates the `Frame` itself, the buffers for the data must be managed
/// through other means (see below).
///
/// `Frame` must be freed with `Frame.free`.
///
/// `Frame` is typically allocated once and then reused multiple times to hold
/// different data (e.g. a single `Frame` to hold frames received from a
/// decoder). In such a case, `Frame.unref` will free any references held by
/// the frame and reset it to its original clean state before it is reused
/// again.
///
/// The data described by an `Frame` is usually reference counted through the
/// AVBuffer API. The underlying buffer references are stored in `Frame`.buf /
/// `Frame`.extended_buf. An `Frame` is considered to be reference counted if
/// at least one reference is set, i.e. if `Frame`.buf[0] != NULL. In such a
/// case, every single data plane must be contained in one of the buffers in
/// `Frame`.buf or `Frame`.extended_buf.
///
/// There may be a single buffer for all the data, or one separate buffer for
/// each plane, or anything in between.
///
/// `@sizeOf(Frame)` is not a part of the public ABI, so new fields may be
/// added to the end with a minor bump.
///
/// Fields can be accessed through `Options`, the name string used, matches the
/// C structure field name for fields accessible through `Options`. The `Class`
/// for `Frame` can be obtained from avcodec_get_frame_class()
pub const Frame = extern struct {
    pub const num_data_pointers = 8;

    data: [num_data_pointers][*]u8,
    linesize: [num_data_pointers]c_int,
    /// Pointers to the data planes/channels.
    ///
    /// For video, this should simply point to data[].
    ///
    /// For planar audio, each channel has a separate data pointer, and
    /// linesize[0] contains the size of each channel buffer.
    /// For packed audio, there is just one data pointer, and linesize[0]
    /// contains the total size of the buffer for all channels.
    ///
    /// Note: Both data and extended_data should always be set in a valid frame,
    /// but for planar audio with more channels that can fit in data,
    /// extended_data must be used in order to access all channels.
    extended_data: [*][*]u8,
    width: c_int,
    height: c_int,
    /// Number of audio samples (per channel) described by this frame.
    nb_samples: c_uint,
    format: extern union {
        pixel: PixelFormat,
        sample: SampleFormat,
    },
    key_frame: c_int,
    pict_type: PictureType,
    sample_aspect_ratio: Rational,
    pts: i64,
    pkt_dts: i64,
    /// Time base for the timestamps in this frame.
    ///
    /// In the future, this field may be set on frames output by decoders or
    /// filters, but its value will be by default ignored on input to encoders
    /// or filters.
    time_base: Rational,
    quality: c_int,
    @"opaque": ?*anyopaque,
    repeat_pict: c_int,
    interlaced_frame: c_int,
    top_field_first: c_int,
    palette_has_changed: c_int,
    /// Sample rate of the audio data.
    sample_rate: c_int,
    buf: [num_data_pointers]*BufferRef,
    extended_buf: [*]*BufferRef,
    nb_extended_buf: c_int,
    side_data: [*]*FrameSideData,
    nb_side_data: c_int,
    flags: c_int,
    color_range: ColorRange,
    color_primaries: ColorPrimaries,
    color_trc: ColorTransferCharacteristic,
    colorspace: ColorSpace,
    chroma_location: ChromaLocation,
    best_effort_timestamp: i64,
    pkt_pos: i64,
    metadata: Dictionary.Mutable,
    decode_error_flags: c_int,
    pkt_size: c_int,
    hw_frames_ctx: *BufferRef,
    opaque_ref: *BufferRef,
    crop_top: usize,
    crop_bottom: usize,
    crop_left: usize,
    crop_right: usize,
    private_ref: *BufferRef,
    /// Channel layout of the audio data.
    ch_layout: ChannelLayout,
    duration: i64,

    /// Allocate a `Frame` and set its fields to default values.  The resulting
    /// struct must be freed using `free`.
    ///
    /// Returns a `Frame` filled with default values.
    ///
    /// This only allocates the `Frame` itself, not the data buffers. Those
    /// must be allocated through other means, e.g. with av_frame_get_buffer()
    /// or manually.
    pub fn init() error{OutOfMemory}!*Frame {
        return av_frame_alloc() orelse error.OutOfMemory;
    }
    extern fn av_frame_alloc() ?*Frame;

    /// Free the frame and any dynamically allocated objects in it, e.g.
    /// extended_data. If the frame is reference counted, it will be
    /// unreferenced first.
    pub fn deinit(frame: *Frame) void {
        var keep_your_dirty_hands_off_my_pointers_ffmpeg: ?*Frame = frame;
        av_frame_free(&keep_your_dirty_hands_off_my_pointers_ffmpeg);
    }
    extern fn av_frame_free(frame: *?*Frame) void;

    /// Set up a new reference to the data described by the source frame.
    ///
    /// Copy frame properties from src to dst and create a new reference for
    /// each `BufferRef` from src.
    ///
    /// If src is not reference counted, new buffers are allocated and the data
    /// is copied.
    ///
    /// Warning: dst MUST have been either unreferenced with `unref`, or newly
    /// allocated with `alloc` before calling this function, or undefined
    /// behavior will occur.
    pub fn ref(dst: *Frame, src: *const Frame) error{OutOfMemory}!void {
        _ = wrap(av_frame_ref(dst, src)) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => unreachable, // I checked the source code, those are the only possible errors.
        };
    }
    extern fn av_frame_ref(dst: *Frame, src: *const Frame) c_int;

    /// Unreference all the buffers referenced by frame and reset the frame fields.
    pub const unref = av_frame_unref;
    extern fn av_frame_unref(frame: *Frame) void;
};

pub const PictureType = enum(c_uint) {
    none = 0,
    i = 1,
    p = 2,
    b = 3,
    s = 4,
    si = 5,
    sp = 6,
    bi = 7,
};

pub const FrameSideData = extern struct {
    type: FrameSideDataType,
    data: [*c]u8,
    size: usize,
    metadata: Dictionary.Mutable,
    buf: [*c]BufferRef,
};

pub const FrameSideDataType = enum(c_uint) {
    panscan = 0,
    a53_cc = 1,
    stereo3d = 2,
    matrixencoding = 3,
    downmix_info = 4,
    replaygain = 5,
    displaymatrix = 6,
    afd = 7,
    motion_vectors = 8,
    skip_samples = 9,
    audio_service_type = 10,
    mastering_display_metadata = 11,
    gop_timecode = 12,
    spherical = 13,
    content_light_level = 14,
    icc_profile = 15,
    s12m_timecode = 16,
    dynamic_hdr_plus = 17,
    regions_of_interest = 18,
    video_enc_params = 19,
    sei_unregistered = 20,
    film_grain_params = 21,
    detection_bboxes = 22,
    dovi_rpu_buffer = 23,
    dovi_metadata = 24,
    dynamic_hdr_vivid = 25,
    ambient_viewing_environment = 26,
    video_hint = 27,
};

pub const AudioServiceType = enum(c_uint) {
    main = 0,
    effects = 1,
    visually_impaired = 2,
    hearing_impaired = 3,
    dialogue = 4,
    commentary = 5,
    emergency = 6,
    voice_over = 7,
    karaoke = 8,
};

pub const RcOverride = extern struct {
    start_frame: c_int,
    end_frame: c_int,
    qscale: c_int,
    quality_factor: f32,
};

pub const HWAccel = extern struct {
    name: [*c]const u8,
    type: MediaType,
    id: Codec.ID,
    pix_fmt: PixelFormat,
    capabilities: c_int,
};

pub const Subtitle = extern struct {
    format: u16, // 0 = graphics
    start_display_time: u32, // relative to packet pts, in ms
    end_display_time: u32, // relative to packet pts, in ms
    num_rects: c_uint,
    rects: [*c][*c]Rect,
    /// Same as packet pts, in AV_TIME_BASE
    pts: i64,

    pub const Rect = extern struct {
        x: c_int,
        y: c_int,
        w: c_int,
        h: c_int,
        nb_colors: c_int,
        data: [4][*c]u8,
        linesize: [4]c_int,
        flags: c_int,
        type: Type,
        text: [*c]u8,
        ass: [*c]u8,
    };

    pub const Type = enum(c_uint) {
        none,
        /// A bitmap, pict will be set
        bitmap,
        text,
        ass,
    };
};

pub const FilterGraph = extern struct {
    av_class: *const Class,
    filters: [*]*FilterContext,
    nb_filters: c_uint,
    scale_sws_opts: [*:0]u8,
    thread_type: c_int,
    nb_threads: c_int,
    @"opaque": ?*anyopaque,
    execute: ?*const FilterExecuteFn,
    aresample_swr_opts: [*:0]u8,

    pub fn alloc() error{OutOfMemory}!*FilterGraph {
        return avfilter_graph_alloc() orelse return error.OutOfMemory;
    }
    extern fn avfilter_graph_alloc() ?*FilterGraph;

    pub fn free(fg: *FilterGraph) void {
        var keep_your_dirty_hands_off_my_pointers_ffmpeg: ?*FilterGraph = fg;
        avfilter_graph_free(&keep_your_dirty_hands_off_my_pointers_ffmpeg);
    }
    extern fn avfilter_graph_free(graph: *?*FilterGraph) void;

    /// Create a new filter instance in a filter graph.
    ///
    /// Returns the context of the newly created filter instance.
    ///
    /// The filter instance is also retrievable directly through
    /// `FilterGraph.filters` or with `FilterGraph.get_filter`.
    pub fn allocFilter(
        graph: *FilterGraph,
        /// The filter to create an instance of.
        filter: *const Filter,
        /// Name to give to the new instance (will be copied to
        /// `FilterContext.name`). This may be used by the caller to identify
        /// different filters, libavfilter itself assigns no semantics to this
        /// parameter. May be `null`.
        name: ?[*:0]const u8,
    ) error{OutOfMemory}!*FilterContext {
        return avfilter_graph_alloc_filter(graph, filter, name) orelse return error.OutOfMemory;
    }
    extern fn avfilter_graph_alloc_filter(graph: *FilterGraph, filter: *const Filter, name: ?[*:0]const u8) ?*FilterContext;

    /// Check validity and configure all the links and formats in the graph.
    pub fn config(graph: *FilterGraph, log_ctx: ?*anyopaque) Error!void {
        _ = try wrap(avfilter_graph_config(graph, log_ctx));
    }
    extern fn avfilter_graph_config(graphctx: *FilterGraph, log_ctx: ?*anyopaque) c_int;
};

/// An instance of a filter.
pub const FilterContext = extern struct {
    av_class: *const Class,
    filter: *const Filter,
    name: ?[*:0]u8,
    input_pads: ?*FilterPad,
    inputs: [*]*FilterLink,
    nb_inputs: c_uint,
    output_pads: ?*FilterPad,
    outputs: [*]*FilterLink,
    nb_outputs: c_uint,
    priv: ?*anyopaque,
    graph: *FilterGraph,
    thread_type: c_int,
    nb_threads: c_int,
    command_queue: ?*opaque {},
    enable_str: [*:0]u8,
    enable: ?*anyopaque,
    var_values: [*]f64,
    is_disabled: c_int,
    hw_device_ctx: *BufferRef,
    ready: c_uint,
    extra_hw_frames: c_int,

    pub const SearchFlags = packed struct(c_int) {
        children: bool = false,
        fake_obj: bool = false,
        _: u30 = 0,
    };

    pub const SinkFlags = packed struct(c_uint) {
        /// Tell `FilterContext.buffersink_get_frame_flags` to read video/samples
        /// buffer reference, but not remove it from the buffer. This is useful if you
        /// need only to read a video/samples buffer, without to fetch it.
        peek: bool = false,

        /// Tell `FilterContext.buffersink_get_frame_flags` not to request a frame from
        /// its input. If a frame is already buffered, it is read (and removed from the
        /// buffer), but if no frame is present, return `Error.WouldBlock`.
        no_request: bool = false,

        _: u30 = 0,
    };

    /// Sets the filter context parameter with the given name to value.
    ///
    /// SI postfixes and some named scalars are supported.
    ///
    /// If the field is of a numeric type, it has to be a numeric or named
    /// scalar. Behavior with more than one scalar and +- infix operators is
    /// undefined.
    ///
    /// If the field is of a flags type, it has to be a sequence of numeric
    /// scalars or named flags separated by '+' or '-'. Prefixing a flag with
    /// '+' causes it to be set without affecting the other flags; similarly,
    /// '-' unsets a flag.
    ///
    /// If the field is of a dictionary type, it has to be a ':' separated list
    /// of key=value parameters. Values containing ':' special characters must
    /// be escaped.
    ///
    /// Asserts:
    /// * a matching named option exists
    /// * the value is valid and in range
    pub fn optSet(
        fc: *FilterContext,
        name: [*:0]const u8,
        /// If the field being set is not of a string type, then the given
        /// string is parsed.
        val: [*:0]const u8,
    ) void {
        _ = wrap(av_opt_set(fc, name, val, .{ .children = true })) catch unreachable;
    }
    extern fn av_opt_set(obj: *anyopaque, name: [*:0]const u8, val: [*:0]const u8, search_flags: SearchFlags) c_int;

    /// Sets the filter context parameter with the given name to an integer value.
    ///
    /// Asserts:
    /// * a matching named option exists
    /// * the value is valid and in range
    pub fn optSetInt(fc: *FilterContext, name: [*:0]const u8, val: i64) void {
        _ = wrap(av_opt_set_int(fc, name, val, .{ .children = true })) catch unreachable;
    }
    extern fn av_opt_set_int(obj: *anyopaque, name: [*:0]const u8, val: i64, search_flags: SearchFlags) c_int;

    /// Sets the filter context parameter with the given name to a 64-bit float value.
    ///
    /// Asserts:
    /// * a matching named option exists
    /// * the value is valid and in range
    pub fn optSetDouble(fc: *FilterContext, name: [*:0]const u8, val: f64) void {
        _ = wrap(av_opt_set_double(fc, name, val, .{ .children = true })) catch unreachable;
    }
    extern fn av_opt_set_double(obj: *anyopaque, name: [*:0]const u8, val: f64, search_flags: SearchFlags) c_int;

    /// Sets the filter context parameter with the given name to a `Rational` value.
    ///
    /// Asserts:
    /// * a matching named option exists
    /// * the value is valid and in range
    pub fn optSetQ(fc: *FilterContext, name: [*:0]const u8, val: Rational) void {
        _ = wrap(av_opt_set_q(fc, name, val, .{ .children = true })) catch unreachable;
    }
    extern fn av_opt_set_q(obj: *anyopaque, name: [*:0]const u8, val: Rational, search_flags: SearchFlags) c_int;

    /// Get a value of the option with the given name.
    pub fn optGetDouble(fc: *FilterContext, option_name: [*:0]const u8) Error!f64 {
        var result: f64 = undefined;
        _ = try wrap(av_opt_get_double(fc, option_name, .{ .children = true }, &result));
        return result;
    }
    extern fn av_opt_get_double(obj: *anyopaque, name: [*:0]const u8, search_flags: SearchFlags, out_val: *f64) c_int;

    /// Initialize a filter with the supplied parameters.
    pub fn initStr(
        /// Uninitialized filter context to initialize.
        ctx: *FilterContext,
        /// Options to initialize the filter with. This must be a ':'-separated
        /// list of options in the 'key=value' form.
        ///
        /// May be NULL if the options have been set directly using the
        /// `Options` API or there are no options that need to be set.
        args: ?[*:0]const u8,
    ) Error!void {
        _ = try wrap(avfilter_init_str(ctx, args));
    }
    extern fn avfilter_init_str(ctx: *FilterContext, args: ?[*:0]const u8) c_int;

    /// Link two filters together.
    ///
    /// @param src    the source filter
    /// @param srcpad index of the output pad on the source filter
    /// @param dst    the destination filter
    /// @param dstpad index of the input pad on the destination filter
    /// @return       zero on success
    pub fn link(
        src: *FilterContext,
        src_pad: c_uint,
        dst: *FilterContext,
        dst_pad: c_uint,
    ) error{OutOfMemory}!void {
        _ = wrap(avfilter_link(src, src_pad, dst, dst_pad)) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => unreachable, // I checked the source code, those are the only possible errors.
        };
    }
    extern fn avfilter_link(src: *FilterContext, srcpad: c_uint, dst: *FilterContext, dstpad: c_uint) c_int;

    /// Add a frame to the buffer source.
    ///
    /// This function is equivalent to `buffersrc_add_frame_flags` with the
    /// AV_BUFFERSRC_FLAG_KEEP_REF flag.
    pub fn buffersrcWriteFrame(
        /// An instance of the buffersrc filter.
        ctx: *FilterContext,
        /// Frame to be added.
        ///
        /// If the frame is reference counted, this function will make a new
        /// reference to it. Otherwise the frame data will be copied.
        frame: *const Frame,
    ) Error!void {
        _ = try wrap(av_buffersrc_write_frame(ctx, frame));
    }
    extern fn av_buffersrc_write_frame(ctx: *FilterContext, frame: *const Frame) c_int;

    /// Add a frame to the buffer source.
    ///
    /// The difference between this function and `buffersrc_write_frame` is
    /// that `buffersrc_write_frame` creates a new reference to the input
    /// frame, while this function takes ownership of the reference passed to it.
    ///
    /// This function is equivalent to `buffersrc_add_frame_flags` without the
    /// AV_BUFFERSRC_FLAG_KEEP_REF flag.
    pub fn buffersrcAddFrame(
        /// An instance of the buffersrc filter.
        ctx: *FilterContext,
        /// Frame to be added.
        ///
        /// If the frame is reference counted, this function will take
        /// ownership of the reference(s) and reset the frame. Otherwise the
        /// frame data will be copied. If this function returns an error, the
        /// input frame is not touched.
        ///
        /// `null` indicates a flush and will cause EOF to come out the other
        /// end of the filter graph.
        frame: ?*Frame,
    ) Error!void {
        _ = try wrap(av_buffersrc_add_frame(ctx, frame));
    }
    extern fn av_buffersrc_add_frame(ctx: *FilterContext, frame: ?*Frame) c_int;

    /// Get a frame with filtered data from sink and put it in frame.
    pub fn buffersinkGetFrameFlags(
        /// Pointer to a buffersink or abuffersink filter context.
        ctx: *FilterContext,
        /// Pointer to an allocated frame that will be filled with data.
        ///
        /// The data must be freed using `Frame.unref` / `Frame.free`.
        frame: *Frame,
        flags: SinkFlags,
    ) Error!void {
        _ = try wrap(av_buffersink_get_frame_flags(ctx, frame, flags));
    }
    extern fn av_buffersink_get_frame_flags(ctx: *FilterContext, frame: *Frame, flags: SinkFlags) c_int;

    /// Same as `buffersink_get_frame`, but with the ability to specify the
    /// number of samples read.
    ///
    /// This function is less efficient than `buffersink_get_frame`, because it
    /// copies the data around.
    ///
    /// Warning: do not mix this function with `buffersink_get_frame`. Use only
    /// one or the other with a single sink, not both.
    pub fn buffersinkGetSamples(
        /// Pointer to a context of the abuffersink `Filter`.
        ctx: *FilterContext,
        /// pointer to an allocated frame that will be filled with data.
        ///
        /// The data must be freed using `Frame.unref / `Frame.free`.
        frame: *Frame,
        /// `frame` will contain exactly nb_samples audio samples, except at
        /// the end of stream, when it can contain less than nb_samples.
        nb_samples: c_int,
    ) Error!void {
        _ = try wrap(av_buffersink_get_samples(ctx, frame, nb_samples));
    }
    extern fn av_buffersink_get_samples(ctx: *FilterContext, frame: *Frame, nb_samples: c_int) c_int;

    /// Set the frame size for an audio buffer sink.
    ///
    /// All calls to `buffersink_get_frame_flags` will return a buffer with
    /// exactly the specified number of samples, or `error.WouldBlock` if there
    /// is not enough. The last buffer at EOF will be padded with 0.
    pub const buffersinkSetFrameSize = av_buffersink_set_frame_size;
    extern fn av_buffersink_set_frame_size(ctx: *FilterContext, frame_size: c_uint) void;
};

pub const FilterExecuteFn = fn ([*c]FilterContext, ?*const FilterActionFn, ?*anyopaque, [*c]c_int, c_int) callconv(.c) c_int;
pub const FilterActionFn = fn ([*c]FilterContext, ?*anyopaque, c_int, c_int) callconv(.c) c_int;
pub const FilterLink = extern struct {
    src: [*c]FilterContext,
    srcpad: ?*FilterPad,
    dst: [*c]FilterContext,
    dstpad: ?*FilterPad,
    type: MediaType,
    format: c_int,
    w: c_int,
    h: c_int,
    sample_aspect_ratio: Rational,
    colorspace: ColorSpace,
    color_range: ColorRange,
    sample_rate: c_int,
    ch_layout: ChannelLayout,
    time_base: Rational,
    incfg: FilterFormatsConfig,
    outcfg: FilterFormatsConfig,
    graph: [*c]FilterGraph,
    current_pts: i64,
    current_pts_us: i64,
    frame_rate: Rational,
    min_samples: c_int,
    max_samples: c_int,
    frame_count_in: i64,
    frame_count_out: i64,
    sample_count_in: i64,
    sample_count_out: i64,
    frame_wanted_out: c_int,
    hw_frames_ctx: [*c]BufferRef,
};

pub const Filter = extern struct {
    name: [*c]const u8,
    description: [*c]const u8,
    inputs: ?*const FilterPad,
    outputs: ?*const FilterPad,
    priv_class: [*c]const Class,
    flags: c_int,
    nb_inputs: u8,
    nb_outputs: u8,
    formats_state: u8,
    preinit: ?*const fn ([*c]FilterContext) callconv(.c) c_int,
    init: ?*const fn ([*c]FilterContext) callconv(.c) c_int,
    uninit: ?*const fn ([*c]FilterContext) callconv(.c) void,
    formats: extern union {
        query_func: ?*const fn ([*c]FilterContext) callconv(.c) c_int,
        pixels_list: [*c]const PixelFormat,
        samples_list: [*c]const SampleFormat,
        pix_fmt: PixelFormat,
        sample_fmt: SampleFormat,
    },
    priv_size: c_int,
    flags_internal: c_int,
    process_command: ?*const fn ([*c]FilterContext, [*c]const u8, [*c]const u8, [*c]u8, c_int, c_int) callconv(.c) c_int,
    activate: ?*const fn ([*c]FilterContext) callconv(.c) c_int,

    /// Get a filter definition matching the given name.
    ///
    /// Returns the filter definition, if any matching one is registered, or
    /// `null` if none found.
    pub const get_by_name = avfilter_get_by_name;
    extern fn avfilter_get_by_name(name: [*:0]const u8) ?*const Filter;
};

pub const FilterPad = opaque {};

pub const FilterFormatsConfig = extern struct {
    formats: ?*FilterFormats,
    samplerates: ?*FilterFormats,
    channel_layouts: ?*FilterChannelLayouts,
};

pub const FilterFormats = opaque {};
pub const FilterChannelLayouts = opaque {};

pub const RDFTransformType = enum(c_uint) {
    dft_r2c = 0,
    idft_c2r = 1,
    idft_r2c = 2,
    dft_c2r = 3,
};

pub const RDFTContext = opaque {
    pub fn init(nbits: c_int, trans: RDFTransformType) error{OutOfMemory}!*RDFTContext {
        return av_rdft_init(nbits, trans) orelse return error.OutOfMemory;
    }
    extern fn av_rdft_init(nbits: c_int, trans: RDFTransformType) ?*RDFTContext;

    pub const calc = av_rdft_calc;
    extern fn av_rdft_calc(s: *RDFTContext, data: [*]FFTSample) void;

    pub const end = av_rdft_end;
    extern fn av_rdft_end(s: *RDFTContext) void;
};
pub const FFTSample = f32;

pub const TXType = enum(c_uint) {
    float_fft = 0,
    double_fft = 2,
    int32_fft = 4,
    float_mdct = 1,
    double_mdct = 3,
    int32_mdct = 5,
    /// Real to complex and complex to real DFT.
    ///
    /// The forward transform performs a real-to-complex DFT of N samples to
    /// N/2+1 complex values.
    ///
    /// The inverse transform performs a complex-to-real DFT of N/2+1 complex
    /// values to N real samples. The output is not normalized, but can be
    /// made so by setting the scale value to 1.0/len.
    ///
    /// The inverse transform always overwrites the input.
    float_rdft = 6,
    double_rdft = 7,
    int32_rdft = 8,
    float_dct = 9,
    double_dct = 10,
    int32_dct = 11,
    float_dct_i = 12,
    double_dct_i = 13,
    int32_dct_i = 14,
    float_dst_i = 15,
    double_dst_i = 16,
    int32_dst_i = 17,

    pub fn SampleType(comptime t: TXType) type {
        return switch (t) {
            .float_fft,
            .float_mdct,
            .float_rdft,
            .float_dct,
            .float_dct_i,
            .float_dst_i,
            => f32,

            .double_fft,
            .double_mdct,
            .double_rdft,
            .double_dct,
            .double_dct_i,
            .double_dst_i,
            => f64,

            .int32_fft,
            .int32_mdct,
            .int32_rdft,
            .int32_dct,
            .int32_dct_i,
            .int32_dst_i,
            => i32,
        };
    }

    pub fn ScaleType(comptime t: TXType) type {
        return switch (t) {
            .float_fft,
            .float_mdct,
            .float_rdft,
            .float_dct,
            .float_dct_i,
            .float_dst_i,
            .int32_fft,
            .int32_mdct,
            .int32_rdft,
            .int32_dct,
            .int32_dct_i,
            .int32_dst_i,
            => f32,

            .double_fft,
            .double_mdct,
            .double_rdft,
            .double_dct,
            .double_dct_i,
            .double_dst_i,
            => f64,
        };
    }

    pub fn stride(t: TXType, inverse: bool) isize {
        return switch (t) {
            .float_fft,
            .float_dct,
            .float_dct_i,
            .float_dst_i,
            => @sizeOf(f32),

            .double_fft,
            .double_dct,
            .double_dct_i,
            .double_dst_i,
            => @sizeOf(f64),

            .int32_fft,
            .int32_dct,
            .int32_dct_i,
            .int32_dst_i,
            => @sizeOf(i32),

            .float_mdct => if (!inverse) @sizeOf(f32) else @sizeOf([2]ComplexFloat),
            .double_mdct => if (!inverse) @sizeOf(f64) else @sizeOf([2]ComplexFloat),
            .int32_mdct => if (!inverse) @sizeOf(i32) else @sizeOf([2]ComplexFloat),

            .float_rdft => if (!inverse) @sizeOf([2]f32) else @sizeOf([2]ComplexFloat),
            .double_rdft => if (!inverse) @sizeOf([2]f64) else @sizeOf([2]ComplexFloat),
            .int32_rdft => if (!inverse) @sizeOf([2]i32) else @sizeOf([2]ComplexFloat),
        };
    }
};

pub const TXFlags = packed struct(u64) {
    inplace: bool = false,
    unaligned: bool = false,
    full_imdct: bool = false,
    real_to_real: bool = false,
    real_to_imaginary: bool = false,
    _: u59 = 0,
};

pub const TXContext = opaque {
    /// Function pointer to a function to perform the transform.
    ///
    /// Using a different context than the one allocated during `av_tx_init` is not
    /// allowed.
    ///
    /// The out and in arrays must be aligned to the maximum required by the CPU
    /// architecture unless the `TXFlags.UNALIGNED` flag was set in `av_tx_init`.
    ///
    /// The stride must follow the constraints the transform type has specified.
    pub const Fn = fn (
        s: *TXContext,
        output_array: ?*anyopaque,
        input_array: ?*anyopaque,
        stride_in_bytes: isize,
    ) callconv(.c) void;

    /// Initialize a transform context with the given configuration.
    ///
    /// (i)MDCTs with an odd length are currently not supported.
    pub fn init(
        /// type type the type of transform
        comptime tx_type: TXType,
        /// whether to do an inverse or a forward transform
        inverse: bool,
        /// len the size of the transform in samples
        len: c_int,
        /// The value to scale the output if supported by type.
        scale: tx_type.ScaleType(),
        flags: TXFlags,
    ) Error!struct {
        context: *TXContext,
        tx_fn: *const Fn,
        stride_in_bytes: isize,

        pub fn tx(s: @This(), output_array: [*]tx_type.SampleType(), input_array: [*]tx_type.SampleType()) void {
            s.tx_fn(s.context, output_array, input_array, s.stride_in_bytes);
        }
    } {
        var ctx: ?*TXContext = null;
        var tx: ?*const Fn = null;
        _ = try wrap(av_tx_init(&ctx, &tx, tx_type, @intFromBool(inverse), len, &scale, flags));
        return .{
            .context = ctx.?,
            .tx_fn = tx.?,
            .stride_in_bytes = tx_type.stride(inverse),
        };
    }
    extern fn av_tx_init(
        ctx: *?*TXContext,
        tx: *?*const Fn,
        @"type": TXType,
        inv: c_int,
        len: c_int,
        scale: ?*const anyopaque,
        flags: TXFlags,
    ) c_int;

    pub fn uninit(ctx: *TXContext) void {
        var keep_your_dirty_hands_off_my_pointers_ffmpeg: ?*TXContext = ctx;
        av_tx_uninit(&keep_your_dirty_hands_off_my_pointers_ffmpeg);
    }
    extern fn av_tx_uninit(ctx: *?*TXContext) void;
};

pub const ComplexFloat = extern struct {
    re: f32,
    im: f32,
};

pub const StreamGroup = extern struct {
    av_class: *const Class,
    priv_data: ?*anyopaque,
    index: c_uint,
    id: i64,
    type: ParamsType,
    params: extern union {
        iamf_audio_element: ?*IAMFAudioElement,
        iamf_mix_presentation: ?*IAMFMixPresentation,
        tile_grid: *TileGrid,
    },
    metadata: Dictionary.Mutable,
    nb_streams: c_uint,
    streams: [*]*Stream,
    disposition: c_int,

    pub const ParamsType = enum(c_uint) {
        none = 0,
        iamf_audio_element = 1,
        iamf_mix_presentation = 2,
        tile_grid = 3,
    };

    pub const TileGrid = opaque {};
};

pub const IAMFAudioElement = opaque {};
pub const IAMFMixPresentation = opaque {};

pub const sws = struct {
    pub const Flags = packed struct(c_int) {
        fast_bilinear: bool = false,
        bilinear: bool = false,
        bicubic: bool = false,
        x: bool = false,
        point: bool = false,
        area: bool = false,
        bicublin: bool = false,
        gauss: bool = false,
        sinc: bool = false,
        lanczos: bool = false,
        spline: bool = false,
        unused11: u1 = 0,
        print_info: bool = false,
        /// not completely implemented
        /// internal chrominance subsampling info
        full_chr_h_int: bool = false,
        /// not completely implemented
        /// input subsampling info
        full_chr_h_inp: bool = false,
        /// not completely implemented
        direct_bgr: bool = false,
        src_v_chr_drop: u2 = 0,
        accurate_rnd: bool = false,
        bitexact: bool = false,
        unused20: u3 = 0,
        error_diffusion: bool = false,
        unused24: std.meta.Int(.unsigned, @bitSizeOf(c_int) - 24) = 0,
    };

    pub const Vector = extern struct {
        coeff: [*]f64,
        length: c_int,
    };

    pub const Filter = extern struct {
        lumH: ?*Vector,
        lumV: ?*Vector,
        chrH: ?*Vector,
        chrV: ?*Vector,
    };

    pub const Context = opaque {
        /// Allocate an empty sws.Context. This must be filled and passed to
        /// init().
        pub fn alloc() error{OutOfMemory}!*Context {
            return sws_alloc_context() orelse error.OutOfMemory;
        }
        extern fn sws_alloc_context() ?*sws.Context;

        /// Initialize the swscaler context sws_context.
        pub fn init(sws_context: *Context, srcFilter: ?*sws.Filter, dstFilter: ?*sws.Filter) Error!void {
            _ = try wrap(sws_init_context(sws_context, srcFilter, dstFilter));
        }
        extern fn sws_init_context(sws_context: *sws.Context, srcFilter: ?*sws.Filter, dstFilter: ?*sws.Filter) c_int;

        /// Free the swscaler context swsContext.
        pub const free = sws_freeContext;
        extern fn sws_freeContext(swsContext: ?*sws.Context) void;

        /// Allocate and return an sws.Context. You need it to perform
        /// scaling/conversion operations using sws.Context.scale().
        pub fn get(srcW: c_int, srcH: c_int, srcFormat: PixelFormat, dstW: c_int, dstH: c_int, dstFormat: PixelFormat, flags: Flags, srcFilter: ?*sws.Filter, dstFilter: ?*sws.Filter, param: ?[*]const f64) error{OutOfMemory}!void {
            return sws_getContext(srcW, srcH, srcFormat, dstW, dstH, dstFormat, flags, srcFilter, dstFilter, param) orelse error.OutOfMemory;
        }
        extern fn sws_getContext(srcW: c_int, srcH: c_int, srcFormat: PixelFormat, dstW: c_int, dstH: c_int, dstFormat: PixelFormat, flags: sws.Flags, srcFilter: ?*sws.Filter, dstFilter: ?*sws.Filter, ?[*]const f64) ?*sws.Context;

        /// Scale the image slice in srcSlice and put the resulting scaled
        /// slice in the image in dst. A slice is a sequence of consecutive
        /// rows in an image.
        ///
        /// Slices have to be provided in sequential order.
        pub fn scale(c: *Context, srcSlice: [*]const [*]const u8, srcStride: [*]const c_int, srcSliceY: c_int, srcSliceH: c_int, dst: [*]const [*]u8, dstStride: [*]const c_int) Error!void {
            _ = try wrap(sws_scale(c, srcSlice, srcStride, srcSliceY, srcSliceH, dst, dstStride));
        }
        extern fn sws_scale(c: *sws.Context, srcSlice: [*]const [*]const u8, srcStride: [*]const c_int, srcSliceY: c_int, srcSliceH: c_int, dst: [*]const [*]u8, dstStride: [*]const c_int) c_int;

        /// Scale source data from src and write the output to dst.
        pub fn scaleFrame(c: *Context, dst: *Frame, src: *const Frame) Error!void {
            _ = try wrap(sws_scale_frame(c, dst, src));
        }
        extern fn sws_scale_frame(c: *sws.Context, dst: *Frame, src: *const Frame) c_int;
    };
};

pub const SwrContext = opaque {
    pub fn alloc() error{OutOfMemory}!*SwrContext {
        return swr_alloc() orelse return error.OutOfMemory;
    }
    extern fn swr_alloc() ?*SwrContext;

    pub fn deinit(s: *SwrContext) void {
        var keep_your_dirty_hands_off_my_pointers_ffmpeg: ?*SwrContext = s;
        swr_free(&keep_your_dirty_hands_off_my_pointers_ffmpeg);
    }
    extern fn swr_free(*?*SwrContext) void;

    pub fn init(
        out_ch_layout: *const ChannelLayout, out_sample_fmt: SampleFormat, out_sample_rate: c_uint,
        in_ch_layout: *const ChannelLayout, in_sample_fmt: SampleFormat, in_sample_rate: c_uint,
        log_offset: c_int, log_ctx: ?*anyopaque,
    ) Error!*SwrContext {
        var ps: ?*SwrContext = try alloc();
        _ = try wrap(swr_alloc_set_opts2(&ps,
            out_ch_layout, out_sample_fmt, out_sample_rate,
            in_ch_layout, in_sample_fmt, in_sample_rate,
            log_offset, log_ctx,
        ));
        const swr = ps.?;
        errdefer swr.deinit();

        _ = try wrap(swr_init(swr));
        return swr;
    }
    extern fn swr_alloc_set_opts2(
        *?*SwrContext,
        *const ChannelLayout, SampleFormat, c_uint,
        *const ChannelLayout, SampleFormat, c_uint,
        c_int, ?*anyopaque,
    ) c_int;
    extern fn swr_init(s: *SwrContext) c_int;


    /// Convert audio.
    ///
    /// If more input is provided than output space, then the input will be buffered.
    /// You can avoid this buffering by using swr_get_out_samples() to retrieve an
    /// upper bound on the required number of output samples for the given number of
    /// input samples. Conversion will run directly without copying whenever possible.
    ///
    /// Returns the number of samples output per channel
    pub fn convert(
        /// allocated Swr context, with parameters set
        s: *SwrContext,
        /// output buffers, only the first one need be set in case of packed audio
        out: *const [*]u8,
        /// amount of space available for output in samples per channel
        out_count: c_uint,
        /// input buffers, only the first one need to be set in case of packed audio.
        ///
        /// set to `null` to flush the last few samples out at the end.
        in: ?*const [*]const u8,
        /// number of input samples available in one channel
        in_count: c_uint,
    ) Error!c_uint {
        return wrap(swr_convert(s, out, out_count, in, in_count));
    }
    extern fn swr_convert(
        *SwrContext,
        *const [*]u8, c_uint,
        ?*const [*]const u8, c_uint,
    ) c_int;
};
