const std = @import("std");
const fs = std.fs;

pub const Logger = struct {
    file_path: []const u8,

    pub fn init(file_path: []const u8) Logger {
        return Logger{
            .file_path = file_path,
        };
    }

    pub fn write(self: Logger, data: []const u8) !void {
        var file: fs.File = undefined;
        file = std.fs.cwd().openFile(self.file_path, .{ .mode = .write_only }) catch |err| switch(err) {
            fs.File.OpenError.FileNotFound => try std.fs.cwd().createFile(self.file_path, .{}),
            else => unreachable
        };
        defer file.close();

        try file.seekFromEnd(0);
        try file.writeAll(data);
        try file.writeAll("\n");
    }
};

