const std = @import("std");
const Logger = @import("logger.zig").Logger;
const mem = std.mem;
const print = std.debug.print;

pub const UdpHdr = struct {
    udp_source: u16,
    udp_dest: u16,
    udp_len: u16,
    udp_check: u16,

    pub fn get_header_size(_: UdpHdr) usize {
        return @sizeOf(u16) * 4;
    }

    pub fn get_source(self: UdpHdr) u16 {
        return self.udp_source;
    }

    pub fn get_dest(self: UdpHdr) u16 {
        return self.udp_dest;
    }

    pub fn get_len(self: UdpHdr) u16 {
        return self.udp_len;
    }

    pub fn get_check(self: UdpHdr) u16 {
        return self.udp_check;
    }

    pub fn parse(self: *UdpHdr, packet: []u8) void {
        self.udp_source = mem.readVarInt(u16, packet[0..2], .big);
        self.udp_dest = mem.readVarInt(u16, packet[2..4], .big);
        self.udp_len = mem.readVarInt(u16, packet[4..6], .big);
        self.udp_check = mem.readVarInt(u16, packet[6..8], .big);
    }

    pub fn print_udp_header(self: UdpHdr) void {
        print("source: {d}\n", .{self.get_source()});
        print("destination: {d}\n", .{self.get_dest()});
        print("length: {d}\n", .{self.get_len()});
        print("checksum: {d}\n", .{self.get_check()});
    }

    pub fn print_udp_payload(_: UdpHdr, buf: []u8) void {
        print("\n// UDP Data Payload \\\\ \n", .{});
        print("{s}", .{buf});
        print("\n\\\\ UDP Data Payload //\n", .{});
    }

    pub fn log_udp_payload(_: UdpHdr, buf: []u8) !void {
        const logger = Logger.init("sniffer.udp.log");
        try logger.write("\n// UDP Data Payload \\\\ \n");
        try logger.write(buf);
        try logger.write("\n \\\\ UDP Data Payload //\n");
    }
};
