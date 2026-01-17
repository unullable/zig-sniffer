const std = @import("std");
const Logger = @import("logger.zig").Logger;
const mem = std.mem;
const print = std.debug.print;

const IcmpType = enum(u8) {
    echo_reply = 0,
    destination_unreachable = 3,
    redirect = 5,
    echo_request = 8,
    time_exceeded = 11,
};

pub const IcmpHdr = struct {
    icmp_type: u8,
    icmp_code: u8,
    icmp_csum: u16,
    icmp_id: u16,
    icmp_seq: u16,

    pub fn get_header_size(_: IcmpHdr) usize {
        return (@sizeOf(u8) * 2) + (@sizeOf(u16) * 3);
    }

    pub fn get_type(self: IcmpHdr) IcmpType {
        return @enumFromInt(self.icmp_type);
    }

    pub fn get_code(self: IcmpHdr) u8 {
        return self.icmp_code;
    }

    pub fn get_csum(self: IcmpHdr) u16 {
        return self.icmp_csum;
    }

    pub fn get_id(self: IcmpHdr) u16 {
        return self.icmp_id;
    }

    pub fn get_seq(self: IcmpHdr) u16 {
        return self.icmp_seq;
    }

    pub fn parse(self: *IcmpHdr, packet: []u8) void {
        self.icmp_type = mem.readVarInt(u8, packet[0..1], .big);
        self.icmp_code = mem.readVarInt(u8, packet[1..2], .big);
        self.icmp_csum = mem.readVarInt(u16, packet[2..4], .big);
        self.icmp_id = mem.readVarInt(u16, packet[4..6], .big);
        self.icmp_seq = mem.readVarInt(u16, packet[6..8], .big);
    }

    pub fn print_icmp_header(self: IcmpHdr) void {
        print("type: {}\n", .{self.get_type()});
        print("code: {d}\n", .{self.get_code()});
        print("csum: {d}\n", .{self.get_csum()});
        print("id: {d}\n", .{self.get_id()});
        print("seq: {d}\n", .{self.get_seq()});
    }

    pub fn print_icmp_payload(_: IcmpHdr, buf: []u8) void {
        print("\n// Data Payload \\\\ \n", .{});
        print("{s}\n", .{buf});
        print("\\\\ Data Payload //\n", .{});
    }

    pub fn log_icmp_payload(_: IcmpHdr, buf: []u8) !void {
        const logger = Logger.init("sniffer.icmp.log");
        try logger.write("// ICMP Data Payload [START] \\ \n");
        try logger.write(buf);
        try logger.write("\\\\ ICMP Data Payload [END] //\n",);
        try logger.write(buf);
    }
};
