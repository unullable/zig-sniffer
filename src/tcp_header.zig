const std = @import("std");
const mem = std.mem;
const print = std.debug.print;
const assert = std.debug.assert;

pub const TcpHdr = struct {
    tcp_src_port: u16,
    tcp_dst_port: u16,
    tcp_seq: u32,
    tcp_ack_seq: u32,
    tcp_offset: u8, // data offset + reserved
    tcp_flag: u8,
    tcp_window: u16,
    tcp_csum: u16,
    tcp_urgent: u16,

    pub fn get_src_port(self: TcpHdr) u16 {
        return self.tcp_src_port;
    }

    pub fn get_dst_port(self: TcpHdr) u16 {
        return self.tcp_dst_port;
    }

    pub fn get_seq(self: TcpHdr) u32 {
        return self.tcp_seq;
    }

    pub fn get_ack_seq(self: TcpHdr) u32 {
        return self.tcp_ack_seq;
    }

    pub fn get_doff(self: TcpHdr) u4 {
        return @intCast((self.tcp_offset & 0b11110000) >> 4);
    }

    pub fn get_res1(self: TcpHdr) u4 {
        return @truncate(self.tcp_offset);
    }

    pub fn get_flag_cwr(self: TcpHdr) u1 {
        return @intCast((self.tcp_flag & 0b10000000) >> 7);
    }

    pub fn get_flag_ece(self: TcpHdr) u1 {
        return @intCast((self.tcp_flag & 0b01000000) >> 6);
    }

    pub fn get_flag_urg(self: TcpHdr) u1 {
        return @intCast((self.tcp_flag & 0b00100000) >> 5);
    }

    pub fn get_flag_ack(self: TcpHdr) u1 {
        return @intCast((self.tcp_flag & 0b00010000) >> 4);
    }

    pub fn get_flag_psh(self: TcpHdr) u1 {
        return @intCast((self.tcp_flag & 0b00001000) >> 3);
    }

    pub fn get_flag_rst(self: TcpHdr) u1 {
        return @intCast((self.tcp_flag & 0b00000100) >> 2);
    }

    pub fn get_flag_syn(self: TcpHdr) u1 {
        return @intCast((self.tcp_flag & 0b00000010) >> 1);
    }

    pub fn get_flag_fin(self: TcpHdr) u1 {
        return @truncate(self.tcp_flag);
    }

    pub fn get_window(self: TcpHdr) u16 {
        return self.tcp_window;
    }

    pub fn get_csum(self: TcpHdr) u16 {
        return self.tcp_csum;
    }

    pub fn get_urg_ptr(self: TcpHdr) u16 {
        return self.tcp_urgent;
    }

    pub fn parse(self: *TcpHdr, packet: []u8) void {
        self.tcp_src_port = mem.readVarInt(u16, packet[0..2], .big);
        self.tcp_dst_port = mem.readVarInt(u16, packet[2..4], .big);
        self.tcp_seq = mem.readVarInt(u32, packet[4..8], .big);
        self.tcp_ack_seq = mem.readVarInt(u32, packet[8..12], .big);
        self.tcp_offset = mem.readVarInt(u8, packet[12..13], .big);
        self.tcp_flag = mem.readVarInt(u8, packet[13..14], .big);
        self.tcp_window = mem.readVarInt(u16, packet[14..16], .big);
        self.tcp_csum = mem.readVarInt(u16, packet[16..18], .big);
        self.tcp_urgent = mem.readVarInt(u16, packet[18..20], .big);
    }

    pub fn print_tcp_header(self: TcpHdr) void {
        print("--- Tcp Header ---\n", .{});
        print("sport: {d}\n", .{self.get_src_port()});
        print("dport: {d}\n", .{self.get_dst_port()});
        print("seq: {d}\n", .{self.get_seq()});
        print("ack: {d}\n", .{self.get_ack_seq()});
        print("doff: {d}\n", .{self.get_doff()});
        print("res1: {d}\n", .{self.get_res1()});
        print("\n--- Flags ----\n", .{});
        print("cwr: {d}\n", .{self.get_flag_cwr()});
        print("ece: {d}\n", .{self.get_flag_ece()});
        print("urg: {d}\n", .{self.get_flag_urg()});
        print("ack: {d}\n", .{self.get_flag_ack()});
        print("psh: {d}\n", .{self.get_flag_psh()});
        print("rst: {d}\n", .{self.get_flag_rst()});
        print("syn: {d}\n", .{self.get_flag_syn()});
        print("fin: {d}\n", .{self.get_flag_fin()});
        print("window: {d}\n", .{self.get_window()});
        print("csum: {d}\n", .{self.get_csum()});
        print("UrgPtr: {d}\n", .{self.get_urg_ptr()});
    }

    pub fn print_tcp_payload(_: TcpHdr, buf: []u8) void {
        print("\n// Data Payload \\\\\n", .{});
        print("{s}\n", .{buf});
        print("\\\\ Data Payload //\n", .{});
    }
};
