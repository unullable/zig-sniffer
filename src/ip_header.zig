const std = @import("std");
const print = std.debug.print;
const mem = std.mem;

const Protocol = enum(u8) {
    icmp = 1,
    igmp = 2,
    tcp = 6,
    udp = 17,
};

pub const IpHdr = struct {
    ip_version_and_header_len: u8,
    ip_tos: u8,
    ip_tot_len: u16,
    ip_id: u16,
    ip_frag_off: u16,
    ip_ttl: u8,
    ip_protocol: u8,
    ip_csum: u16,
    ip_src: u32,
    ip_dst: u32,

    pub fn get_ip_version(self: IpHdr) u4 {
        return @intCast((self.ip_version_and_header_len & 0b11110000) >> 4);
    }

    pub fn get_ihl(self: IpHdr) u4 {
        return @truncate(self.ip_version_and_header_len);
    }

    pub fn get_tos(self: IpHdr) u8 {
        return self.ip_tos;
    }

    pub fn get_ttl(self: IpHdr) u8 {
        return self.ip_ttl;
    }

    pub fn get_proto(self: IpHdr) Protocol {
        return @enumFromInt(self.ip_protocol);
    }

    pub fn get_total_len(self: IpHdr) u16 {
        return self.ip_tot_len;
    }

    pub fn get_id(self: IpHdr) u16 {
        return self.ip_id;
    }

    pub fn get_frag_off(self: IpHdr) u16 {
        return self.ip_frag_off;
    }

    pub fn get_csum(self: IpHdr) u16 {
        return self.ip_csum;
    }

    pub fn get_src_address(self: IpHdr) u32 {
        return self.ip_src;
    }

    pub fn get_dst_address(self: IpHdr) u32 {
        return self.ip_dst;
    }

    pub fn parse(self: *IpHdr, packet: []const u8) void {
        self.ip_version_and_header_len = mem.readVarInt(u8, packet[0..1], .big);
        self.ip_tos = mem.readVarInt(u8, packet[1..2], .big);
        self.ip_tot_len = mem.readVarInt(u16, packet[2..4], .big);
        self.ip_id = mem.readVarInt(u16, packet[4..6], .big);
        self.ip_frag_off = mem.readVarInt(u16, packet[6..8], .big);
        self.ip_ttl = mem.readVarInt(u8, packet[8..9], .big);
        self.ip_protocol = mem.readVarInt(u8, packet[9..10], .big);
        self.ip_csum = mem.readVarInt(u16, packet[10..12], .big);
        self.ip_src = mem.readVarInt(u32, packet[12..16], .big);
        self.ip_dst = mem.readVarInt(u32, packet[16..20], .big);
    }

    fn ip_to_str(ip4: u32) [4]u8 {
        return [4]u8{
            @intCast(@as(u32, ip4 >> 24) & 0xff),
            @intCast(@as(u32, ip4 >> 16) & 0xff),
            @intCast(@as(u32, ip4 >> 8) & 0xff),
            @intCast(@as(u32, ip4) & 0xff),
        };
    }

    pub fn print_ip_header(self: IpHdr) void {
        print("\n------------ IP HEADER -------------\n", .{});
        print("version: {d}\n", .{self.get_ip_version()});
        print("ihl: {d}\n", .{self.get_ihl()});
        print("tos: {d}\n", .{self.get_tos()});
        print("total len: {d}\n", .{self.get_total_len()});
        print("id: {d}\n", .{self.get_id()});
        print("frag_off: {d}\n", .{self.get_frag_off()});
        print("ttl: {d}\n", .{self.get_ttl()});
        print("protocol: {}\n", .{self.get_proto()});
        print("check: {d}\n", .{self.get_csum()});
        print("saddr: {any}\n", .{ip_to_str(self.get_src_address())});
        print("daddr: {any}\n", .{ip_to_str(self.get_dst_address())});
    }
};
