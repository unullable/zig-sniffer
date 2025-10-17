const std = @import("std");
const posix = std.posix;
const print = std.debug.print;
const IpHdr = @import("ip_header.zig").IpHdr;
const TcpHdr = @import("tcp_header.zig").TcpHdr;
const UdpHdr = @import("udp_header.zig").UdpHdr;
const IcmpHdr = @import("icmp_header.zig").IcmpHdr;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2) {
        print("usage: {s} <protocol(tcp/udp/icmp)>\n", .{args[0]});
        return;
    }

    var proto: u32 = undefined;
    if (std.mem.indexOf(u8, args[1], "tcp") == 0) {
        proto = posix.IPPROTO.TCP;
    } else if (std.mem.indexOf(u8, args[1], "udp") == 0) {
        proto = posix.IPPROTO.UDP;
    } else if (std.mem.indexOf(u8, args[1], "icmp") == 0) {
        proto = posix.IPPROTO.ICMP;
    }

    const sniffsock = try posix.socket(posix.AF.INET, posix.SOCK.RAW, proto);
    defer posix.close(sniffsock);

    var packet: [0xffff]u8 = undefined;

    var iphdr: IpHdr = undefined;
    var tcphdr: TcpHdr = undefined;
    var udphdr: UdpHdr = undefined;
    var icmphdr: IcmpHdr = undefined;

    while (true) {
        const buffer_len = try posix.recvfrom(sniffsock, &packet, 0, null, null);

        if (buffer_len < 20) {
            print("recvfrom error: invalid packet!\n", .{});
            continue;
        }

        iphdr.parse(&packet);
        iphdr.print_ip_header();

        const iphdr_len: usize = @as(u8, iphdr.get_ihl()) * 4;

        switch (iphdr.get_proto()) {
            .tcp => {
                tcphdr.parse(packet[iphdr_len..]);

                tcphdr.print_tcp_header();

                const doff: usize = @as(u8, tcphdr.get_doff()) * 4;
                tcphdr.print_tcp_payload(packet[iphdr_len + doff .. buffer_len]);
            },
            .udp => {
                udphdr.parse(packet[iphdr_len..]);
                udphdr.print_udp_header();
                udphdr.print_udp_payload(packet[iphdr_len + udphdr.get_header_size() .. buffer_len]);
            },
            .icmp => {
                icmphdr.parse(packet[iphdr_len..]);
                icmphdr.print_icmp_header();
                icmphdr.print_icmp_payload(packet[iphdr_len + icmphdr.get_header_size() .. buffer_len]);
            },
            .igmp => {
                // todo
                unreachable;
            },
        }
    }
}
