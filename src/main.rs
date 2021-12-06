use std::{
    net::{IpAddr, Ipv4Addr},
    time::Instant,
};

use pnet::{
    packet::{
        icmp::{echo_request::MutableEchoRequestPacket, IcmpTypes},
        ip::IpNextHeaderProtocols,
        ipv4::MutableIpv4Packet,
        util, MutablePacket,
    },
    transport::{self, transport_channel, TransportChannelType},
};
use structopt::StructOpt;

static DEFAULT_BUFFER_SIZE: usize = 1024;
static IPV4_HEADER_LEN: usize = 21;
static ICMP_HEADER_LEN: usize = 8;
static ICMP_PAYLOAD_LEN: usize = 32;
static DEFAULT_MAX_HOP: u8 = 30;

#[derive(Debug, StructOpt)]
#[structopt(name = "rustyroute", about = "Rust toy clone of traceroute")]
struct CliOptions {
    #[structopt(short, long)]
    url: String,
}

fn main() -> anyhow::Result<()> {
    let cli_options = CliOptions::from_args();
    let icmp_packet_size = ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN;
    let ip_packet_size = icmp_packet_size + IPV4_HEADER_LEN;
    let channel_type = TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp);
    let (mut tx, mut rx) = transport_channel(DEFAULT_BUFFER_SIZE, channel_type)?;
    let mut response_iter = transport::icmp_packet_iter(&mut rx);

    let traceroute_destination = cli_options.url.parse::<Ipv4Addr>()?;
    // NOTE: Can accept strings if we do a DNS lookup to get the address
    // Not doing any of that as it will involve handling ipv6 too, which one can ignore when the
    // purpose of an app is to learn
    println!(
        "traceroute to {} (ip: {}), {} byte packets",
        traceroute_destination, traceroute_destination, ip_packet_size
    );

    for ttl in 1..DEFAULT_MAX_HOP {
        let mut buffer_ip = vec![0u8; ip_packet_size];
        let mut buffer_icmp = vec![0u8; icmp_packet_size];

        let icmp_packet = create_icmp_packet(
            &mut buffer_ip,
            &mut buffer_icmp,
            traceroute_destination,
            ttl,
        )?;
        let start_time = Instant::now();
        // NOTE: You can send multiple packets like real traceroute to compare multiple rtts
        tx.send_to(icmp_packet, IpAddr::V4(traceroute_destination))?;

        let (_resopnse_packet, ip_addr) = response_iter.next()?;
        let round_trip_time = start_time.elapsed().as_millis();

        // NOTE: This check might not work for all the cases?
        // Ideal way would be to check for `PORT_UNREACHABLE` packet type
        if ip_addr == traceroute_destination {
            break;
        }

        // We are just assuming that the response ICMP that we got here was for the packet that we
        // sent out and also it has the TTL_EXPIRED type. Ideally we should check if that is
        // actully the case.
        println!(
            "{:>3}  {} ({}) {}ms",
            ttl,
            // NOTE: Perform reverse dns lookup to see human readable address (we will assume it's
            // the same as ip)
            ip_addr.to_string(),
            ip_addr.to_string(),
            round_trip_time
        );
    }

    Ok(())
}

fn create_icmp_packet<'a>(
    buffer_ip: &'a mut [u8],
    buffer_icmp: &'a mut [u8],
    dest: Ipv4Addr,
    ttl: u8,
) -> anyhow::Result<MutableIpv4Packet<'a>> {
    let mut icmp_packet = MutableEchoRequestPacket::new(buffer_icmp)
        .ok_or_else(|| anyhow::anyhow!("Buffer is less than minimum required packet size"))?;
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    let checksum = util::checksum(&icmp_packet.packet_mut(), 2);
    icmp_packet.set_checksum(checksum);

    let mut ipv4_packet = MutableIpv4Packet::new(buffer_ip)
        .ok_or_else(|| anyhow::anyhow!("Buffer is less than minimum required packet size"))?;
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(IPV4_HEADER_LEN as u8);
    ipv4_packet.set_total_length((IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN) as u16);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_destination(dest);
    ipv4_packet.set_payload(icmp_packet.packet_mut());

    Ok(ipv4_packet)
}
