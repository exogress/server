use bytes::Buf;
use std::{
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

const IPV4: u16 = 1;
const IPV6: u16 = 2;

pub fn parse_ecs(buf: &[u8]) -> anyhow::Result<IpAddr> {
    let mut c = Cursor::new(buf);

    let family = c.get_u16();
    let number_of_left_bits = c.get_u8();

    if family == IPV4 {
        const ADDR_LEN: usize = 4;

        let mut addr: Vec<u8> = Vec::from(&buf[4..]);
        if addr.len() > ADDR_LEN {
            bail!("bad addr length")
        }
        if addr.len() < ADDR_LEN {
            addr.resize(ADDR_LEN, 0);
        }
        if number_of_left_bits >= (ADDR_LEN * 8) as u8 {
            bail!("bad addr prefix")
        }

        let byte = Cursor::new(addr).get_u32() & !(u32::MAX >> number_of_left_bits);
        let ip = Ipv4Addr::from(byte).into();

        return Ok(ip);
    } else if family == IPV6 {
        const ADDR_LEN: usize = 16;

        let mut addr: Vec<u8> = Vec::from(&buf[4..]);
        if addr.len() > ADDR_LEN {
            bail!("bad addr length")
        }
        if addr.len() < ADDR_LEN {
            addr.resize(ADDR_LEN, 0);
        }
        if number_of_left_bits >= (ADDR_LEN * 8) as u8 {
            bail!("bad addr prefix")
        }
        let byte = Cursor::new(addr).get_u128() & !(u128::MAX >> number_of_left_bits);
        let ip = Ipv6Addr::from(byte).into();

        return Ok(ip);
    } else {
        bail!("unknown family")
    }
}
