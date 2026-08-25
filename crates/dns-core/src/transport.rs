use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::error::{DnsCoreError, Result};
use crate::query::{QueryOptions, build_query};
use crate::response::{DnsResponse, QueryResult, Transport};

pub fn exchange(server: IpAddr, port: u16, options: &QueryOptions) -> Result<QueryResult> {
    let mut last_error = None;
    let attempts = options.retries.max(1);

    for _ in 0..attempts {
        match perform_exchange(server, port, options) {
            Ok(result) => return Ok(result),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| DnsCoreError::Parse("query failed".into())))
}

fn perform_exchange(server: IpAddr, port: u16, options: &QueryOptions) -> Result<QueryResult> {
    let wire = build_query(options)?;
    let started = Instant::now();
    let response_bytes = match options.transport {
        Transport::Udp => udp_exchange(server, port, &wire, options.timeout)?,
        Transport::Tcp => tcp_exchange(server, port, &wire, options.timeout)?,
    };
    let rtt = started.elapsed();
    let response = DnsResponse::from_wire(&response_bytes)?;

    Ok(QueryResult {
        server,
        transport: options.transport,
        qname: options.qname.clone(),
        qtype: options.qtype.to_string(),
        rtt,
        response,
    })
}

fn udp_exchange(server: IpAddr, port: u16, wire: &[u8], timeout: Duration) -> Result<Vec<u8>> {
    let socket = match server {
        IpAddr::V4(_) => UdpSocket::bind("0.0.0.0:0"),
        IpAddr::V6(_) => UdpSocket::bind("[::]:0"),
    }
    .map_err(|error| DnsCoreError::Parse(error.to_string()))?;

    socket
        .set_read_timeout(Some(timeout))
        .map_err(|error| DnsCoreError::Parse(error.to_string()))?;
    socket
        .set_write_timeout(Some(timeout))
        .map_err(|error| DnsCoreError::Parse(error.to_string()))?;

    let target = SocketAddr::new(server, port);
    socket
        .send_to(wire, target)
        .map_err(|error| DnsCoreError::Parse(error.to_string()))?;

    let mut buffer = vec![0_u8; 65_536];
    let read = socket
        .recv_from(&mut buffer)
        .map_err(|error| DnsCoreError::Parse(error.to_string()))?
        .0;
    buffer.truncate(read);
    Ok(buffer)
}

fn tcp_exchange(server: IpAddr, port: u16, wire: &[u8], timeout: Duration) -> Result<Vec<u8>> {
    let target = SocketAddr::new(server, port);
    let mut stream = TcpStream::connect_timeout(&target, timeout)
        .map_err(|error| DnsCoreError::Parse(error.to_string()))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| DnsCoreError::Parse(error.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| DnsCoreError::Parse(error.to_string()))?;

    let len = (wire.len() as u16).to_be_bytes();
    stream
        .write_all(&len)
        .and_then(|_| stream.write_all(wire))
        .map_err(|error| DnsCoreError::Parse(error.to_string()))?;

    let mut len_buf = [0_u8; 2];
    stream
        .read_exact(&mut len_buf)
        .map_err(|error| DnsCoreError::Parse(error.to_string()))?;
    let response_len = u16::from_be_bytes(len_buf) as usize;
    let mut buffer = vec![0_u8; response_len];
    stream
        .read_exact(&mut buffer)
        .map_err(|error| DnsCoreError::Parse(error.to_string()))?;
    Ok(buffer)
}
