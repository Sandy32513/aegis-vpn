use std::io;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TunConfig {
    pub name: String,
    pub address_cidr: String,
    pub mtu: u32,
}

pub trait TunDevice: Send {
    fn name(&self) -> &str;
    fn mtu(&self) -> u32;
    fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()>;

    /// Read multiple packets in a batch into a contiguous buffer.
    /// Returns the number of packets successfully read.
    /// Default implementation calls read_packet in a loop.
    fn read_packets_batch(&mut self, _buf: &mut [u8], max_packets: usize) -> io::Result<usize> {
        // Default: single-packet fallback
        if max_packets == 0 {
            return Ok(0);
        }
        // Call the single-packet implementation
        match self.read_packet(_buf) {
            Ok(_) => Ok(1),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }
    }
}
