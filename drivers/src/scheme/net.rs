use super::Scheme;
use crate::{DeviceError, DeviceResult};
use alloc::string::String;
use alloc::vec::Vec;
use smoltcp::wire::{EthernetAddress, IpCidr, Ipv4Cidr};

pub trait NetScheme: Scheme {
    fn recv(&self, buf: &mut [u8]) -> DeviceResult<usize>;
    fn send(&self, buf: &[u8]) -> DeviceResult<usize>;
    fn get_mac(&self) -> EthernetAddress;
    fn get_ifname(&self) -> String;
    fn get_ip_address(&self) -> Vec<IpCidr>;
    fn set_ipv4_address(&self, _cidr: Ipv4Cidr) -> DeviceResult {
        Err(DeviceError::NotSupported)
    }
    fn poll(&self) -> DeviceResult;
}
