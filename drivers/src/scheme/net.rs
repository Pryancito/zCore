use super::Scheme;
use crate::{DeviceError, DeviceResult};
use alloc::string::String;
use alloc::vec::Vec;
use smoltcp::wire::{EthernetAddress, IpCidr, Ipv4Cidr};

pub trait NetScheme: Scheme {
    fn recv(&self, buf: &mut [u8]) -> DeviceResult<usize>;
    fn send(&self, buf: &[u8]) -> DeviceResult<usize>;
    fn can_recv(&self) -> bool {
        true
    }
    fn can_send(&self) -> bool {
        true
    }
    fn get_mac(&self) -> EthernetAddress;
    fn get_ifname(&self) -> String;
    fn get_ip_address(&self) -> Vec<IpCidr>;
    fn set_ipv4_address(&self, _cidr: Ipv4Cidr) -> DeviceResult {
        Err(DeviceError::NotSupported)
    }
    fn add_route(&self, _cidr: IpCidr, _gateway: Option<smoltcp::wire::IpAddress>) -> DeviceResult {
        Err(DeviceError::NotSupported)
    }
    fn poll(&self) -> DeviceResult;
}
