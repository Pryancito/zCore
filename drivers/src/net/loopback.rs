// smoltcp
use smoltcp::{iface::Interface, phy::Loopback, time::Instant};

use crate::net::get_sockets;
use alloc::sync::Arc;

use alloc::string::String;
use lock::Mutex;

use crate::scheme::{NetScheme, Scheme, RouteInfo};
use crate::{DeviceError, DeviceResult};

use alloc::vec::Vec;
use smoltcp::wire::EthernetAddress;
use smoltcp::wire::{IpCidr, Ipv4Cidr};

#[derive(Clone)]
pub struct LoopbackInterface {
    pub iface: Arc<Mutex<Interface<'static, Loopback>>>,
    pub name: String,
    pub routes: Arc<Mutex<Vec<RouteInfo>>>,
}

impl Scheme for LoopbackInterface {
    fn name(&self) -> &str {
        "loopback"
    }

    fn handle_irq(&self, _cause: usize) {}
}

impl NetScheme for LoopbackInterface {
    fn recv(&self, _buf: &mut [u8]) -> DeviceResult<usize> {
        unimplemented!()
    }
    fn send(&self, _buf: &[u8]) -> DeviceResult<usize> {
        unimplemented!()
    }
    fn poll(&self) -> DeviceResult {
        let timestamp = Instant::from_micros(crate::net::timer_now_as_micros() as i64);
        let sockets = get_sockets();
        let mut sockets = sockets.lock();
        match self.iface.lock().poll(&mut sockets, timestamp) {
            Ok(_) => Ok(()),
            Err(err) => {
                debug!("poll got err {}", err);
                Err(DeviceError::IoError)
            }
        }
    }

    fn get_mac(&self) -> EthernetAddress {
        self.iface.lock().ethernet_addr()
    }

    fn get_ifname(&self) -> String {
        self.name.clone()
    }

    fn get_ip_address(&self) -> Vec<IpCidr> {
        Vec::from(self.iface.lock().ip_addrs())
    }
    
    fn add_route(&self, cidr: IpCidr, gateway: Option<smoltcp::wire::IpAddress>) -> DeviceResult {
        self.routes.lock().push(RouteInfo { dst: cidr, gateway });
        Ok(())
    }

    fn del_route(&self, cidr: IpCidr, _gateway: Option<smoltcp::wire::IpAddress>) -> DeviceResult {
        self.routes.lock().retain(|r| r.dst != cidr);
        Ok(())
    }

    fn get_routes(&self) -> Vec<RouteInfo> {
        let iface = self.iface.lock();
        let mut res = Vec::new();
        
        // 1. Add tracked routes
        res.extend(self.routes.lock().clone());

        // 2. Add direct routes
        for cidr in iface.ip_addrs() {
            if let IpCidr::Ipv4(v4) = cidr {
                if v4.prefix_len() > 0 {
                    res.push(RouteInfo {
                        dst: IpCidr::Ipv4(v4.network()),
                        gateway: None,
                    });
                }
            }
        }
        res
    }
}
