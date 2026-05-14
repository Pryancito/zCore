use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use lock::Mutex;

use smoltcp::iface::*;
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
// use smoltcp::socket::SocketSet;
use smoltcp::time::Instant;
use smoltcp::wire::*;
use smoltcp::Result;

use super::realtek::rtl8211f::{self, RTL8211F};
use super::{timer_now_as_micros, ProviderImpl, PAGE_SIZE};

use crate::net::get_sockets;
use crate::scheme::{NetScheme, RouteInfo, Scheme};
use crate::{DeviceError, DeviceResult};

#[derive(Clone)]
pub struct RTLxDriver(Arc<Mutex<RTL8211F<ProviderImpl>>>);

#[derive(Clone)]
pub struct RTLxInterface {
    pub iface: Arc<Mutex<Interface<'static, RTLxDriver>>>,
    pub driver: RTLxDriver,
    pub routes: Arc<Mutex<Vec<RouteInfo>>>,
    pub name: String,
    pub irq: usize,
}

impl Scheme for RTLxInterface {
    fn name(&self) -> &str {
        "rtl8211f"
    }

    fn handle_irq(&self, irq: usize) {
        if irq != self.irq {
            // not ours, skip it
            return;
        }

        let status = self.driver.0.lock().interrupt_status();

        let handle_tx_rx = 3;
        if status == handle_tx_rx {
            let timestamp = Instant::from_micros(timer_now_as_micros() as i64);
            let sockets = get_sockets();
            let mut sockets = sockets.lock();

            self.driver.0.lock().int_disable();
            match self.iface.lock().poll(&mut sockets, timestamp) {
                Ok(b) => {
                    debug!("nic poll, is changed ?: {}", b);
                }
                Err(err) => {
                    error!("poll got err {}", err);
                }
            }
            self.driver.0.lock().int_enable();
            //return true;
        }
    }
}

impl NetScheme for RTLxInterface {
    fn get_mac(&self) -> EthernetAddress {
        self.iface.lock().ethernet_addr()
    }

    fn get_ifname(&self) -> String {
        self.name.clone()
    }

    fn get_ip_address(&self) -> Vec<IpCidr> {
        Vec::from(self.iface.lock().ip_addrs())
    }

    fn set_ipv4_address(&self, cidr: Ipv4Cidr) -> DeviceResult {
        let mut iface = self.iface.lock();
        let mut updated = false;
        iface.update_ip_addrs(|addrs| {
            if let Some(addr) = addrs
                .iter_mut()
                .find(|addr| matches!(addr, IpCidr::Ipv4(_)))
            {
                *addr = IpCidr::Ipv4(cidr);
                updated = true;
            }
        });
        if updated {
            Ok(())
        } else {
            Err(DeviceError::NotSupported)
        }
    }

    fn add_route(&self, cidr: IpCidr, gateway: Option<IpAddress>) -> DeviceResult {
        let mut iface = self.iface.lock();
        match (cidr, gateway) {
            (IpCidr::Ipv4(c), Some(IpAddress::Ipv4(gw))) if c.prefix_len() == 0 => {
                iface
                    .routes_mut()
                    .add_default_ipv4_route(gw)
                    .map_err(|_| DeviceError::IoError)?;

                let mut routes = self.routes.lock();
                routes.retain(|r| !(matches!(r.dst, IpCidr::Ipv4(_)) && r.dst.prefix_len() == 0));
                routes.push(RouteInfo {
                    dst: cidr,
                    gateway: Some(IpAddress::Ipv4(gw)),
                });
            }
            _ => {
                self.routes.lock().push(RouteInfo { dst: cidr, gateway });
            }
        }
        Ok(())
    }

    fn del_route(&self, cidr: IpCidr, _gateway: Option<IpAddress>) -> DeviceResult {
        let mut iface = self.iface.lock();
        if let IpCidr::Ipv4(c) = cidr {
            if c.prefix_len() == 0 {
                let _ = iface.routes_mut().remove_default_ipv4_route();
            }
        }
        self.routes.lock().retain(|r| r.dst != cidr);
        Ok(())
    }

    fn get_routes(&self) -> Vec<RouteInfo> {
        let iface = self.iface.lock();
        let mut res = Vec::new();

        res.extend(self.routes.lock().clone());

        for cidr in iface.ip_addrs() {
            if let IpCidr::Ipv4(v4) = cidr {
                if v4.prefix_len() > 0 {
                    // Direct interface routes only; the default route is tracked separately.
                    res.push(RouteInfo {
                        dst: IpCidr::Ipv4(v4.network()),
                        gateway: None,
                    });
                }
            }
        }
        res
    }

    fn poll(&self) -> DeviceResult {
        let timestamp = Instant::from_micros(timer_now_as_micros() as i64);
        // Disable interrupts while holding the SOCKETS and iface locks.
        // On real hardware the NIC fires a hardware interrupt as soon as a
        // frame lands in the DMA ring.  If that interrupt is delivered while
        // this thread already holds SOCKETS, handle_irq() will try to acquire
        // the same lock and spin forever, dead-locking the single-CPU system.
        // Keeping interrupts off for the duration of iface.poll() avoids the
        // race; any pending NIC interrupt fires safely after we release the
        // locks and re-enable interrupts.
        let intr_was_on = super::intr_get();
        if intr_was_on {
            super::intr_off();
        }
        let sockets = get_sockets();
        let mut sockets = sockets.lock();
        let result = self.iface.lock().poll(&mut sockets, timestamp);
        // Explicitly release the SOCKETS guard here, before re-enabling
        // interrupts.  Without this drop the guard would live until the end
        // of the function (after intr_on), which would re-introduce the
        // deadlock we are fixing.
        drop(sockets);
        if intr_was_on {
            super::intr_on();
        }
        match result {
            Ok(b) => {
                debug!("nic poll, is changed ?: {}", b);
                Ok(())
            }
            Err(err) => {
                error!("poll got err {}", err);
                Err(DeviceError::IoError)
            }
        }
    }

    fn recv(&self, buf: &mut [u8]) -> DeviceResult<usize> {
        if self.driver.0.lock().can_recv() {
            let (vec_recv, rxcount) = self.driver.0.lock().geth_recv(1);
            buf.copy_from_slice(&vec_recv);
            Ok(rxcount as usize)
        } else {
            Err(DeviceError::NotReady)
        }
    }

    fn send(&self, data: &[u8]) -> DeviceResult<usize> {
        if self.driver.0.lock().can_send() {
            self.driver.0.lock().geth_send(data).unwrap();
            Ok(data.len())
        } else {
            Err(DeviceError::NotReady)
        }
    }
}

pub struct RTLxRxToken(Vec<u8>);
pub struct RTLxTxToken(RTLxDriver);

impl<'a> Device<'a> for RTLxDriver {
    type RxToken = RTLxRxToken;
    type TxToken = RTLxTxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1536;
        caps.max_burst_size = Some(64);
        caps.medium = Medium::Ethernet;
        caps
    }

    fn receive(&mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        if self.0.lock().can_recv() {
            //这里每次只接收一个网络包
            let (vec_recv, _rxcount) = self.0.lock().geth_recv(1);
            Some((RTLxRxToken(vec_recv), RTLxTxToken(self.clone())))
        } else {
            None
        }
    }

    fn transmit(&mut self) -> Option<Self::TxToken> {
        if self.0.lock().can_send() {
            Some(RTLxTxToken(self.clone()))
        } else {
            None
        }
    }
}

impl phy::RxToken for RTLxRxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        // Dispatch to global packet tapping (AF_PACKET sockets)
        super::net_dispatch_packet(&self.0);
        f(&mut self.0)
    }
}

impl phy::TxToken for RTLxTxToken {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        let mut buffer = [0u8; 1536];
        let result = f(&mut buffer[..len]);
        if result.is_ok() {
            (self.0).0.lock().geth_send(&buffer[..len]).unwrap();
        }
        result
    }
}

pub fn rtlx_init<F: Fn(usize, usize) -> Option<usize>>(
    irq: usize,
    mapper: F,
) -> DeviceResult<RTLxInterface> {
    mapper(rtl8211f::PINCTRL_GPIO_BASE as usize, PAGE_SIZE * 2);
    mapper(rtl8211f::SYS_CFG_BASE as usize, PAGE_SIZE * 2);

    let mut rtl8211f = RTL8211F::<ProviderImpl>::new(&[0u8; 6]);
    let mac = rtl8211f.get_umac();
    //启动前请为D1插上网线
    warn!("Please plug in the Ethernet cable");

    rtl8211f.open().unwrap();
    rtl8211f.set_rx_mode();
    rtl8211f.adjust_link().unwrap();

    let net_driver = RTLxDriver(Arc::new(Mutex::new(rtl8211f)));

    let ethernet_addr = EthernetAddress::from_bytes(&mac);
    let ip_addrs = [IpCidr::new(IpAddress::v4(192, 168, 0, 123), 24)];
    let default_gateway = Ipv4Address::new(192, 168, 0, 1);
    static mut ROUTES_STORAGE: [Option<(IpCidr, Route)>; 1] = [None; 1];
    let mut routes = unsafe { Routes::new(&mut ROUTES_STORAGE[..]) };
    routes.add_default_ipv4_route(default_gateway).unwrap();
    let neighbor_cache = NeighborCache::new(BTreeMap::new());
    let iface = InterfaceBuilder::new(net_driver.clone())
        .ethernet_addr(ethernet_addr)
        .neighbor_cache(neighbor_cache)
        .ip_addrs(ip_addrs)
        .routes(routes)
        .finalize();

    info!("rtl8211f interface up with addr 192.168.0.123/24");
    info!("rtl8211f interface up with route 192.168.0.1/24");
    let rtl8211f_iface = RTLxInterface {
        iface: Arc::new(Mutex::new(iface)),
        driver: net_driver,
        routes: Arc::new(Mutex::new(vec![RouteInfo {
            dst: IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0),
            gateway: Some(IpAddress::Ipv4(default_gateway)),
        }])),
        name: String::from("rtl8211f"),
        irq,
    };

    Ok(rtl8211f_iface)
}

//TODO: Global SocketSet
// lazy_static::lazy_static! {
//     pub static ref SOCKETS: Mutex<SocketSet<'static>> =
//         Mutex::new(SocketSet::new(vec![]));
// }
