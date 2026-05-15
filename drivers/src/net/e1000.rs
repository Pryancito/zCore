//! Intel PRO/1000 Network Adapter i.e. e1000 network driver
//! Datasheet: <https://www.intel.ca/content/dam/doc/datasheet/82574l-gbe-controller-datasheet.pdf>

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use smoltcp::iface::*;
use smoltcp::phy::{self, DeviceCapabilities};
use smoltcp::time::Instant;
use smoltcp::wire::*;
use smoltcp::Result;

use super::{timer_now_as_micros, ProviderImpl};
use crate::net::get_sockets;
use crate::scheme::{NetScheme, Scheme, SchemeUpcast, RouteInfo, NetStats};
use crate::{Device, DeviceError, DeviceResult};
use crate::bus::pci_drivers::PciDriver;
use crate::builder::IoMapper;
use pci::{PCIDevice, BAR};
use isomorphic_drivers::net::ethernet::intel::e1000::E1000;
use isomorphic_drivers::net::ethernet::structs::EthernetAddress as DriverEthernetAddress;
use lock::Mutex;

#[derive(Clone)]
pub struct E1000Driver {
    pub hw: Arc<Mutex<E1000<crate::net::ProviderImpl>>>,
    pub stats: Arc<Mutex<NetStats>>,
}

#[derive(Clone)]
pub struct E1000Interface {
    iface: Arc<Mutex<Interface<'static, E1000Driver>>>,
    driver: E1000Driver,
    name: String,
    irq: usize,
    pub stats: Arc<Mutex<NetStats>>,
    pub routes: Arc<Mutex<Vec<RouteInfo>>>,
}

impl Scheme for E1000Interface {
    fn name(&self) -> &str {
        "e1000"
    }

    fn handle_irq(&self, irq: usize) {
        if irq != self.irq {
            return;
        }

        let mut hw = self.driver.hw.lock();
        if hw.handle_interrupt() {
            let self_clone = self.clone();
            crate::utils::deferred_job::push_deferred_job(move || {
                let ts = Instant::from_micros(timer_now_as_micros() as i64);
                let sockets = get_sockets();
                let mut sockets = sockets.lock();
                if let Err(e) = self_clone.iface.lock().poll(&mut sockets, ts) {
                    warn!("[e1000] poll error: {}", e);
                }
            });
        }
    }
}

impl NetScheme for E1000Interface {
    fn get_mac(&self) -> EthernetAddress {
        self.iface.lock().ethernet_addr()
    }

    fn get_ifname(&self) -> String {
        self.name.clone()
    }

    // get ip addresses
    fn get_ip_address(&self) -> Vec<IpCidr> {
        Vec::from(self.iface.lock().ip_addrs())
    }

    fn poll(&self) -> DeviceResult {
        let timestamp = Instant::from_micros(timer_now_as_micros() as i64);
        let sockets = get_sockets();
        let mut sockets = sockets.lock();
        match self.iface.lock().poll(&mut sockets, timestamp) {
            Ok(p) => {
                trace!("e1000 NetScheme poll: {:?}", p);
                Ok(())
            }
            Err(err) => {
                warn!("poll got err {}", err);
                Err(DeviceError::IoError)
            }
        }
    }

    fn recv(&self, buf: &mut [u8]) -> DeviceResult<usize> {
        // Try to read directly from hardware.
        if let Some(pkt) = self.driver.hw.lock().receive() {
            let n = pkt.len().min(buf.len());
            buf[..n].copy_from_slice(&pkt[..n]);
            Ok(n)
        } else {
            Err(DeviceError::NotReady)
        }
    }

    fn send(&self, data: &[u8]) -> DeviceResult<usize> {
        if self.driver.hw.lock().can_send() {
            let mut driver = self.driver.hw.lock();
            driver.send(data);
            Ok(data.len())
        } else {
            Err(DeviceError::NotReady)
        }
    }

    fn can_recv(&self) -> bool {
        // Return true so callers always attempt recv(); actual receive will return NotReady if nothing.
        true
    }

    fn can_send(&self) -> bool {
        self.driver.hw.lock().can_send()
    }

    fn set_ipv4_address(&self, cidr: Ipv4Cidr) -> DeviceResult {
        let mut iface = self.iface.lock();
        iface.update_ip_addrs(|addrs| {
            if let Some(first) = addrs.first_mut() {
                *first = IpCidr::Ipv4(cidr);
            }
        });
        Ok(())
    }

    fn add_route(&self, cidr: IpCidr, gateway: Option<IpAddress>) -> DeviceResult {
        let mut iface = self.iface.lock();
        if let Some(IpAddress::Ipv4(gw)) = gateway {
            iface
                .routes_mut()
                .add_default_ipv4_route(gw)
                .map_err(|_| DeviceError::IoError)?;
            
            let mut routes = self.routes.lock();
            routes.retain(|r| r.dst.prefix_len() != 0);
            routes.push(RouteInfo {
                dst: cidr,
                gateway: Some(IpAddress::Ipv4(gw)),
            });
        } else {
            self.routes.lock().push(RouteInfo { dst: cidr, gateway });
        }
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

    fn get_stats(&self) -> NetStats {
        self.stats.lock().clone()
    }
}

pub struct E1000RxToken {
    data: Vec<u8>,
    stats: Arc<Mutex<NetStats>>,
}

pub struct E1000TxToken {
    driver: E1000Driver,
    stats: Arc<Mutex<NetStats>>,
}

impl phy::Device<'_> for E1000Driver {
    type RxToken = E1000RxToken;
    type TxToken = E1000TxToken;

    fn receive(&mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        self.hw.lock().receive().map(|pkt| {
            (
                E1000RxToken { data: pkt, stats: self.stats.clone() },
                E1000TxToken { driver: self.clone(), stats: self.stats.clone() },
            )
        })
    }

    fn transmit(&mut self) -> Option<Self::TxToken> {
        if self.hw.lock().can_send() {
            Some(E1000TxToken { driver: self.clone(), stats: self.stats.clone() })
        } else {
            None
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1536;
        caps.max_burst_size = Some(64);
        caps
    }
}

impl phy::RxToken for E1000RxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        let mut stats = self.stats.lock();
        stats.rx_packets += 1;
        stats.rx_bytes += self.data.len() as u64;
        drop(stats);

        // Dispatch to global packet tapping (AF_PACKET sockets)
        super::net_dispatch_packet(&self.data);
        f(&mut self.data)
    }
}

impl phy::TxToken for E1000TxToken {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        let mut buffer = [0u8; 1536];
        let result = f(&mut buffer[..len]);

        let mut driver = self.driver.hw.lock();
        driver.send(&buffer[..len]);
        drop(driver);
        
        let mut stats = self.stats.lock();
        stats.tx_packets += 1;
        stats.tx_bytes += len as u64;

        result
    }
}

pub fn init(
    name: String,
    irq: usize,
    header: usize,
    size: usize,
    index: usize,
) -> DeviceResult<E1000Interface> {
    info!("Probing e1000 {}", name);

    let mac: [u8; 6] = [0x54, 0x51, 0x9F, 0x71, 0xC0, index as u8];
    let e1000 = E1000::new(header, size, DriverEthernetAddress::from_bytes(&mac));
    let hw = Arc::new(Mutex::new(e1000));
    let stats = Arc::new(Mutex::new(NetStats::default()));
    let net_driver = E1000Driver { hw: hw.clone(), stats: stats.clone() };

    let ethernet_addr = EthernetAddress::from_bytes(&mac);
    let ip_addrs = [IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0)];
    let default_v4_gw = Ipv4Address::new(0, 0, 0, 0);
    static mut ROUTES_STORAGE: [Option<(IpCidr, Route)>; 4] = [None; 4];
    let mut routes = unsafe { Routes::new(&mut ROUTES_STORAGE[..]) };
    routes.add_default_ipv4_route(default_v4_gw).unwrap();
    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let iface = InterfaceBuilder::new(net_driver.clone())
        .ethernet_addr(ethernet_addr)
        .neighbor_cache(neighbor_cache)
        .ip_addrs(ip_addrs)
        .routes(routes)
        .finalize();

    info!(
        "e1000 interface {} up with addr 10.0.2.{}/24",
        name,
        15 + index
    );
    let e1000_iface = E1000Interface {
        iface: Arc::new(Mutex::new(iface)),
        driver: net_driver,
        name,
        irq,
        stats,
        routes: Arc::new(Mutex::new(vec![RouteInfo {
            dst: IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0),
            gateway: Some(IpAddress::Ipv4(default_v4_gw)),
        }])),
    };

    Ok(e1000_iface)
}

pub struct E1000DriverPci;

impl PciDriver for E1000DriverPci {
    fn name(&self) -> &str {
        "e1000"
    }

    fn matched(&self, vendor_id: u16, device_id: u16) -> bool {
        vendor_id == 0x8086 && (device_id == 0x100e || device_id == 0x100f)
    }

    fn init(&self, dev: &PCIDevice, mapper: &Option<Arc<dyn IoMapper>>, irq: Option<usize>) -> DeviceResult<Device> {
        if let Some(BAR::Memory(addr, len, _, _)) = dev.bars[0] {
            if let Some(m) = mapper {
                m.query_or_map(addr as usize, 4096 * 8);
            }
            let vaddr = crate::bus::phys_to_virt(addr as usize);
            let name = alloc::format!("eth{}", dev.loc.bus);
            let vector = irq.map(|idx| idx + 32).unwrap_or(0);
            let iface = init(name, vector, vaddr, len as usize, 0)?;
            Ok(Device::Net(Arc::new(iface)))
        } else {
            Err(crate::DeviceError::NotSupported)
        }
    }
}
