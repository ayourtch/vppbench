use memif::*;
use lazy_static::lazy_static;


/*
VPP config:


create interface memif master
set int ip address memif0/0 192.0.2.1/24
set interface state memif0/0 up

create memif socket id 1 filename /run/vpp/memif2.sock
create interface memif master id 1
set int ip address memif0/1 198.51.100.1/24
set interface state memif0/1 up


this executable will connect to memif0/1, the other one will connect to memif0/0

*/

use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct SerializableInstant {
    duration_since_epoch: Duration,
}

lazy_static! {
   static ref EPOCH_START: Instant = Instant::now();
}

impl From<Instant> for SerializableInstant {
    fn from(instant: Instant) -> Self {
        let duration = instant.duration_since(*EPOCH_START);
        Self {
            duration_since_epoch: duration,
        }
    }
}

impl SerializableInstant {
    fn now() -> Self {
        let duration = Instant::now().duration_since(*EPOCH_START);
        Self {
            duration_since_epoch: duration,
        }
    }
    fn to_instant(&self) -> Instant {
        *EPOCH_START + self.duration_since_epoch
    }
}

/*
fn main() {
    // Dependencies in Cargo.toml:
    // bincode = "1.3.3"
    // serde = { version = "1.0", features = ["derive"] }

    let now = Instant::now();

    // Serialize
    let serializable = SerializableInstant::from(now);
    let serialized = bincode::serialize(&serializable).unwrap();

    // Deserialize
    let deserialized: SerializableInstant = bincode::deserialize(&serialized).unwrap();
    let reconstructed_instant = deserialized.to_instant();

    println!("Original: {:?}", now);
    println!("Reconstructed: {:?}", reconstructed_instant);
}
*/

fn main() -> anyhow::Result<()> {
    use oside::protocols::all::*;
    use oside::protocols::geneve::*;
    use oside::*;
    use std::convert::TryFrom;

    let addr = "06:05:04:03:02:01";

    let socket_path = "/run/vpp/memif.sock";
    let mut conn = connect_to_memif_id(socket_path, 1).unwrap();
    let mut packet_count = 0;

    let mut last_instant = Instant::now();

    loop {


    let serializable = SerializableInstant::now();
    let serialized = bincode::serialize(&serializable).unwrap();

        let request = Ether!(src = addr, dst = "ff:ff:ff:ff:ff:ff")
            / IP!(dst = "192.0.2.2", src = "198.51.100.2")
            // / IP!(dst = "198.51.100.1", src = "198.51.100.2")
	    / UDP!(sport = 6081, dport=6081)
	    / GENEVE!(vni =42)
            / IP!(dst = "192.168.0.1", src = "192.168.0.2")
            / ICMP!()
            / Echo!(identifier = 0, sequence = packet_count)
            / Raw!(serialized.into());
        // println!("Request: {:?}", &request);
        let bytes = request.lencode();
        let mut bufs = memif_buffer_alloc(&conn, 0, 1, 2048);
	if bufs.len() < 1 {
            std::thread::sleep(std::time::Duration::from_millis(1000));
	    continue;
	}
        bufs[0].len = bytes.len() as u32;
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), bufs[0].data.as_mut_ptr(), bytes.len());
        }
	let bufs_len = bufs.len();
        memif_tx_burst(&conn, 0, bufs);
        memif_refill_queue(&conn, 0, 65535, 0);
	/*
            let ring = memif_get_ring(&conn, MemifRingType::S2m, 0);
            unsafe {
                println!("S: {} {}", (*ring).head.get(), (*ring).tail.get());
            }
            let ring = memif_get_ring(&conn, MemifRingType::M2s, 0);
            unsafe {
                println!("M: {} {}", (*ring).head.get(), (*ring).tail.get());
            }
	*/
	packet_count += bufs_len as u16;
	// println!("Packet count: {}", packet_count);
        let mut pkts = memif_rx_burst(&conn, 0, 32);
	packet_count += pkts.len() as u16;
        // println!("pkts: {}", pkts.len());
        for p in &pkts {
            // println!("    len {}", p.len);
            let end = p.len as usize;
            let data = &p.data[0..end];
            let sca = Ether!().ldecode(data).unwrap().0;

            if let Some(arp) = sca.get_layer(ARP!()) {
                println!("ARP request!");
                let reply = Ether!(src = addr, dst = sca[Ether!()].src.clone())
                    / ARP!(
                        op = 2,
                        hwdst = sca[ARP!()].hwsrc.value(),
                        pdst = sca[ARP!()].psrc.value(),
                        hwsrc = addr,
                        psrc = sca[ARP!()].pdst.value()
                    );
                println!("ARP Reply: {:?}", &reply);
                let bytes = reply.lencode();
                let mut bufs = memif_buffer_alloc(&conn, 0, 1, 2048);
                bufs[0].len = bytes.len() as u32;
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        bufs[0].data.as_mut_ptr(),
                        bytes.len(),
                    );
                }
                memif_tx_burst(&conn, 0, bufs);
            } else {
                if let Some(icmpecho) = sca.get_layer(EchoReply!()) {
		    if let Some(raw) = sca.get_layer(Raw!()) {
		       // println!("Got raw data: {:?}", &raw);
		        let deserialized: SerializableInstant = bincode::deserialize(&raw.data).unwrap();
                        let reconstructed_instant = deserialized.to_instant();
			let elapsed = Instant::now().duration_since(reconstructed_instant);
			// println!("Duration since: {:?}", &elapsed);
			if Instant::now().duration_since(last_instant) > Duration::new(1,0) {
			    last_instant = Instant::now();
			    println!("Packet count: {}", packet_count);
			    packet_count = 0;
			}

		    }
                }
            }
            // println!("Data received: {:?}", &sca);
        }
        /*memif_buffer_enq_tx(&conn, &conn.rx_queues[0], 0, &mut pkts);
        memif_tx_burst(&conn, 0, pkts);
        /* if pkts.len() > 0 {
            println!("{:?}", &pkts[0]);
        } */
        */
       // std::thread::sleep(std::time::Duration::from_millis(1000));
       // std::thread::sleep(std::time::Duration::from_millis(100));
       // std::thread::sleep(std::time::Duration::from_nanos(1));
    }

    Ok(())
}
