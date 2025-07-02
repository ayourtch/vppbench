use criterion::{criterion_group, criterion_main, Criterion};
use memif::*;
use lazy_static::lazy_static;

use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct SerializableInstant {
    duration_since_epoch: Duration,
}

use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::Arc;


lazy_static! {
   static ref EPOCH_START: Instant = Instant::now();
}

// Global variable using OnceLock and Mutex for thread safety
static GLOBAL_STATE: OnceLock<Arc<Mutex<GlobalState>>> = OnceLock::new();

unsafe impl Send for GlobalState {}


fn get_global_state() -> &'static Mutex<GlobalState> {
    GLOBAL_STATE.get_or_init(|| Arc::new(Mutex::new(new_global_state())))
}

/*
fn increment_counter() {
    let mut state = get_global_state().lock().unwrap();
    state.counter += 1;
    println!("Counter incremented to: {}", state.counter);
}

fn update_name(new_name: &str) {
    let mut state = get_global_state().lock().unwrap();
    state.name = new_name.to_string();
    println!("Name updated to: {}", state.name);
}

fn print_state() {
    let state = get_global_state().lock().unwrap();
    println!("Current state: {:?}", *state);
}
*/


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

struct GlobalState {
  conn: MemifConn,
  packet_count: usize,
  last_instant: Instant,
}

fn new_global_state() -> GlobalState {
    use oside::protocols::all::*;
    use oside::protocols::geneve::*;
    use oside::*;
    use std::convert::TryFrom;


    let socket_path = "/run/vpp/memif.sock";
    let mut conn = connect_to_memif_id(socket_path, 1).unwrap();
    let mut packet_count = 0;

    let mut last_instant = Instant::now();

    let state = GlobalState { conn, packet_count, last_instant };
    state
}

fn test_rtt() {
    use oside::protocols::all::*;
    use oside::protocols::geneve::*;
    use oside::*;
    use std::convert::TryFrom;
    let addr = "06:05:04:03:02:01";
    let mut state = get_global_state().lock().unwrap();

    let serializable = SerializableInstant::now();
    let serialized = bincode::serialize(&serializable).unwrap();

    let mut last_instant = state.last_instant;
    let mut packet_count = state.packet_count;

        let request = Ether!(src = addr, dst = "ff:ff:ff:ff:ff:ff")
            / IP!(dst = "192.0.2.2", src = "198.51.100.2")
            // / IP!(dst = "198.51.100.1", src = "198.51.100.2")
	    / UDP!(sport = 6081, dport=6081)
	    / GENEVE!(vni =42)
            / IP!(dst = "192.168.0.1", src = "192.168.0.2")
            / ICMP!()
            / Echo!(identifier = 0, sequence = packet_count as u16)
            / Raw!(serialized.into());
        // println!("Request: {:?}", &request);
        let bytes = request.lencode();
        let mut bufs = memif_buffer_alloc(&state.conn, 0, 1, 2048);
	if bufs.len() < 1 {
            std::thread::sleep(std::time::Duration::from_millis(1000));
	    return;
	}
        bufs[0].len = bytes.len() as u32;
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), bufs[0].data.as_mut_ptr(), bytes.len());
        }
	let bufs_len = bufs.len();
        memif_tx_burst(&state.conn, 0, bufs);
        memif_refill_queue(&state.conn, 0, 65535, 0);
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
	packet_count += bufs_len;
	// println!("Packet count: {}", packet_count);
        let mut pkts = memif_rx_burst(&state.conn, 0, 32);
	packet_count += pkts.len();
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
                let mut bufs = memif_buffer_alloc(&state.conn, 0, 1, 2048);
                bufs[0].len = bytes.len() as u32;
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        bufs[0].data.as_mut_ptr(),
                        bytes.len(),
                    );
                }
                memif_tx_burst(&state.conn, 0, bufs);
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
       state.last_instant = last_instant;
       state.packet_count = packet_count;
}

fn rtt_benchmark(c: &mut Criterion) {
    c.bench_function("VPP rtt", |b| b.iter(|| test_rtt()));
}

criterion_group!(benches, rtt_benchmark);
criterion_main!(benches);

