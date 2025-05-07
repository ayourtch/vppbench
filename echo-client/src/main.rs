use memif::*;

fn main() -> anyhow::Result<()> {
    use oside::protocols::all::*;
    use oside::*;
    use std::convert::TryFrom;

    let socket_path = "/run/vpp/memif.sock";
    let mut conn = connect_to_memif(socket_path).unwrap();

    loop {
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
        let mut pkts = memif_rx_burst(&conn, 0, 32);
        println!("pkts: {}", pkts.len());
        for p in &pkts {
            println!("    len {}", p.len);
            let end = p.len as usize;
            let data = &p.data[0..end];
            let sca = Ether!().ldecode(data).unwrap().0;
            let addr = "01:02:03:04:05:06";

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
                println!("Reply: {:?}", &reply);
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
                if let Some(icmpecho) = sca.get_layer(Echo!()) {
                    let reply = Ether!(src = addr, dst = sca[Ether!()].src.clone())
                        / IP!(dst = sca[IP!()].src.value(), src = sca[IP!()].dst.value())
                        / ICMP!()
                        / EchoReply!(
                            identifier = sca[Echo!()].identifier.value(),
                            sequence = sca[Echo!()].sequence.value()
                        )
                        / Raw!(sca[Raw!()].data.clone());
                    println!("Reply: {:?}", &reply);
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
                }
            }
            println!("Sca: {:?}", &sca);
        }
        /*memif_buffer_enq_tx(&conn, &conn.rx_queues[0], 0, &mut pkts);
        memif_tx_burst(&conn, 0, pkts);
        /* if pkts.len() > 0 {
            println!("{:?}", &pkts[0]);
        } */
        */
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    Ok(())
}
