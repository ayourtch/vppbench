use binary_serde::{BinarySerde, Endianness, binary_serde_bitfield};
use std::cell::Cell;

use std::os::fd::RawFd;

use std::ffi::CString;
use std::ffi::c_void;
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixDatagram, UnixListener};

use vcell::VolatileCell;

use anyhow::Context;
use std::io::{Read, Write};

// Constants
const MEMIF_CACHELINE_SIZE: usize = 64;
const MEMIF_COOKIE: u32 = 0x3E31F20;
const MEMIF_VERSION_MAJOR: u16 = 2;
const MEMIF_VERSION_MINOR: u16 = 0;
const MEMIF_VERSION: u16 = (MEMIF_VERSION_MAJOR << 8) | MEMIF_VERSION_MINOR;

// Enumerations
#[repr(u8)]
#[derive(Debug, BinarySerde, PartialEq, Eq)]
enum MemifMsgType {
    None = 0,
    Ack = 1,
    Hello = 2,
    Init = 3,
    AddRegion = 4,
    AddRing = 5,
    Connect = 6,
    Connected = 7,
    Disconnect = 8,
}

#[derive(Debug, BinarySerde, PartialEq, Eq, Clone)]
#[repr(u8)]
pub enum MemifRingType {
    S2m = 0,
    M2s = 1,
}

#[derive(Debug, BinarySerde, PartialEq, Eq)]
#[repr(u8)]
enum MemifInterfaceMode {
    Ethernet = 0,
    Ip = 1,
    PuntInject = 2,
}

// Type Definitions
type MemifRegionIndex = u16;
type MemifRegionOffset = u32;
type MemifRegionSize = u64;
type MemifRingIndex = u16;
type MemifInterfaceId = u32;

// type MemifVersion = u16;

#[derive(Debug, BinarySerde, PartialEq, Eq)]
struct MemifVersion {
    minor: u8,
    major: u8,
}

type MemifLog2RingSize = u8;

trait AsMemifMsg {
    fn as_memif_msg(self) -> MemifMsg;
}

impl AsMemifMsg for MemifMsg {
    fn as_memif_msg(self) -> MemifMsg {
        self
    }
}

// Struct Definitions

#[derive(Debug, BinarySerde, PartialEq, Eq)]
struct MemifMsgHello {
    name: [u8; 32],
    min_version: MemifVersion,
    max_version: MemifVersion,
    max_region: MemifRegionIndex,
    max_m2s_ring: MemifRingIndex,
    max_s2m_ring: MemifRingIndex,
    max_log2_ring_size: MemifLog2RingSize,
}

impl AsMemifMsg for MemifMsgHello {
    fn as_memif_msg(self) -> MemifMsg {
        MemifMsg::Hello(self)
    }
}

#[derive(Debug, BinarySerde, PartialEq, Eq)]
struct MemifMsgInit {
    version: MemifVersion,
    id: MemifInterfaceId,
    mode: MemifInterfaceMode,
    secret: [u8; 24],
    name: [u8; 32],
}

impl AsMemifMsg for MemifMsgInit {
    fn as_memif_msg(self) -> MemifMsg {
        MemifMsg::Init(self)
    }
}

#[derive(Debug, BinarySerde, PartialEq, Eq)]
struct MemifMsgAddRegion {
    index: MemifRegionIndex,
    size: MemifRegionSize,
}

impl AsMemifMsg for MemifMsgAddRegion {
    fn as_memif_msg(self) -> MemifMsg {
        MemifMsg::AddRegion(self)
    }
}

const MEMIF_MSG_ADD_RING_FLAG_S2M: u16 = 1 << 0;
#[derive(Debug, BinarySerde, PartialEq, Eq)]
struct MemifMsgAddRing {
    flags: u16,
    index: MemifRingIndex,
    region: MemifRegionIndex,
    offset: MemifRegionOffset,
    log2_ring_size: MemifLog2RingSize,
    private_hdr_size: u16,
}

impl AsMemifMsg for MemifMsgAddRing {
    fn as_memif_msg(self) -> MemifMsg {
        MemifMsg::AddRing(self)
    }
}

#[derive(Debug, BinarySerde, PartialEq, Eq)]
struct MemifMsgConnect {
    if_name: [u8; 32],
}

impl AsMemifMsg for MemifMsgConnect {
    fn as_memif_msg(self) -> MemifMsg {
        MemifMsg::Connect(self)
    }
}

#[derive(Debug, BinarySerde, PartialEq, Eq)]
struct MemifMsgConnected {
    if_name: [u8; 32],
}

impl AsMemifMsg for MemifMsgConnected {
    fn as_memif_msg(self) -> MemifMsg {
        MemifMsg::Connected(self)
    }
}

#[derive(Debug, BinarySerde, PartialEq, Eq)]
struct MemifMsgDisconnect {
    code: u32,
    string: [u8; 96],
}

impl AsMemifMsg for MemifMsgDisconnect {
    fn as_memif_msg(self) -> MemifMsg {
        MemifMsg::Disconnect(self)
    }
}

/*
#[repr(C, align(128))]
struct MemifMsg {
    msg_type: MemifMsgType,
    data: MemifMsgData,
}
*/

#[derive(Debug, PartialEq, Eq)]
pub enum MemifMsg {
    Hello(MemifMsgHello),
    Init(MemifMsgInit),
    Ack,
    AddRegion(MemifMsgAddRegion),
    AddRing(MemifMsgAddRing),
    Connect(MemifMsgConnect),
    Connected(MemifMsgConnected),
    Disconnect(MemifMsgDisconnect),
}

const MEMIF_DESC_FLAG_NEXT: u16 = 1 << 0;
#[repr(C, packed)]
struct MemifDesc {
    flags: u16,
    region: MemifRegionIndex,
    length: u32,
    offset: MemifRegionOffset,
    metadata: u32,
}

// Note: Rust doesn't directly support flexible array members as in C.
// `desc` in `MemifRing` must be handled differently, potentially with Vec<MemifDesc> or similar.
#[repr(C, align(64))]
struct MemifRing {
    cookie: u32,
    flags: u16,
    head: VolatileCell<u16>,
    _reserved1: [u8; 120],
    tail: VolatileCell<u16>,
    _reserved2: [u8; 62 + 8],
    // desc: Vec<MemifDesc>, // An example alternative for flexible array member
}

struct MemifRegion {
    addr: *mut c_void,
    region_size: u64,
    buffer_offset: u32,
    fd: OwnedFd,
}

struct MemifArgs {
    num_s2m_rings: u8,
    num_m2s_rings: u8,
    log2_ring_size: u8,
    buffer_size: u16,
}

struct MemifQueue {
    // memif_ring_t *ring
    log2_ring_size: u8,
    region: u8,
    offset: u32,
    last_head: Cell<u16>,
    last_tail: Cell<u16>,
    int_fd: OwnedFd,
    int_count: u64,
    next_buf: Cell<u32>,
}

fn get_memif_ring_size(args: &MemifArgs) -> u32 {
    std::mem::size_of::<MemifRing>() as u32
        + (std::mem::size_of::<MemifDesc>() as u32 * (1 << args.log2_ring_size))
}

fn memif_add_region(args: &MemifArgs, has_buffers: bool) -> anyhow::Result<MemifRegion> {
    let buffer_offset: u32 = if has_buffers {
        0
    } else {
        (args.num_s2m_rings as u32 + args.num_m2s_rings as u32) * get_memif_ring_size(args)
    };
    let region_size: u64 = if has_buffers {
        buffer_offset as u64
            + args.buffer_size as u64
                * ((1 << args.log2_ring_size) as u64)
                * (args.num_s2m_rings as u64 + args.num_m2s_rings as u64)
    } else {
        buffer_offset as u64
    };
    let fd = {
        use nix::fcntl;
        use nix::sys::memfd;

        let name = CString::new("memif region 0")?;
        let name = "memif region 0";

        let mfd = memfd::memfd_create(name, memfd::MemFdCreateFlag::MFD_ALLOW_SEALING)?;

        fcntl::fcntl(
            &mfd,
            fcntl::FcntlArg::F_ADD_SEALS(fcntl::SealFlag::F_SEAL_SHRINK),
        )?;
        nix::unistd::ftruncate(&mfd, region_size.try_into()?)?;
        mfd
    };
    let ptr = unsafe {
        use nix::sys::mman;
        use std::num::NonZeroUsize;

        let size = NonZeroUsize::new(region_size.try_into()?).unwrap();
        mman::mmap(
            None,
            size,
            mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
            mman::MapFlags::MAP_SHARED,
            // MUST be a reference, else fd is closed before use
            &fd,
            0,
        )?
        .as_ptr()
    };

    let out = MemifRegion {
        addr: ptr,
        buffer_offset,
        region_size,
        fd,
    };
    Ok(out)
}

fn serialize_msg_into(vec: &mut Vec<u8>, msg: &MemifMsg) -> Result<(), std::io::Error> {
    use MemifMsg::*;
    // this is a hack against a weird problem that happens if i declare message type being u16
    let zero: u8 = 0;

    let out = match msg {
        Ack => {
            let t = MemifMsgType::Ack;
            t.binary_serialize_into(vec, Endianness::Little)?;
            zero.binary_serialize_into(vec, Endianness::Little)
        }
        Hello(x) => {
            let t = MemifMsgType::Hello;
            t.binary_serialize_into(vec, Endianness::Little)?;
            zero.binary_serialize_into(vec, Endianness::Little)?;
            x.binary_serialize_into(vec, Endianness::Little)
        }
        Init(x) => {
            let t = MemifMsgType::Init;
            t.binary_serialize_into(vec, Endianness::Little)?;
            zero.binary_serialize_into(vec, Endianness::Little)?;
            x.binary_serialize_into(vec, Endianness::Little)
        }
        AddRegion(x) => {
            let t = MemifMsgType::AddRegion;
            t.binary_serialize_into(vec, Endianness::Little)?;
            zero.binary_serialize_into(vec, Endianness::Little)?;
            x.binary_serialize_into(vec, Endianness::Little)
        }
        AddRing(x) => {
            let t = MemifMsgType::AddRing;
            t.binary_serialize_into(vec, Endianness::Little)?;
            zero.binary_serialize_into(vec, Endianness::Little)?;
            x.binary_serialize_into(vec, Endianness::Little)
        }
        Connect(x) => {
            let t = MemifMsgType::Connect;
            t.binary_serialize_into(vec, Endianness::Little)?;
            zero.binary_serialize_into(vec, Endianness::Little)?;
            x.binary_serialize_into(vec, Endianness::Little)
        }
        Connected(x) => {
            let t = MemifMsgType::Connected;
            t.binary_serialize_into(vec, Endianness::Little)?;
            zero.binary_serialize_into(vec, Endianness::Little)?;
            x.binary_serialize_into(vec, Endianness::Little)
        }
        Disconnect(x) => {
            let t = MemifMsgType::Disconnect;
            t.binary_serialize_into(vec, Endianness::Little)?;
            zero.binary_serialize_into(vec, Endianness::Little)?;
            x.binary_serialize_into(vec, Endianness::Little)
        }

        x => unimplemented!(),
    };
    while vec.len() < 128 {
        vec.push(0);
    }
    out
}

fn deserialize_msg(data: &[u8]) -> Option<MemifMsg> {
    let msg_type = MemifMsgType::binary_deserialize(data, Endianness::Little).unwrap();
    println!("Msg type: {:?}", &msg_type);
    Some(match msg_type {
        MemifMsgType::None => return None,
        MemifMsgType::Hello => MemifMsg::Hello(
            MemifMsgHello::binary_deserialize(&data[2..], Endianness::Little).unwrap(),
        ),
        MemifMsgType::Init => MemifMsg::Init(
            MemifMsgInit::binary_deserialize(&data[2..], Endianness::Little).unwrap(),
        ),
        MemifMsgType::Ack => MemifMsg::Ack,
        MemifMsgType::AddRegion => MemifMsg::AddRegion(
            MemifMsgAddRegion::binary_deserialize(&data[2..], Endianness::Little).unwrap(),
        ),
        MemifMsgType::AddRing => MemifMsg::AddRing(
            MemifMsgAddRing::binary_deserialize(&data[2..], Endianness::Little).unwrap(),
        ),
        MemifMsgType::Connect => MemifMsg::Connect(
            MemifMsgConnect::binary_deserialize(&data[2..], Endianness::Little).unwrap(),
        ),
        MemifMsgType::Connected => MemifMsg::Connected(
            MemifMsgConnected::binary_deserialize(&data[2..], Endianness::Little).unwrap(),
        ),
        MemifMsgType::Disconnect => MemifMsg::Disconnect(
            MemifMsgDisconnect::binary_deserialize(&data[2..], Endianness::Little).unwrap(),
        ),
        x => return None,
    })
}

pub struct MemifConn {
    is_master: bool,
    sock: uds::UnixSeqpacketConn,
    run_args: MemifArgs,
    regions: Vec<MemifRegion>,
    tx_queues: Vec<MemifQueue>,
    rx_queues: Vec<MemifQueue>,
}

pub fn memif_get_ring_offset(conn: &MemifConn, typ: MemifRingType, ring_num: u16) -> u32 {
    let ring_size = get_memif_ring_size(&conn.run_args);
    let ring_offset =
        (ring_num as u32 + (typ.clone() as u32) * (conn.run_args.num_s2m_rings as u32)) * ring_size;
    ring_offset
}

fn memif_get_ring_by_offset(conn: &MemifConn, ring_offset: u32) -> *mut MemifRing {
    let p = conn.regions[0]
        .addr
        .wrapping_add(ring_offset.try_into().unwrap());
    p as *mut MemifRing
}

pub fn memif_get_ring(conn: &MemifConn, typ: MemifRingType, ring_num: u16) -> *mut MemifRing {
    let ring_offset = memif_get_ring_offset(conn, typ.clone(), ring_num);
    memif_get_ring_by_offset(conn, ring_offset)
}

fn memif_get_ring_desc_by_offset(
    conn: &MemifConn,
    ring_offset: u32,
    desc_num: u32,
) -> *mut MemifDesc {
    let desc0_offs = ring_offset + std::mem::size_of::<MemifRing>() as u32;
    let desc_offs = desc0_offs + desc_num * std::mem::size_of::<MemifDesc>() as u32;
    let p = conn.regions[0]
        .addr
        .wrapping_add(desc_offs.try_into().unwrap());
    p as *mut MemifDesc
}

fn memif_get_ring_desc(
    conn: &MemifConn,
    typ: MemifRingType,
    ring_num: u16,
    desc_num: u32,
) -> *mut MemifDesc {
    let ring_offset = memif_get_ring_offset(conn, typ.clone(), ring_num);
    memif_get_ring_desc_by_offset(conn, ring_offset, desc_num)
}

fn get_ring_count(conn: &mut MemifConn, typ: MemifRingType) -> u16 {
    let ring_count = if typ == MemifRingType::S2m {
        conn.run_args.num_s2m_rings
    } else {
        conn.run_args.num_m2s_rings
    };
    ring_count as u16
}

fn memif_init_rings(conn: &mut MemifConn, typ: MemifRingType) {
    let ring_size = 1u32 << conn.run_args.log2_ring_size;
    let ring_count = get_ring_count(conn, typ.clone());

    for i in 0..ring_count {
        let ring = memif_get_ring(conn, typ.clone(), i as u16);
        unsafe {
            (*ring).cookie = MEMIF_COOKIE;
            (*ring).head.set(0);
            (*ring).tail.set(0);
            (*ring).flags = 0;
        }
        let base: u32 = i as u32 + (typ.clone() as u32 * conn.run_args.num_s2m_rings as u32);
        let ring_offset = base * ring_size;
        for j in 0..ring_size {
            let slot = ring_offset + j;
            let desc = memif_get_ring_desc(conn, typ.clone(), i as u16, j);
            unsafe {
                (*desc).region = 1;
                let offs: u32 =
                    conn.regions[0].buffer_offset + slot * (conn.run_args.buffer_size as u32);
                (*desc).offset = offs;
                (*desc).length = conn.run_args.buffer_size as u32;
            }
        }
    }
}

fn memif_init_queues(conn: &mut MemifConn, typ: MemifRingType) -> anyhow::Result<()> {
    let mut queues: Vec<MemifQueue> = vec![];
    let ring_count = get_ring_count(conn, typ.clone());
    for x in 0..ring_count {
        let region = 0;
        let int_fd = nix::sys::eventfd::eventfd(0, nix::sys::eventfd::EfdFlags::EFD_NONBLOCK)?;
        let mq = MemifQueue {
            log2_ring_size: conn.run_args.log2_ring_size,
            int_fd,
            region,
            offset: memif_get_ring_offset(conn, typ.clone(), x),
            last_head: 0.into(),
            last_tail: 0.into(),
            next_buf: 0.into(),
            int_count: 0,
        };
        queues.push(mq);
    }
    let ring_count = if typ == MemifRingType::S2m {
        conn.tx_queues = queues;
    } else {
        conn.rx_queues = queues;
    };
    Ok(())
}

fn memif_enq_msg_add_ring(
    conn: &MemifConn,
    typ: MemifRingType,
    index: usize,
) -> anyhow::Result<()> {
    let flags = if typ == MemifRingType::S2m {
        MEMIF_MSG_ADD_RING_FLAG_S2M
    } else {
        0
    };
    let mq = if typ == MemifRingType::M2s {
        &conn.rx_queues[index]
    } else {
        &conn.tx_queues[index]
    };
    let index = index as u16;
    let msg = MemifMsgAddRing {
        flags,
        index,
        region: mq.region as u16,
        offset: mq.offset,
        log2_ring_size: mq.log2_ring_size,
        private_hdr_size: 0,
    };
    memif_send_msg(conn.sock.as_raw_fd(), msg, Some(mq.int_fd.as_raw_fd()))
}

fn memif_init_queues_and_rings(conn: &mut MemifConn) {
    memif_init_rings(conn, MemifRingType::S2m);
    memif_init_rings(conn, MemifRingType::M2s);
    memif_init_queues(conn, MemifRingType::S2m);
    memif_init_queues(conn, MemifRingType::M2s);
}

fn memif_send_msg<M: AsMemifMsg>(
    sock: RawFd,
    msg: M,
    pass_fd: Option<RawFd>,
) -> anyhow::Result<()> {
    use nix::sys::socket::ControlMessage;
    use nix::sys::socket::MsgFlags;
    use std::io::IoSlice;
    let mut msg_bytes: Vec<u8> = vec![];
    let msg = msg.as_memif_msg();
    serialize_msg_into(&mut msg_bytes, &msg)?;
    let iov = [IoSlice::new(&msg_bytes)];
    let mut fds = vec![];
    let cmsgs = if let Some(pass_fd) = pass_fd {
        fds.push(pass_fd);
        let cmsg = ControlMessage::ScmRights(&fds);
        vec![cmsg]
    } else {
        vec![]
    };
    nix::sys::socket::sendmsg::<()>(sock, &iov, &cmsgs, MsgFlags::empty(), None)?;
    Ok(())
}

pub fn memif_refill_queue(
    conn: &MemifConn,
    qid: u16,
    count: u16,
    headroom: u16,
) -> anyhow::Result<()> {
    let num = if conn.is_master {
        conn.run_args.num_s2m_rings
    } else {
        conn.run_args.num_m2s_rings
    };
    if qid > num.into() {
        panic!("{} larger than available queues {}", qid, num);
    }
    let mq = &conn.rx_queues[qid as usize];
    let mask = ((1 << mq.log2_ring_size) - 1) as u16;
    let mut slot = 0;
    let mut counter = 0;
    let ring = memif_get_ring_by_offset(conn, mq.offset);

    if conn.is_master {
        unsafe {
            let newtail = if (*ring).tail.get() + count <= mq.last_head.get() {
                (*ring).tail.get() + count
            } else {
                mq.last_head.get()
            };
            (*ring).tail.set(newtail);
            return Ok(());
        }
    }
    unsafe {
        let head = (*ring).head.get();
        slot = head;
        let ns = (1 << mq.log2_ring_size) + mq.last_tail.get() - head;
        println!("ns: {}", ns);
        let count = if count < ns { count } else { ns };
        while counter < count {
            let d = memif_get_ring_desc_by_offset(conn, mq.offset, (slot & mask) as u32);
            (*d).region = 1;
            (*d).length = (conn.run_args.buffer_size - headroom) as u32;
            (*d).offset =
                (*d).offset - ((*d).offset % conn.run_args.buffer_size as u32) + headroom as u32;
            slot += 1;
            counter += 1;
        }
        // memory barrier
        (*ring).head.set(slot.try_into()?);
        /*
                for i in 0..(*ring)._reserved2.len() {
                    (*ring)._reserved2[i] = i as u8;
                }
        */
    }
    Ok(())
}

pub fn connect_to_memif(socket_path: &str) -> anyhow::Result<MemifConn> {
    let sock = uds::UnixSeqpacketConn::connect(socket_path)?;

    let mut message: [u8; 2048] = [0; 2048];
    let len = sock.recv(message.as_mut_slice())?;
    println!("len: {}", len);

    let msg = deserialize_msg(&message[0..len]);
    println!("{:?}", &message[0..len]);

    println!("{:?}", &msg);
    let msg = msg.unwrap();
    match &msg {
        MemifMsg::Hello(x) => {
            let name = String::from_utf8_lossy(&x.name);
            println!("Name: {}", &name);
            let run_args = MemifArgs {
                num_s2m_rings: 1,
                num_m2s_rings: 1,
                log2_ring_size: 10,
                buffer_size: 2048,
            };

            let seg0 = memif_add_region(&run_args, false).unwrap();
            let seg1 = memif_add_region(&run_args, true).unwrap();

            let mut conn = MemifConn {
                is_master: false,
                sock,
                run_args,
                regions: vec![seg0, seg1],
                tx_queues: vec![],
                rx_queues: vec![],
            };
            memif_init_queues_and_rings(&mut conn);
            {
                let msg = MemifMsgInit {
                    version: MemifVersion {
                        major: MEMIF_VERSION_MAJOR as u8,
                        minor: MEMIF_VERSION_MINOR as u8,
                    },
                    id: 0,
                    mode: MemifInterfaceMode::Ethernet,
                    secret: [0; 24],
                    name: [0x42; 32],
                };
                memif_send_msg(conn.sock.as_raw_fd(), msg, None).unwrap();
            }
            for i in 0..conn.regions.len() {
                let reg = &conn.regions[i];
                let msg = MemifMsgAddRegion {
                    index: i as u16,
                    size: reg.region_size,
                };
                memif_send_msg(conn.sock.as_raw_fd(), msg, Some(reg.fd.as_raw_fd())).unwrap();
            }
            for i in 0..conn.run_args.num_m2s_rings {
                memif_enq_msg_add_ring(&conn, MemifRingType::M2s, i as usize).unwrap();
            }
            for i in 0..conn.run_args.num_s2m_rings {
                memif_enq_msg_add_ring(&conn, MemifRingType::S2m, i as usize).unwrap();
            }
            let msg = MemifMsgConnect {
                if_name: [0x43; 32],
            };
            memif_send_msg(conn.sock.as_raw_fd(), msg, None).unwrap();
            return Ok(conn);
        }
        x => {}
    }
    unimplemented!()
}

const MEMIF_BUFFER_FLAG_NEXT: u8 = 1 << 0;

#[derive(Debug)]
pub struct MemifBuffer<'a> {
    desc_index: u16,
    // void *queue
    pub len: u32,
    flags: u8,
    pub data: &'a [u8],
}

pub struct MemifMutBuffer<'a> {
    desc_index: u16,
    // void *queue
    pub len: u32,
    flags: u8,
    pub data: &'a mut [u8],
}

fn memif_get_buffer(conn: &MemifConn, ring_offset: u32, index: u16) -> *const c_void {
    let d = memif_get_ring_desc_by_offset(conn, ring_offset, index as u32);
    let d_region = unsafe { (*d).region };
    let d_offset = unsafe { (*d).offset };
    let p = conn.regions[d_region as usize]
        .addr
        .wrapping_add(d_offset.try_into().unwrap());
    p
}

pub fn memif_buffer_alloc(
    conn: &MemifConn,
    qid: u16,
    count: u16,
    size: u16,
) -> Vec<MemifMutBuffer<'_>> {
    let mq = &conn.tx_queues[qid as usize];
    let ring = memif_get_ring_by_offset(conn, mq.offset);
    let mask = ((1 << mq.log2_ring_size) - 1) as u16;
    let ring_size = 1 << mq.log2_ring_size as u16;

    let mut out = vec![];

    let mut ns = if conn.is_master {
        unsafe { (*ring).head.get() - mq.next_buf.get() as u16 }
    } else {
        unsafe { ring_size - (mq.next_buf.get() as u16) + (*ring).tail.get() }
    };
    let mut b0_flags = 0;
    let mut count = count;
    'outer: while count > 0 && ns > 0 {
        let saved_out_len = out.len();
        let saved_next_buf = unsafe { mq.next_buf.get() };
        let mut dst_left = if conn.is_master {
            let d = memif_get_ring_desc_by_offset(
                conn,
                mq.offset,
                (saved_next_buf & mask as u32) as u32,
            );
            unsafe { (*d).length }
        } else {
            conn.run_args.buffer_size as u32
        };

        let mut src_left = size;

        while src_left > 0 {
            let b0_desc_index = unsafe { mq.next_buf.get() } as u16;

            let b0_len = std::cmp::min(dst_left, src_left as u32);
            // slave resets buffer offset
            if conn.is_master {
                let d =
                    memif_get_ring_desc_by_offset(conn, mq.offset, (b0_desc_index & mask) as u32);
                unsafe {
                    (*d).offset -= (*d).offset % conn.run_args.buffer_size as u32;
                }
            }
            let ptr =
                memif_get_buffer(conn, mq.offset, b0_desc_index & mask) as *const u8 as *mut u8;
            let b0_data =
                unsafe { std::slice::from_raw_parts_mut(ptr, conn.run_args.buffer_size as usize) };

            src_left -= b0_len as u16;
            dst_left -= b0_len as u32;
            ns -= 1;
            let curr_next_buf = mq.next_buf.get();
            mq.next_buf.set(curr_next_buf + 1);

            if src_left > 0 {
                if dst_left == 0 {
                    if ns > 0 {
                        let d = memif_get_ring_desc_by_offset(
                            conn,
                            mq.offset,
                            (b0_desc_index & mask) as u32,
                        );
                        unsafe { (*d).flags |= MEMIF_DESC_FLAG_NEXT };
                        b0_flags |= MEMIF_BUFFER_FLAG_NEXT;
                        let next_desc_index = unsafe { mq.next_buf.get() };
                        let d1 = memif_get_ring_desc_by_offset(
                            conn,
                            mq.offset,
                            (next_desc_index & mask as u32) as u32,
                        );
                        unsafe { (*d1).flags = 0 };
                    } else {
                        // rollback allocated chain buffers
                    }
                }
            }
            let b0 = MemifMutBuffer {
                desc_index: b0_desc_index,
                flags: b0_flags,
                len: b0_len,
                data: b0_data,
            };
            out.push(b0);
        }
        count -= 1;
    }
    if count > 0 {
        dbg!("ring buffer full, qid: {}", qid);
    }
    out
}

fn memif_buffer_enq_tx(
    conn: &MemifConn,
    from_q: &MemifQueue,
    qid: u16,
    bufs: &mut Vec<MemifBuffer<'_>>,
) -> u16 {
    let mq = &conn.tx_queues[qid as usize];
    let ring = memif_get_ring_by_offset(conn, mq.offset);
    let mask = ((1 << mq.log2_ring_size) - 1) as u16;
    let ring_size = 1 << mq.log2_ring_size as u16;
    let from_mask = ((1 << from_q.log2_ring_size) - 1) as u16;

    assert!(!conn.is_master);
    let mut count = bufs.len();
    let mq_next_buf = unsafe { mq.next_buf.get() };
    let ring_tail = unsafe { (*ring).tail.get() } as u32;
    let mut ns = ring_size - mq_next_buf + ring_tail;
    let mut i = 0;

    while count > 0 && ns > 0 {
        // swap the descriptors
        let slot = mq_next_buf;
        let from_index = bufs[i].desc_index;
        let to_d = memif_get_ring_desc_by_offset(conn, mq.offset, (slot & mask as u32) as u32);
        let from_d =
            memif_get_ring_desc_by_offset(conn, from_q.offset, (from_index & from_mask) as u32);
        unsafe { std::ptr::swap(to_d, from_d) };
        // update the descriptor in the buffer
        bufs[i].desc_index = slot as u16;

        unsafe { mq.next_buf.set(mq_next_buf + 1) };
        count -= 1;
        ns -= 1;
        i += 1;
    }
    if count > 0 {
        dbg!("ring buffer full {}", qid);
    }
    i as u16
}

pub fn memif_tx_burst(conn: &MemifConn, qid: u16, bufs: Vec<MemifMutBuffer<'_>>) -> u16 {
    let mq = &conn.tx_queues[qid as usize];
    let ring = memif_get_ring_by_offset(conn, mq.offset);
    let mask = ((1 << mq.log2_ring_size) - 1) as u16;

    if bufs.len() == 0 {
        return 0;
    }

    let mut count = bufs.len();
    let mut ntx = 0;

    let mut index = if conn.is_master {
        unsafe { (*ring).tail.get() }
    } else {
        unsafe { (*ring).head.get() }
    };

    let mut b0_desc_index = 0;

    while count > 0 {
        let b0 = &bufs[ntx];
        b0_desc_index = b0.desc_index;
        if b0.desc_index & mask != index & mask {
            panic!("Invalid desc index");
        }
        let d = memif_get_ring_desc_by_offset(conn, mq.offset, (b0.desc_index & mask) as u32);
        unsafe {
            (*d).length = b0.len;
            (*d).flags = if b0.flags & MEMIF_BUFFER_FLAG_NEXT != 0 {
                MEMIF_DESC_FLAG_NEXT
            } else {
                0
            }
        }
        if !conn.is_master {
            unsafe {
                // reset headroom
                (*d).offset -= (*d).offset % (conn.run_args.buffer_size as u32);
            }
            // calculate offset from user data
            let data_offset = unsafe {
                (b0.data.as_ptr() as *mut c_void)
                    .offset_from(conn.regions[(*d).region as usize].addr)
                    - (*d).offset as isize
            };
            if data_offset != 0 {
                if (data_offset < 0)
                    || (data_offset + b0.len as isize > conn.run_args.buffer_size as isize)
                {
                    break;
                }
                unsafe { (*d).offset += data_offset as u32 };
            }
        }
        ntx += 1;
        count -= 1;
        index += 1;
    }
    // memory barrier
    if conn.is_master {
        unsafe {
            (*ring).tail.set(b0_desc_index + 1);
        }
    } else {
        unsafe {
            (*ring).head.set(b0_desc_index + 1);
        }
    }
    return ntx.try_into().unwrap();
}

pub fn memif_rx_burst(conn: &MemifConn, qid: u16, count: u16) -> Vec<MemifBuffer<'_>> {
    let mut out = vec![];

    let mq = &conn.rx_queues[qid as usize];
    let ring = memif_get_ring_by_offset(conn, mq.offset);
    let mask = ((1 << mq.log2_ring_size) - 1) as u16;

    let mut cur_slot = if conn.is_master {
        mq.last_head.get()
    } else {
        mq.last_tail.get()
    };
    let mut last_slot = if conn.is_master {
        unsafe { (*ring).head.get() }
    } else {
        unsafe { (*ring).tail.get() }
    };
    if cur_slot == last_slot {
        return out;
    }
    let mut ns = last_slot - cur_slot;
    let mut count = count;
    while ns > 0 && count > 0 {
        let d = memif_get_ring_desc_by_offset(conn, mq.offset, (cur_slot & mask) as u32);
        let len = unsafe { (*d).length };
        let d_flags = unsafe { (*d).flags };
        let flags = if d_flags & MEMIF_DESC_FLAG_NEXT != 0 {
            MEMIF_BUFFER_FLAG_NEXT
        } else {
            0
        };
        let ptr = memif_get_buffer(conn, mq.offset, cur_slot & mask) as *const u8;
        let data = unsafe { std::slice::from_raw_parts(ptr, conn.run_args.buffer_size as usize) };
        let b = MemifBuffer {
            desc_index: cur_slot,
            flags,
            len,
            data,
        };

        if !conn.is_master {
            unsafe {
                (*d).length = conn.run_args.buffer_size as u32;
            }
        }
        if d_flags & MEMIF_DESC_FLAG_NEXT != 0 {
            unsafe { (*d).flags &= !MEMIF_DESC_FLAG_NEXT }
        }
        out.push(b);
        ns -= 1;
        count -= 1;
        cur_slot += 1;
    }
    if conn.is_master {
        mq.last_head.set(cur_slot);
    } else {
        mq.last_tail.set(cur_slot);
    }

    out
}
