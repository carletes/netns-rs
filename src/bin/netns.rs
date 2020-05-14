use clap::{crate_version, App, AppSettings, Arg, SubCommand};
use netlink_packet_route::{
    nsid::Nla::{Fd, Id},
    traits::ParseableParametrized,
    NetlinkBuffer, NetlinkHeader, NetlinkMessage, NetlinkPayload, NsidHeader, NsidMessage,
    RtnlMessage, RtnlMessageBuffer, AF_UNSPEC, NLM_F_REQUEST, RTM_NEWNSID,
};
use netlink_sys::{Protocol, Socket};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{read_dir, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::process;

struct NamedNetns {
    name: OsString,
    nsid: Option<i32>,
}

impl fmt::Display for NamedNetns {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let nsid = match self.nsid {
            Some(nsid) => format!("{}", nsid),
            None => "undefined".to_string(),
        };

        write!(f, "{} (nsid: {})", self.name.to_string_lossy(), nsid)
    }
}

static NETNS_REF_DIR: &str = "/var/run/netns";

fn ref_path(name: &OsString) -> io::Result<PathBuf> {
    let mut path = PathBuf::from(NETNS_REF_DIR);
    path.push(name);
    match path.parent() {
        Some(p) => {
            if p.as_os_str() == NETNS_REF_DIR {
                Ok(path)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Invalid namespace name {}", name.to_string_lossy()),
                ))
            }
        }
        None => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Invalid namespace name {}", name.to_string_lossy()),
        )),
    }
}

impl NamedNetns {
    fn new(name: OsString) -> io::Result<Self> {
        let ref_file = OpenOptions::new().read(true).open(ref_path(&name)?)?;

        // socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE) = 4
        let mut sock = Socket::new(Protocol::Route)?;

        // bind(4, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 0
        sock.bind_auto()?;

        let mut req = NetlinkMessage {
            header: NetlinkHeader {
                flags: NLM_F_REQUEST,
                sequence_number: 0,
                ..Default::default()
            },
            payload: NetlinkPayload::from(RtnlMessage::GetNsId(NsidMessage {
                header: NsidHeader {
                    rtgen_family: AF_UNSPEC as u8,
                },
                nlas: vec![Fd(ref_file.as_raw_fd() as u32)],
            })),
        };

        req.finalize();

        let mut buf = vec![0; 1024 * 8];
        req.serialize(&mut buf[..req.buffer_len()]);
        sock.send(&buf, 0)?;

        let mut recv_buf = vec![0; 1024 * 8];
        sock.recv(&mut recv_buf[..], 0)?;

        let recv_packet = NetlinkBuffer::new_checked(&recv_buf[..])
            .or_else(|err| Err(io::Error::new(io::ErrorKind::Other, format!("{:?}", err))))?;
        let recv_payload = recv_packet.payload();
        let recv_msgbuf = RtnlMessageBuffer::new(&recv_payload);
        match RtnlMessage::parse_with_param(&recv_msgbuf, RTM_NEWNSID) {
            Ok(RtnlMessage::NewNsId(NsidMessage { nlas, .. })) => match nlas.get(0) {
                Some(Id(id)) => Ok(NamedNetns {
                    name: name,
                    nsid: match id {
                        -1 => None,
                        _ => Some(*id),
                    },
                }),
                Some(unexpected) => Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Unexpected netlink attribute: {:?}", unexpected),
                )),
                None => Err(io::Error::new(
                    io::ErrorKind::Other,
                    "No nsid attribute returned",
                )),
            },
            Ok(unexpected) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Unexpected netlink response: {:?}", unexpected),
            )),
            Err(err) => Err(io::Error::new(io::ErrorKind::Other, format!("{:?}", err))),
        }
    }
}

fn create_ns(name: &str, veth_prefix: &str) -> io::Result<()> {
    // println!("ip netns add {}", name);
    let mut ref_path = PathBuf::from(NETNS_REF_DIR);
    ref_path.push(name);
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(ref_path)?;

    let veth_dev = format!("{}XX", veth_prefix);
    let veth_peer = format!("{}YY", veth_prefix);
    println!("ip link add {} type veth peer {}", veth_dev, veth_peer);
    println!("ip link set {} netns {}", veth_peer, name);

    Ok(())
}

fn list_netns() -> io::Result<()> {
    match read_dir(OsStr::new(NETNS_REF_DIR)) {
        Ok(rd) => {
            for entry in rd {
                let entry = entry?;

                match NamedNetns::new(entry.file_name()) {
                    Ok(ns) => println!("{}", ns),
                    Err(err) => eprintln!("{}", err),
                }
            }
            Ok(())
        }
        Err(err) => {
            if err.kind() == io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(err)
            }
        }
    }
}

fn main() {
    let matches = App::new("netns")
        .version(crate_version!())
        .setting(AppSettings::SubcommandRequired)
        .subcommand(
            SubCommand::with_name("create")
                .about("Creates a named network namespace")
                .arg(
                    Arg::with_name("veth-prefix")
                        .value_name("PREFIX")
                        .long("veth-prefix")
                        .help("Base prefix of the veth device pair")
                        .default_value("veth"),
                )
                .arg(
                    Arg::with_name("veth-address")
                        .value_name("ADDR/PREFIX")
                        .long("veth-address")
                        .help("IPv4 address of the veth device in the current network namespace"),
                )
                .arg(
                    Arg::with_name("veth-peer-address")
                        .value_name("ADDR/PREFIX")
                        .long("veth-peer-address")
                        .help("IPv4 address of the veth device in the new network namespace")
                        .default_value("10.1.1.1/24"),
                )
                .arg(
                    Arg::with_name("name")
                        .value_name("NAME")
                        .help("Name of the new network namespace")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("delete")
                .about("Deletes a named network namespace")
                .arg(
                    Arg::with_name("name")
                        .value_name("NAME")
                        .help("Name of the network namespace")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(SubCommand::with_name("list").about("Lists all named network namespaces"))
        .get_matches();

    match matches.subcommand_name() {
        Some("create") => {
            let matches = matches.subcommand_matches("create").unwrap();
            match create_ns(
                matches.value_of("name").unwrap(),
                matches.value_of("veth-prefix").unwrap(),
            ) {
                Ok(_) => process::exit(0),
                Err(err) => {
                    eprintln!("Error: {:?}", err);
                    process::exit(1);
                }
            }
        }
        Some("delete") => {}
        Some("list") => match list_netns() {
            Ok(_) => process::exit(0),
            Err(err) => {
                eprintln!("Error: {:?}", err);
                process::exit(1);
            }
        },
        _ => {
            unreachable!();
        }
    }
}
