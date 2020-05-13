use clap::{crate_version, App, AppSettings, Arg, SubCommand};
use netlink_packet_route::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NsidMessage, RtnlMessage,
};
use netlink_sys::{Protocol, Socket, SocketAddr};
use std::ffi::{OsStr, OsString};
use std::fs::{read_dir, OpenOptions};
use std::io;
use std::path::PathBuf;
use std::process;

struct NamedNetns {
    name: OsString,
    nsid: i32,
}

static NETNS_REF_DIR: &str = "/var/run/netns";

impl NamedNetns {
    fn new(name: OsString) -> io::Result<Self> {
        // socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE) = 3
        let mut sock = Socket::new(Protocol::Route)?;
        sock.connect(&SocketAddr::new(0, 0))?;

        let mut packet = NetlinkMessage {
            header: NetlinkHeader::default(),
            payload: NetlinkPayload::from(RtnlMessage::GetNsId(NsidMessage::default())),
        };

        Ok(NamedNetns {
            name: name,
            nsid: 0,
        })
    }
}

// setsockopt(3, SOL_SOCKET, SO_SNDBUF, [32768], 4) = 0
// setsockopt(3, SOL_SOCKET, SO_RCVBUF, [1048576], 4) = 0
// setsockopt(3, SOL_NETLINK, NETLINK_EXT_ACK, [1], 4) = 0
// bind(3, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 0
// sendto(3, {{len=28, type=RTM_GETNSID, flags=NLM_F_REQUEST, seq=0, pid=0}, {rtgen_family=AF_UNSPEC}, {{nla_len=8, nla_type=NETNSA_FD}, 4}}, 28, 0, NULL, 0) = 28
// recvmsg(3, {msg_name={sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, msg_namelen=12, msg_iov=[{iov_base={{len=28, type=RTM_NEWNSID, flags=0, seq=0, pid=5436}, {rtgen_family=AF_UNSPEC}, {{nla_len=8, nla_type=NETNSA_NSID}, -1}}, iov_len=16384}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 28
//

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
                let ns = NamedNetns::new(entry.file_name())?;
                println!("{} (id: {})", ns.name.to_string_lossy(), ns.nsid)
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
