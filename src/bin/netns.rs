use anyhow::{Context, Result};
use clap::{crate_version, App, AppSettings, Arg, SubCommand};
use netlink_packet_core::NLMSG_ERROR;
use netlink_packet_route::{
    nsid::Nla::{Fd, Id},
    traits::ParseableParametrized,
    DecodeError, NetlinkBuffer, NetlinkHeader, NetlinkMessage, NetlinkPayload, NsidHeader,
    NsidMessage, RtnlMessage, RtnlMessageBuffer, AF_UNSPEC, NLM_F_REQUEST, RTM_NEWNSID,
};
use netlink_packet_utils::parsers::parse_i32;
use netlink_sys::{Protocol, Socket};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{setns, unshare, CloneFlags};
use std::convert;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{create_dir_all, read_dir, remove_file, OpenOptions};
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
enum NetnsError {
    #[error("Invalid namespace name {0:?}")]
    InvalidName(OsString),

    #[error(transparent)]
    IOError(#[from] io::Error),

    #[error("Missing netlink nsid attribute")]
    MissingNsIdAttribute,

    #[error("Netlink decoding error")]
    NetlinkDecodeError(DecodeError),

    #[error("Unexpected netlink attribute")]
    UnexpectedNetlinkAttribute,

    #[error("Unexpected netlink response")]
    UnexpectedNetlinkResponse,
}

impl convert::From<DecodeError> for NetnsError {
    fn from(err: DecodeError) -> Self {
        NetnsError::NetlinkDecodeError(err)
    }
}

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

fn ref_path(name: &OsString) -> Result<PathBuf> {
    let mut path = PathBuf::from(NETNS_REF_DIR);
    path.push(name);
    match path.parent() {
        Some(p) => {
            if p.as_os_str() == NETNS_REF_DIR {
                Ok(path)
            } else {
                Err(NetnsError::InvalidName(name.clone()).into())
            }
        }
        None => Err(NetnsError::InvalidName(name.clone()).into()),
    }
}

fn ensure_shared_mount_point() -> Result<()> {
    create_dir_all(NETNS_REF_DIR)?;

    let mut remount_flags = MsFlags::empty();
    remount_flags.set(MsFlags::MS_SHARED, true);
    remount_flags.set(MsFlags::MS_REC, true);

    let remount_shared_rec = |path: &str| -> io::Result<()> {
        mount(NONE, path, NONE, remount_flags, NONE).or_else(|err| -> io::Result<()> {
            match err {
                nix::Error::Sys(errno) => Err(errno.into()),
                _ => Err(io::Error::new(io::ErrorKind::Other, "Unknwon error")),
            }
        })
    };

    remount_shared_rec(NETNS_REF_DIR).or_else(|err| match err.kind() {
        io::ErrorKind::InvalidInput => {
            let mut flags = MsFlags::empty();
            flags.set(MsFlags::MS_BIND, true);
            flags.set(MsFlags::MS_REC, true);
            mount(Some(NETNS_REF_DIR), NETNS_REF_DIR, NONE, flags, NONE).or_else(
                |err| match err {
                    nix::Error::Sys(errno) => Err(errno.into()),
                    _ => Err(io::Error::new(io::ErrorKind::Other, "Unknwon error")),
                },
            )?;

            remount_shared_rec(NETNS_REF_DIR)
        }
        otherwise => Err(otherwise.into()),
    })?;

    Ok(())
}

const NONE: Option<&'static [u8]> = None;

impl NamedNetns {
    fn create(name: &str) -> Result<Self> {
        ensure_shared_mount_point().with_context(|| format!("Cannot mount {}", NETNS_REF_DIR))?;

        let name = OsString::from(name);
        let ref_path_name = ref_path(&name)?;

        let orig_netns = OpenOptions::new().read(true).open("/proc/self/ns/net")?;

        fn create_netns_ref(ref_path_name: &PathBuf) -> Result<()> {
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(ref_path_name)?;

            Ok(())
        }

        fn create_netns() -> Result<()> {
            unshare(CloneFlags::CLONE_NEWNET)?;

            Ok(())
        }

        fn restore_netns(fd: RawFd) -> Result<()> {
            setns(fd, CloneFlags::CLONE_NEWNET)?;

            Ok(())
        }

        fn mount_netns_ref(ref_path_name: &PathBuf) -> Result<()> {
            mount(
                Some("/proc/self/ns/net"),
                ref_path_name,
                NONE,
                MsFlags::MS_BIND,
                NONE,
            )?;

            Ok(())
        }

        create_netns_ref(&ref_path_name)
            .with_context(|| format!("Cannot create {}", ref_path_name.to_string_lossy()))
            .and_then(|_| {
                create_netns()
                    .context("Cannot switch to new network namespace")
                    .and_then(|_| {
                        mount_netns_ref(&ref_path_name)
                            .with_context(|| {
                                format!("Cannot mount {}", ref_path_name.to_string_lossy())
                            })
                            .and_then(|_| {
                                restore_netns(orig_netns.as_raw_fd())
                                    .context("Error switching back to original network namespace")
                                    .and_then(|_| Self::from_name(name))
                                    .or_else(|err| {
                                        umount2(&ref_path_name, MntFlags::MNT_DETACH)?;
                                        Err(err)
                                    })
                            })
                            .or_else(|err| {
                                restore_netns(orig_netns.as_raw_fd())?;
                                Err(err)
                            })
                    })
                    .or_else(|err| {
                        remove_file(&ref_path_name)?;
                        Err(err)
                    })
            })
    }

    fn from_name(name: OsString) -> Result<Self> {
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
            .map_err(|err| -> NetnsError { err.into() })?;
        let recv_payload = recv_packet.payload();

        if recv_packet.message_type() == NLMSG_ERROR {
            // Error code in the first 4 octets of payload, and it's negated.
            let errno =
                -parse_i32(&recv_payload[..4]).map_err(|err| -> NetnsError { err.into() })?;
            return Err(io::Error::from_raw_os_error(errno).into());
        }

        let recv_msgbuf = RtnlMessageBuffer::new(&recv_payload);
        match RtnlMessage::parse_with_param(&recv_msgbuf, RTM_NEWNSID) {
            Ok(RtnlMessage::NewNsId(NsidMessage { nlas, .. })) => match nlas.get(0) {
                Some(Id(id)) => Ok(Self {
                    name,
                    nsid: match id {
                        -1 => None,
                        _ => Some(*id),
                    },
                }),
                Some(_unexpected) => Err(NetnsError::UnexpectedNetlinkAttribute.into()),
                None => Err(NetnsError::MissingNsIdAttribute.into()),
            },
            Ok(_unexpected) => Err(NetnsError::UnexpectedNetlinkResponse.into()),
            Err(err) => Err(NetnsError::NetlinkDecodeError(err).into()),
        }
    }

    fn delete(name: &str) -> Result<()> {
        let name = OsString::from(name);
        let ref_path_name = ref_path(&name)?;

        fn unmount_ref(ref_path_name: &PathBuf) -> Result<()> {
            umount2(ref_path_name, MntFlags::MNT_DETACH)?;
            Ok(())
        }

        fn remove_ref(ref_path_name: &PathBuf) -> Result<()> {
            remove_file(ref_path_name)?;
            Ok(())
        }

        unmount_ref(&ref_path_name)
            .with_context(|| format!("Cannot unmount {}", ref_path_name.to_string_lossy()))?;

        remove_ref(&ref_path_name)
            .with_context(|| format!("Cannot remove {}", ref_path_name.to_string_lossy()))
    }
}

fn create_ns(name: &str) -> Result<()> {
    NamedNetns::create(name).with_context(|| format!("Cannot create namespace {}", name))?;
    Ok(())
}

fn delete_ns(name: &str) -> Result<()> {
    NamedNetns::delete(name).with_context(|| format!("Cannot delete namespace {}", name))?;
    Ok(())
}

fn list_netns() -> Result<()> {
    read_dir(OsStr::new(NETNS_REF_DIR))
        .and_then(|rd| {
            for entry in rd {
                let entry = entry?;

                match NamedNetns::from_name(entry.file_name()) {
                    Ok(ns) => println!("{}", ns),
                    Err(err) => eprintln!(
                        "Invalid namespace reference '{}': {}",
                        entry.path().to_string_lossy(),
                        err
                    ),
                }
            }
            Ok(())
        })
        .or_else(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(err.into())
            }
        })
}

fn main() -> Result<()> {
    let matches = App::new("netns")
        .version(crate_version!())
        .setting(AppSettings::SubcommandRequired)
        .subcommand(
            SubCommand::with_name("create")
                .about("Creates a named network namespace")
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
            create_ns(matches.value_of("name").unwrap())
        }
        Some("delete") => {
            let matches = matches.subcommand_matches("delete").unwrap();
            delete_ns(matches.value_of("name").unwrap())
        }
        Some("list") => list_netns(),
        _ => {
            unreachable!();
        }
    }
}
