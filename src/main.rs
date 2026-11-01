#[macro_use]
extern crate log;

use std::fmt;
use std::net::SocketAddr;
use std::{fs, io, process};

use anyhow::{Result, anyhow, bail};

use clap::Parser;
use serde::Deserialize;

use base64;
use radius::core::rfc3580::TUNNEL_TYPE_VLAN;
use radius::core::tag::Tag;
use sha2::{Digest, Sha256};

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::signal;

use radius::core::code::Code;
use radius::core::packet::Packet;
use radius::core::request::Request;
use radius::core::rfc2865::{
    NAS_PORT_TYPE_ETHERNET, lookup_calling_station_id, lookup_nas_port_type, lookup_user_name,
    lookup_user_password,
};
use radius::core::rfc2868::{
    TUNNEL_MEDIUM_TYPE_IEEE_802, add_tunnel_medium_type, add_tunnel_password,
    add_tunnel_private_group_id, add_tunnel_type,
};
use radius::server::{RequestHandler, SecretProvider, SecretProviderError, Server};

use hex;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(default_value = "::", short, long)]
    address: String,
    #[arg(default_value_t = 1812, short, long)]
    port: u16,
    config_file: String,
}

#[derive(Deserialize, Debug)]
#[serde(
    rename_all = "SCREAMING_SNAKE_CASE",
    tag = "wlan_access_type",
    content = "wlan_access_parameter"
)]
enum WlanAccessType {
    NoAccess,
    FixedPsk(String),
    HmacPsk(String),
}

#[derive(Deserialize, Debug)]
struct Network {
    name: String,
    #[serde(flatten)]
    wlan_access: WlanAccessType,
    vlan_id: u16,
    mac_addrs: Vec<MACAddr>,
}

#[derive(Deserialize, Debug)]
struct Networks {
    fallback_network: String,
    #[serde(rename = "network")]
    networks: Vec<Network>,
}

impl Networks {
    fn network_for_mac(&self, mac: &MACAddr) -> Result<&Network> {
        for n in &self.networks {
            if n.mac_addrs.contains(mac) {
                return Ok(&n);
            }
        }
        for n in &self.networks {
            if n.name == self.fallback_network {
                return Ok(&n);
            }
        }
        bail!("Couldn't find a fallback network")
    }
}

#[derive(Deserialize, Debug)]
struct ConfigFile {
    radius_secret: String,
    hmac_psk_len: usize,
    networks: Networks,
}

fn read_config(path: &str) -> Result<ConfigFile> {
    let config_text = io::read_to_string(fs::File::open(path)?)?;
    Ok(toml::from_str(&config_text)?)
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    let config = match read_config(&args.config_file) {
        Ok(c) => c,
        Err(e) => bail!("Couldn't read config file '{}': {}", args.config_file, e),
    };

    // start UDP listening
    let secprov = MySecretProvider {
        secret: config.radius_secret.clone().into_bytes(),
    };
    let mut server = match Server::listen(
        &args.address,
        args.port,
        MyRequestHandler { config: config },
        secprov,
    )
    .await
    {
        Ok(server) => server,
        Err(err) => {
            error!("Failed to start server: {}", err.to_string());
            process::exit(1);
        }
    };
    server.set_buffer_size(1500); // default value: 1500
    server.set_skip_authenticity_validation(false); // default value: false

    // once it has reached here, a RADIUS server is now ready
    info!(
        "Server is now ready: {}",
        server.get_listen_address().unwrap()
    );

    // start the loop to handle the RADIUS requests
    server.run(signal::ctrl_c()).await?;
    Ok(())
}

#[derive(Debug, PartialEq)]
struct MACAddr([u8; 6]);

impl<'de> serde::Deserialize<'de> for MACAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let str = String::deserialize(deserializer)?;
        let res = Self::try_from(str).map_err(|e| serde::de::Error::custom(e))?;
        Ok(res)
    }
}

impl TryFrom<String> for MACAddr {
    type Error = anyhow::Error;

    fn try_from(val: String) -> Result<Self> {
        let parts = val.split(&['-', ':']);
        let res: Result<Vec<u8>> = parts.map(|i| Ok(u8::from_str_radix(i, 16)?)).collect();
        Ok(res?.try_into()?)
    }
}

impl From<[u8; 6]> for MACAddr {
    fn from(val: [u8; 6]) -> Self {
        Self(val)
    }
}

impl TryFrom<Vec<u8>> for MACAddr {
    type Error = anyhow::Error;

    fn try_from(val: Vec<u8>) -> Result<Self, Self::Error> {
        let val = val.as_array().ok_or(anyhow!("Conversion error"))?;
        Ok(Self(*val))
    }
}

impl AsRef<[u8]> for MACAddr {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for MACAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

fn parse_mac_address(addr: &Vec<u8>) -> Result<MACAddr> {
    let result = hex::decode(&addr[..])?;
    result.try_into()
}

fn get_ppsk(master_pwd: &String, mac: &MACAddr, bytes: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(master_pwd.as_bytes());
    hasher.update(mac);
    let hashed = hasher.finalize();
    let (trunc, _) = hashed.split_at(bytes);
    base64::encode(&trunc)
}

fn get_mac_from_request(req: &Packet) -> Result<MACAddr> {
    match lookup_calling_station_id(req) {
        Some(Ok(id)) => id.try_into(),
        _ => match lookup_user_password(req) {
            Some(Ok(pw)) => parse_mac_address(&pw),
            _ => match lookup_user_name(req) {
                Some(Ok(user)) => user.try_into(),
                _ => Err(anyhow!("Couldn't get MAC address from request")),
            },
        },
    }
}

struct MyRequestHandler {
    config: ConfigFile,
}

fn add_tunnel_info(vlan_id: u16, ppsk: Option<&String>, tag: &Tag, resp: &mut Packet) {
    if let Some(ppsk) = ppsk {
        let to_sized = |message: &[u8]| [vec![message.len() as u8], message.to_vec()].concat();
        add_tunnel_password(resp, Some(&tag), &to_sized(&ppsk.as_bytes())[..]).unwrap();
    }
    add_tunnel_type(resp, Some(&tag), TUNNEL_TYPE_VLAN);
    add_tunnel_medium_type(resp, Some(&tag), TUNNEL_MEDIUM_TYPE_IEEE_802);
    add_tunnel_private_group_id(resp, Some(&tag), &vlan_id.to_string().as_str());
}

fn answer_packet(handler: &MyRequestHandler, req: &Packet) -> Result<Packet> {
    let mac_addr = get_mac_from_request(req)?;

    let port_type = match lookup_nas_port_type(req) {
        Some(Ok(t)) => Some(t),
        _ => None,
    };

    let network = handler.config.networks.network_for_mac(&mac_addr)?;

    let ppsk = match port_type {
        Some(NAS_PORT_TYPE_ETHERNET) => None,
        _ => match &network.wlan_access {
            WlanAccessType::NoAccess => None,
            WlanAccessType::FixedPsk(psk) => Some(psk),
            WlanAccessType::HmacPsk(key) => {
                Some(&get_ppsk(&key, &mac_addr, handler.config.hmac_psk_len))
            }
        },
    };

    let mut resp = req.make_response_packet(Code::AccessAccept);
    info!(
        "Assigning {mac_addr} to network {} (vlan {})",
        network.name, network.vlan_id
    );
    add_tunnel_info(network.vlan_id, ppsk, &Tag::new(1), &mut resp);

    Ok(resp)
}

#[async_trait]
impl RequestHandler<(), io::Error> for MyRequestHandler {
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        let req_packet = req.get_packet();

        let resp = answer_packet(&self, &req_packet).unwrap_or_else(|err| {
            error!("{}", err);
            req_packet.make_response_packet(Code::AccessReject)
        });

        conn.send_to(&resp.encode().unwrap(), req.get_remote_addr())
            .await?;
        Ok(())
    }
}

struct MySecretProvider {
    secret: Vec<u8>,
}

impl SecretProvider for MySecretProvider {
    fn fetch_secret(&self, _remote_addr: SocketAddr) -> Result<Vec<u8>, SecretProviderError> {
        Ok(self.secret.clone())
    }
}
