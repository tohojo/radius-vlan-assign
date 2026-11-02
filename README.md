# RADIUS server for VLAN assignment and stateless PPSKs

A Rust implementation of a radius server that allows assigning VLANs to WiFi
access points (using hostapd) and Unifi enterprise switch ports (using Unifi
802.1X support).

The code is forked from
[hostapd-slppsk-radius](https://github.com/fakuivan/hostapd-slppsk-radius) but
updated with a new config format and support for assigning VLANs to wired
switches as well.

## HMAC-PSK support

The HMAC-PSK idea comes from [hostapd-slppsk](https://github.com/fakuivan/hostapd-slppsk).
The main difference being that it does not use the `wpa_psk_file` config, instead it uses
`wpa_psk_radius` to request the PPSK for each station. The generated PPSKs should be exactly
the same to hostapd-slppsk given the same Master Password and configs.

The main advantage with this approach is that there's no need to keep a psk file in sync,
hence the design is less hacky, possibly leaner on the CPU and definitely way more scalable.
However Rust binaries are huge, even after a lot of optimizations I managed to reduce
the file size to barely less than 1MB, which is too large considering most routers come
with 8 to 16MB of flash storage.

## OpenWRT AP

```conf
config wifi-iface
   ## ...
   list hostapd_bss_options 'auth_server_addr=<radius server ip>'
   list hostapd_bss_options 'auth_server_port=<radius server port>'
   list hostapd_bss_options 'macaddr_acl=2'
   list hostapd_bss_options 'wpa_psk_radius=2'
   list hostapd_bss_options 'auth_server_shared_secret=<radius server secret>'
   # TODO add nas-id option `with radius_auth_req_attr`
```

## Slim executable

[min-sized-rust](https://github.com/johnthagen/min-sized-rust)

The minsize progfile in [Cargo.toml](./Cargo.toml) can be used to reduce the size of the
binary.

## Cross compiling

[cross-rs](https://github.com/cross-rs/cross), but feel free to use cargo and the OpenWRT SDK.
