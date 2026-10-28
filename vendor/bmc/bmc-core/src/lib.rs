//! bmc-kvm — native KVM console client and IPMI manager for server BMCs
//! (Supermicro/ATEN, Quanta/AMI MegaRAC, HP iLO 4, Dell iDRAC 9, Dell
//! iDRAC 8, ASRock Rack/AMI SP-X and Gigabyte/Avocent MergePoint).
//!
//! This crate is the protocol core: every family's console, media, power and
//! IPMI code, the inventory and the network routes, with no GUI toolkit, so
//! the CLI and each GUI build on the same code.

pub mod ast2100;
pub mod auth;
pub mod avct_dvc;
pub mod changelog;
pub mod clock;
pub mod confirm;
pub mod console;
pub mod creds;
pub mod damage;
pub mod event_log;
pub mod events;
pub mod families;
pub mod frame_pump;
pub mod hosts;
pub mod httpd;
pub mod ilo_dvc;
pub mod image;
pub mod import;
pub mod inflate;
pub mod input;
pub mod inventory;
pub mod ipmi;
pub mod ipmi_records;
pub mod jobs;
pub mod keys;
pub mod latency;
pub mod legacy_tls;
pub mod media;
pub mod media_source;
pub mod net;
pub mod power;
pub mod preview;
pub mod probes;
pub mod process;
pub mod rand;
pub mod rfb;
pub mod routes;
pub mod sessions;
pub mod signals;
pub mod tables;
pub mod takeover;
pub mod vmedia;
pub mod vnc;
pub mod ws;
