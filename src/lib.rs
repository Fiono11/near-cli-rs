#![allow(clippy::arc_with_non_send_sync)]
pub use common::CliResult;

pub mod commands;
pub mod common;
pub mod config;
pub mod frost_aggregate_signature_options;
pub mod frost_round1_signature_options;
pub mod frost_round2_signature_options;
pub mod js_command_match;
pub mod network;
pub mod network_for_frost_aggregate;
pub mod network_for_frost_round1;
pub mod network_for_frost_round2;
pub mod network_for_simplpedpop_round2;
pub mod network_for_threshold_account;
pub mod network_for_transaction;
pub mod network_view_at_block;
pub mod simplpedpop_round2_signature_options;
pub mod threshold_account_signature_options;
pub mod transaction_signature_options;
pub mod types;
pub mod utils_command;

#[derive(Debug, Clone)]
pub struct GlobalContext {
    pub config: crate::config::Config,
    pub offline: bool,
}
