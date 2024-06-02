use crate::{
    commands::{SimplPedPoPRound2, SimplPedPoPRound2Context},
    types::path_buf::PathBuf,
};

use super::SaveImplicitAccountContext;
use color_eyre::eyre::Context;
use olaf::simplpedpop::AllMessage;
use serde_json::from_str;
use std::{fs, io::Write};

#[derive(Debug, Clone, interactive_clap::InteractiveClap)]
#[interactive_clap(input_context = crate::GlobalContext)]
#[interactive_clap(output_context = Round2Context)]
pub struct Round2 {
    #[interactive_clap(skip_default_input_arg)]
    /// What is the sender account ID?
    pub sender_account_id: crate::types::account_id::AccountId,
    #[interactive_clap(long)]
    /// The folder that contains the files for the round 1 of the SimplPedPoP protocol
    files: PathBuf,
    #[interactive_clap(named_arg)]
    /// Select network
    network_config: crate::network_for_simplpedpop_round2::NetworkForTransactionArgs,
    //#[interactive_clap(named_arg)]
    // Specify a folder to save the implicit account file
    //save_to_folder: super::SaveToFolder,
}

#[derive(Clone)]
struct Round2Context(SimplPedPoPRound2Context);

impl Round2Context {
    pub fn from_previous_context(
        previous_context: crate::GlobalContext,
        scope: &<Round2 as interactive_clap::ToInteractiveClapContextScope>::InteractiveClapContextScope,
    ) -> color_eyre::eyre::Result<Self> {
        let on_after_getting_network_callback: crate::commands::OnAfterGettingNetworkCallbackSimplPedPoPRound2 =
            std::sync::Arc::new({
                let signer_id = scope.sender_account_id.0.clone();

                let file_path: std::path::PathBuf = scope.files.clone().into();

                let all_messages_string = fs::read_to_string(file_path.join("all_messages.json")).unwrap();

                let all_messages_bytes: Vec<Vec<u8>> = from_str(&all_messages_string).unwrap();

                let all_messages: Vec<AllMessage> = all_messages_bytes
                    .iter()
                    .map(|all_message| AllMessage::from_bytes(all_message).unwrap())
                    .collect();

                move |_network_config| {
                    Ok(crate::commands::SimplPedPoPRound2 { signer_id: signer_id.clone(), messages: all_messages.clone() })
                }
            });

        Ok(Self(crate::commands::SimplPedPoPRound2Context {
            global_context: previous_context,
            on_after_getting_network_callback,
            on_before_signing_callback: std::sync::Arc::new(
                |_prepolulated_unsinged_transaction, _network_config| Ok(()),
            ),
        }))
    }
}

impl Round2 {
    pub fn input_sender_account_id(
        context: &crate::GlobalContext,
    ) -> color_eyre::eyre::Result<Option<crate::types::account_id::AccountId>> {
        crate::common::input_signer_account_id_from_used_account_list(
            &context.config.credentials_home_dir,
            "What is the sender account ID?",
        )
    }
}

impl From<Round2Context> for crate::commands::SimplPedPoPRound2Context {
    fn from(item: Round2Context) -> Self {
        item.0
    }
}
