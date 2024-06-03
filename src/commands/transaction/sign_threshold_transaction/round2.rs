use ed25519_dalek::VerifyingKey;
use olaf::simplpedpop::AllMessage;
use serde_json::from_str;
use std::{
    fs::{self, File},
    io::Write,
};

use crate::types::path_buf::PathBuf;

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
    network_config: crate::network_for_frost_round2::NetworkForTransactionArgs,
}

#[derive(Clone)]
pub struct Round2Context(crate::commands::FrostRound2ActionContext);

impl Round2Context {
    pub fn from_previous_context(
        previous_context: crate::GlobalContext,
        scope: &<Round2 as interactive_clap::ToInteractiveClapContextScope>::InteractiveClapContextScope,
    ) -> color_eyre::eyre::Result<Self> {
        let on_after_getting_network_callback: crate::commands::OnAfterGettingNetworkCallbackFrostRound2 =
            std::sync::Arc::new({
                let signer_id = scope.sender_account_id.0.clone();

                let file_path: std::path::PathBuf = scope.files.clone().into();

                let recipients_string = fs::read_to_string(file_path.join("recipients.json")).unwrap();

                let encoded_strings: Vec<String> = serde_json::from_str(&recipients_string).unwrap();

                //let recipients_bytes: Vec<Vec<u8>> = from_str(&recipients_string).unwrap();

                let recipients: Vec<VerifyingKey> = encoded_strings
                    .iter()
                    .map(|encoded_string| {
                        let s = bs58::decode(encoded_string).into_vec().unwrap();
                        let mut recipient = [0; 32];
                        recipient.copy_from_slice(&s);
                        VerifyingKey::from_bytes(&recipient).unwrap()
                    })
                    .collect();

                move |_network_config| {
                    Ok(crate::commands::FrostRound2 { signer_id: signer_id.clone() })
                }
            });

        Ok(Self(crate::commands::FrostRound2ActionContext {
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

impl From<Round2Context> for crate::commands::FrostRound2ActionContext {
    fn from(item: Round2Context) -> Self {
        item.0
    }
}
