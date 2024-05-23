use ed25519_dalek::{olaf::simplpedpop::AllMessage, SigningKey, VerifyingKey};
use serde_json::from_str;
use std::{
    fs::{self, File},
    io::Write,
};

use crate::types::path_buf::PathBuf;

#[derive(Debug, Clone, interactive_clap::InteractiveClap)]
#[interactive_clap(input_context = crate::GlobalContext)]
#[interactive_clap(output_context = SimplpedpopRound1Context)]
pub struct SimplpedpopRound1 {
    #[interactive_clap(long)]
    /// The folder that contains the files for the round 1 of the SimplPedPoP protocol
    round1: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SimplpedpopRound1Context;

impl SimplpedpopRound1Context {
    pub fn from_previous_context(
        previous_context: crate::GlobalContext,
        scope: &<SimplpedpopRound1 as interactive_clap::ToInteractiveClapContextScope>::InteractiveClapContextScope,
    ) -> color_eyre::eyre::Result<Self> {
        let file_path: std::path::PathBuf = scope.round1.clone().into();

        let secret_key_string = fs::read_to_string(file_path.join("secret_key.json")).unwrap();

        let secret_key_vec: Vec<u8> = from_str(&secret_key_string).unwrap();

        let mut secret_key_bytes = [0; 32];
        secret_key_bytes.copy_from_slice(&secret_key_vec[..32]);

        let mut keypair = SigningKey::from_bytes(&secret_key_bytes);

        let recipients_string = fs::read_to_string(file_path.join("recipients.json")).unwrap();

        let recipients_bytes: Vec<Vec<u8>> = from_str(&recipients_string).unwrap();

        let recipients: Vec<VerifyingKey> = recipients_bytes
            .iter()
            .map(|recipient_bytes| {
                let mut recipient = [0; 32];
                recipient.copy_from_slice(recipient_bytes);
                VerifyingKey::from_bytes(&recipient).unwrap()
            })
            .collect();

        let all_message: AllMessage = keypair.simplpedpop_contribute_all(2, recipients).unwrap();

        let all_message_bytes: Vec<u8> = all_message.to_bytes();
        let all_message_vec: Vec<Vec<u8>> = vec![all_message_bytes];

        let all_message_json = serde_json::to_string_pretty(&all_message_vec).unwrap();

        let mut all_message_file = File::create(file_path.join("all_messages.json")).unwrap();

        all_message_file
            .write_all(&all_message_json.as_bytes())
            .unwrap();
        Ok(Self)
    }
}
