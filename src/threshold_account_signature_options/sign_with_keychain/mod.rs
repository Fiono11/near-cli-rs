use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

use color_eyre::eyre::{ContextCompat, WrapErr};
use color_eyre::owo_colors::OwoColorize;
use ed25519_dalek::olaf::simplpedpop::AllMessage;
use ed25519_dalek::SigningKey;
use inquire::CustomType;
use near_crypto::ED25519SecretKey;
use tracing_indicatif::span_ext::IndicatifSpanExt;

use crate::common::JsonRpcClientExt;
use crate::common::RpcQueryResponseExt;

#[derive(Debug, Clone, interactive_clap::InteractiveClap)]
#[interactive_clap(input_context = crate::commands::ThresholdAccountContext)]
#[interactive_clap(output_context = SignKeychainContext)]
pub struct SignKeychain {
    #[interactive_clap(long)]
    #[interactive_clap(skip_default_input_arg)]
    signer_public_key: Option<crate::types::public_key::PublicKey>,
    /*#[interactive_clap(long)]
    #[interactive_clap(skip_default_input_arg)]
    nonce: Option<u64>,
    #[interactive_clap(long)]
    #[interactive_clap(skip_default_input_arg)]
    block_hash: Option<crate::types::crypto_hash::CryptoHash>,
    #[interactive_clap(long)]
    #[interactive_clap(skip_default_input_arg)]
    block_height: Option<near_primitives::types::BlockHeight>,
    #[interactive_clap(long)]
    #[interactive_clap(skip_interactive_input)]
    meta_transaction_valid_for: Option<u64>,
    #[interactive_clap(subcommand)]
    submit: super::Submit,*/
}

//pub struct SignKeychainContext;

#[derive(Clone)]
pub struct SignKeychainContext {
    network_config: crate::config::NetworkConfig,
    global_context: crate::GlobalContext,
    //signed_transaction_or_signed_delegate_action: super::SignedTransactionOrSignedDelegateAction,
    //on_before_sending_transaction_callback:
    //crate::transaction_signature_options::OnBeforeSendingTransactionCallback,
    //on_after_sending_transaction_callback:
    //crate::transaction_signature_options::OnAfterSendingTransactionCallback,
}

impl From<super::sign_with_legacy_keychain::SignLegacyKeychainContext> for SignKeychainContext {
    fn from(value: super::sign_with_legacy_keychain::SignLegacyKeychainContext) -> Self {
        SignKeychainContext {
            network_config: value.network_config,
            global_context: value.global_context,
            //signed_transaction_or_signed_delegate_action: value
            //.signed_transaction_or_signed_delegate_action,
            //on_before_sending_transaction_callback: value.on_before_sending_transaction_callback,
            //on_after_sending_transaction_callback: value.on_after_sending_transaction_callback,
        }
    }
}

impl SignKeychainContext {
    #[tracing::instrument(
        name = "Signing the transaction with a key saved in the secure keychain ...",
        skip_all
    )]
    pub fn from_previous_context(
        previous_context: crate::commands::ThresholdAccountContext,
        scope: &<SignKeychain as interactive_clap::ToInteractiveClapContextScope>::InteractiveClapContextScope,
    ) -> color_eyre::eyre::Result<Self> {
        let file_path = PathBuf::from_str("src/commands/account/create_threshold_account").unwrap();

        let recipients = previous_context
            .prepopulated_threshold_account
            .receivers_id
            .clone();

        let network_config = previous_context.network_config.clone();

        let service_name = std::borrow::Cow::Owned(format!(
            "near-{}-{}",
            network_config.network_name,
            previous_context
                .prepopulated_threshold_account
                .signer_id
                .as_str()
        ));

        let password = if previous_context.global_context.offline {
            let res = keyring::Entry::new(
                &service_name,
                &format!(
                    "{}:{}",
                    previous_context.prepopulated_threshold_account.signer_id,
                    scope.signer_public_key.clone().wrap_err(
                        "Signer public key is required to sign a transaction in offline mode"
                    )?
                ),
            )?
            .get_password();

            match res {
                Ok(password) => password,
                Err(err) => {
                    match matches!(err, keyring::Error::NoEntry) {
                        true => eprintln!("Warning: no access key found in keychain"),
                        false => eprintln!("Warning: keychain was not able to be read, {}", err),
                    }

                    eprintln!("trying with the legacy keychain");
                    return from_legacy_keychain(previous_context, scope);
                }
            }
        } else {
            let access_key_list = network_config
                .json_rpc_client()
                .blocking_call_view_access_key_list(
                    &previous_context.prepopulated_threshold_account.signer_id,
                    near_primitives::types::Finality::Final.into(),
                )
                .wrap_err_with(|| {
                    format!(
                        "Failed to fetch access key list for {}",
                        previous_context.prepopulated_threshold_account.signer_id
                    )
                })?
                .access_key_list_view()?;

            let res = access_key_list
                .keys
                .into_iter()
                .filter(|key| {
                    matches!(
                        key.access_key.permission,
                        near_primitives::views::AccessKeyPermissionView::FullAccess
                    )
                })
                .map(|key| key.public_key)
                .find_map(|public_key| {
                    let keyring = keyring::Entry::new(
                        &service_name,
                        &format!(
                            "{}:{}",
                            previous_context.prepopulated_threshold_account.signer_id, public_key
                        ),
                    )
                    .ok()?;
                    keyring.get_password().ok()
                });

            match res {
                Some(password) => password,
                None => {
                    // no access keys found, try the legacy keychain
                    warning_message(format!(
                        "{}",
                        "no access keys found in keychain, trying legacy keychain".red()
                    ));
                    return from_legacy_keychain(previous_context, scope);
                }
            }
        };

        let account_json: super::AccountKeyPair =
            serde_json::from_str(&password).wrap_err("Error reading data")?;

        let mut signing_key =
            SigningKey::from_keypair_bytes(&account_json.private_key.unwrap_as_ed25519().0)
                .unwrap();

        let all_message: AllMessage = signing_key
            .simplpedpop_contribute_all(2, recipients)
            .unwrap();

        let all_message_bytes: Vec<u8> = all_message.to_bytes();
        let all_message_vec: Vec<Vec<u8>> = vec![all_message_bytes];

        let all_message_json = serde_json::to_string_pretty(&all_message_vec).unwrap();

        let mut all_message_file = File::create(file_path.join("all_messages.json")).unwrap();

        all_message_file
            .write_all(&all_message_json.as_bytes())
            .unwrap();

        Ok(Self {
            network_config: previous_context.network_config,
            global_context: previous_context.global_context,
        })
    }
}

#[tracing::instrument(name = "Warning:", skip_all)]
fn warning_message(instrument_message: String) {
    tracing::Span::current().pb_set_message(&instrument_message);
    std::thread::sleep(std::time::Duration::from_secs(1));
}

#[tracing::instrument(name = "Trying to sign with the legacy keychain ...", skip_all)]
fn from_legacy_keychain(
    previous_context: crate::commands::ThresholdAccountContext,
    scope:  &<SignKeychain as interactive_clap::ToInteractiveClapContextScope>::InteractiveClapContextScope,
) -> color_eyre::eyre::Result<SignKeychainContext> {
    let legacy_scope =
        super::sign_with_legacy_keychain::InteractiveClapContextScopeForSignLegacyKeychain {
            signer_public_key: scope.signer_public_key.clone(),
            //nonce: scope.nonce,
            //block_hash: scope.block_hash,
            //block_height: scope.block_height,
            //meta_transaction_valid_for: scope.meta_transaction_valid_for,
        };

    Ok(
        super::sign_with_legacy_keychain::SignLegacyKeychainContext::from_previous_context(
            previous_context,
            &legacy_scope,
        )?
        .into(),
    )
}

/*impl From<SignKeychainContext> for super::SubmitContext {
    fn from(item: SignKeychainContext) -> Self {
        Self {
            network_config: item.network_config,
            global_context: item.global_context,
            signed_transaction_or_signed_delegate_action: item
                .signed_transaction_or_signed_delegate_action,
            on_before_sending_transaction_callback: item.on_before_sending_transaction_callback,
            on_after_sending_transaction_callback: item.on_after_sending_transaction_callback,
        }
    }
}*/

impl SignKeychain {
    fn input_signer_public_key(
        context: &crate::commands::ThresholdAccountContext,
    ) -> color_eyre::eyre::Result<Option<crate::types::public_key::PublicKey>> {
        if context.global_context.offline {
            return Ok(Some(
                CustomType::<crate::types::public_key::PublicKey>::new("Enter public_key:")
                    .prompt()?,
            ));
        }
        Ok(None)
    }

    fn input_nonce(
        context: &crate::commands::ThresholdAccountContext,
    ) -> color_eyre::eyre::Result<Option<u64>> {
        if context.global_context.offline {
            return Ok(Some(
                CustomType::<u64>::new("Enter a nonce for the access key:").prompt()?,
            ));
        }
        Ok(None)
    }

    fn input_block_hash(
        context: &crate::commands::ThresholdAccountContext,
    ) -> color_eyre::eyre::Result<Option<crate::types::crypto_hash::CryptoHash>> {
        if context.global_context.offline {
            return Ok(Some(
                CustomType::<crate::types::crypto_hash::CryptoHash>::new(
                    "Enter recent block hash:",
                )
                .prompt()?,
            ));
        }
        Ok(None)
    }

    fn input_block_height(
        context: &crate::commands::ThresholdAccountContext,
    ) -> color_eyre::eyre::Result<Option<near_primitives::types::BlockHeight>> {
        if context.global_context.offline {
            return Ok(Some(
                CustomType::<near_primitives::types::BlockHeight>::new(
                    "Enter recent block height:",
                )
                .prompt()?,
            ));
        }
        Ok(None)
    }
}
