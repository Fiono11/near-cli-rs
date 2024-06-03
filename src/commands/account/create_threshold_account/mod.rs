#![allow(clippy::enum_variant_names, clippy::large_enum_variant)]
use inquire::CustomType;
use strum::{EnumDiscriminants, EnumIter, EnumMessage};

//mod create_implicit_account;
//mod fund_myself_create_account;
pub mod round1;
pub mod round2;
//pub mod sponsor_by_faucet_service;

#[derive(Debug, Clone, interactive_clap::InteractiveClap)]
#[interactive_clap(context = crate::GlobalContext)]
pub struct CreateThresholdAccount {
    #[interactive_clap(subcommand)]
    mode: Mode,
}

#[derive(Debug, Clone, EnumDiscriminants, interactive_clap_derive::InteractiveClap)]
#[interactive_clap(context = crate::GlobalContext)]
#[strum_discriminants(derive(EnumMessage, EnumIter))]
/// Choose a mode to create an implicit account:
pub enum Mode {
    #[strum_discriminants(strum(
        message = "round1  - Round1 of the creation of an implicit threshold account"
    ))]
    /// Use auto-generation to create an implicit account
    Round1(round1::Round1),
    #[strum_discriminants(strum(
        message = "round2  - Round2 of the creation of an implicit threshold account"
    ))]
    /// Use auto-generation to create an implicit account
    Round2(round2::Round2),
}

#[derive(Debug, Clone, interactive_clap::InteractiveClap)]
#[interactive_clap(input_context = SaveImplicitAccountContext)]
#[interactive_clap(output_context = SaveToFolderContext)]
pub struct SaveToFolder {
    #[interactive_clap(skip_default_input_arg)]
    /// Where to save the implicit account file?
    folder_path: crate::types::path_buf::PathBuf,
}

#[derive(Clone)]
struct SaveToFolderContext;

impl SaveToFolderContext {
    pub fn from_previous_context(
        previous_context: SaveImplicitAccountContext,
        scope: &<SaveToFolder as interactive_clap::ToInteractiveClapContextScope>::InteractiveClapContextScope,
    ) -> color_eyre::eyre::Result<Self> {
        (previous_context.on_after_getting_folder_path_callback)(
            &scope.folder_path.clone().into(),
        )?;
        Ok(Self)
    }
}

impl SaveToFolder {
    fn input_folder_path(
        context: &SaveImplicitAccountContext,
    ) -> color_eyre::eyre::Result<Option<crate::types::path_buf::PathBuf>> {
        eprintln!();
        Ok(Some(
            CustomType::new("Where to save the implicit threshold account file?")
                .with_starting_input(&format!(
                    "{}/implicit_threshold_account",
                    context.config.credentials_home_dir.to_string_lossy()
                ))
                .prompt()?,
        ))
    }
}

pub type OnAfterGettingFolderPathCallback =
    std::sync::Arc<dyn Fn(&std::path::PathBuf) -> crate::CliResult>;

#[derive(Clone)]
pub struct SaveImplicitAccountContext {
    config: crate::config::Config,
    on_after_getting_folder_path_callback: OnAfterGettingFolderPathCallback,
}
