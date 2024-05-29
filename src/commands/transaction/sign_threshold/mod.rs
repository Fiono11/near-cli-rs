use inquire::CustomType;
use strum::{EnumDiscriminants, EnumIter, EnumMessage};

mod round1;
mod round2;

#[derive(Debug, Clone, interactive_clap::InteractiveClap)]
#[interactive_clap(context = crate::GlobalContext)]
pub struct ImplicitThresholdAccount {
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
    Round1(self::round1::Round1),
    /*#[strum_discriminants(strum(
        message = "round2  - Round2 of the creation of an implicit threshold account"
    ))]
    /// Use auto-generation to create an implicit account
    Round2(self::round2::Round2),*/
}
