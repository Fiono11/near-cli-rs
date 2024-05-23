use strum::{EnumDiscriminants, EnumIter, EnumMessage};

mod simplpedpop_round1;

#[derive(Debug, Clone, interactive_clap::InteractiveClap)]
#[interactive_clap(context = crate::GlobalContext)]
pub struct OlafCommands {
    #[interactive_clap(subcommand)]
    config_actions: OlafActions,
}

#[derive(Debug, EnumDiscriminants, Clone, interactive_clap::InteractiveClap)]
#[interactive_clap(context = crate::GlobalContext)]
#[strum_discriminants(derive(EnumMessage, EnumIter))]
#[non_exhaustive]
/// What do you want to do with a near CLI config?
pub enum OlafActions {
    #[strum_discriminants(strum(
        message = "simplpedpop-round1         - First round of the SimplPedPoP protocol"
    ))]
    /// First round of the SimplPedPoP protocol
    SimplpedpopRound1(self::simplpedpop_round1::SimplpedpopRound1),
}
