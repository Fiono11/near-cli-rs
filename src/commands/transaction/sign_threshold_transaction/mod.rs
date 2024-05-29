use inquire::CustomType;
use strum::{EnumDiscriminants, EnumIter, EnumMessage};

mod round1;
//mod round2;

#[derive(Debug, Clone, interactive_clap::InteractiveClap)]
#[interactive_clap(context = crate::GlobalContext)]
pub struct ImplicitThresholdAccount {
    #[interactive_clap(subcommand)]
    round: SignThresholdTransactionRound,
}

#[derive(Debug, Clone, EnumDiscriminants, interactive_clap_derive::InteractiveClap)]
#[interactive_clap(input_context = crate::GlobalContext)]
#[interactive_clap(output_context = SignThresholdTransactionRoundContext)]
#[strum_discriminants(derive(EnumMessage, EnumIter))]
/// Choose a mode to create an implicit account:
pub enum SignThresholdTransactionRound {
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

#[derive(Clone)]
pub struct SignThresholdTransactionRoundContext(crate::GlobalContext);

impl SignThresholdTransactionRoundContext {
    pub fn from_previous_context(
        previous_context: crate::GlobalContext,
        scope: &<SignThresholdTransactionRound as interactive_clap::ToInteractiveClapContextScope>::InteractiveClapContextScope,
    ) -> color_eyre::eyre::Result<Self> {
        match scope {
            /*CoverCostsCreateThresholdAccountDiscriminants::SponsorByFaucetService => {
            if previous_context.offline {
                Err(color_eyre::Report::msg(
                    "Error: Creating an account with a faucet sponsor is not possible offline.",
                ))
            } else {
                Ok(Self(previous_context))
            }
            }*/
            _ => Ok(Self(previous_context)),
        }
    }
}

impl From<SignThresholdTransactionRoundContext> for crate::GlobalContext {
    fn from(item: SignThresholdTransactionRoundContext) -> Self {
        item.0
    }
}
