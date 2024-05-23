#[derive(Debug, Clone, interactive_clap::InteractiveClap)]
#[interactive_clap(input_context = crate::GlobalContext)]
#[interactive_clap(output_context = SimplpedpopRound1Context)]
pub struct SimplpedpopRound1 {
    #[interactive_clap(long)]
    /// The secret key of the contributor in the SimplPedPoP protocol
    secret_key: String,
    #[interactive_clap(long)]
    recipients: String,
    #[interactive_clap(long)]
    output: String,
}

#[derive(Debug, Clone)]
pub struct SimplpedpopRound1Context;

impl SimplpedpopRound1Context {
    pub fn from_previous_context(
        previous_context: crate::GlobalContext,
        scope: &<SimplpedpopRound1 as interactive_clap::ToInteractiveClapContextScope>::InteractiveClapContextScope,
    ) -> color_eyre::eyre::Result<Self> {
        /*let keypair =
            curve25519_dalek:: SigningKey::from(SecretKey::from_bytes(&scope.secret_key.as_bytes()).unwrap());

        let recipients_string =
            fs::read_to_string(Path::new(&recipients).join("recipients.json")).unwrap();
        let recipients_bytes: Vec<Vec<u8>> = from_str(&recipients_string).unwrap();

        let recipients: Vec<PublicKey> = recipients_bytes
            .iter()
            .map(|recipient| PublicKey::from_bytes(recipient).unwrap())
            .collect();

            let all_message: AllMessage = keypair.simplpedpop_contribute_all(2, recipients).unwrap();*/
        Ok(Self)
    }
}
