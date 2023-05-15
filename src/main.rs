#![forbid(unsafe_code)]

use age_plugin::run_state_machine;
use gumdrop::Options;

mod error;
mod format;
mod hid;
mod k256;
mod key;
mod plugin;

use error::Error;

const PLUGIN_NAME: &str = "ledger";
const RECIPIENT_PREFIX: &str = "age1ledger";
const IDENTITY_PREFIX: &str = "age-plugin-ledger-";
const STANZA_TAG: &str = "ledger-k256";

#[macro_export]
macro_rules! fl {
    ($message_id:literal) => {{
        i18n_embed_fl::fl!($crate::LANGUAGE_LOADER, $message_id)
    }};
    ($message_id:literal, $($kwarg:expr),* $(,)*) => {{
        i18n_embed_fl::fl!($crate::LANGUAGE_LOADER, $message_id, $($kwarg,)*)
    }};
}

#[derive(Debug, Options)]
struct PluginOptions {
    #[options(help = "Print this help message and exit.")]
    help: bool,

    #[options(help = "Print version info and exit.", short = "V")]
    version: bool,

    #[options(
        help = "Run the given age plugin state machine. Internal use only.",
        meta = "STATE-MACHINE",
        no_short
    )]
    age_plugin: Option<String>,

    #[options(help = "Print identities stored in connected Ledger Nano.")]
    identity: bool,

    #[options(help = "List recipients for age identities in connected Ledger Nano.")]
    list: bool,
}

fn identity() -> Result<(), Error> {
    let device = crate::hid::LedgerHIDDevice::new();
    let recipient = key::get_device_recipient(&device)?;
    let stub = key::Stub::new(&recipient).to_string();
    let recipient = recipient.to_string();
    if !console::user_attended() {
        let recipient = recipient.as_str();
        eprintln!("Recipient: {recipient}");
    }
    println!("#    Recipient: {recipient}\n{stub}",);
    println!();
    Ok(())
}

fn list() -> Result<(), Error> {
    let device = crate::hid::LedgerHIDDevice::new();
    let recipient = key::get_device_recipient(&device)?;
    println!("{recipient}");
    println!();
    Ok(())
}

fn main() -> Result<(), Error> {
    let opts = PluginOptions::parse_args_default_or_exit();

    if [opts.identity, opts.list].iter().filter(|&&b| b).count() > 1 {
        return Err(Error::MultipleCommands);
    }

    if let Some(state_machine) = opts.age_plugin {
        run_state_machine(
            &state_machine,
            plugin::RecipientPlugin::default,
            plugin::IdentityPlugin::default,
        )?;
        Ok(())
    } else if opts.version {
        println!("age-plugin-ledger {}", env!("CARGO_PKG_VERSION"));
        Ok(())
    } else if opts.identity {
        identity()
    } else if opts.list {
        list()
    } else {
        return Err(Error::MultipleCommands);
    }
}
