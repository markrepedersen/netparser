use emacs::{defun, Env, Result, Value};
use netparse::{run, PacketOptions};

emacs::plugin_is_GPL_compatible!();

#[emacs::module(name = "emacs_netparser", defun_prefix = "netparser", separator = "/")]
fn init(_: &Env) -> Result<()> {
    Ok(())
}

#[defun]
fn run_netparser(env: &Env, interface: String) -> Result<()> {
    let opts = PacketOptions {
        interface: String::from(interface),
        ..Default::default()
    };
    run(&opts).unwrap();
    Ok(())
}
