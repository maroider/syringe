//! Based on http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html
//! and https://github.com/fdiskyou/injectAllTheThings.

use std::env;

mod lib;

use lib::inject_dll;

#[cfg(not(windows))]
compile_error!("This crate is currently only compatible with Windows");

fn main() {
    let pid = env::args()
        .nth(1)
        .expect("Expected PID as argument")
        .parse()
        .expect("PID must be a valid positive numer");

    let payload = env::args_os().nth(2).expect("Expected a payload to inject");

    inject_dll(pid, payload.as_ref()).unwrap();
}
