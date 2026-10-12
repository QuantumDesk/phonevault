// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Started by Chrome/Firefox as the native messaging host for the Phone Vault extension:
    // relay to the running app and exit (no window). See src/bridge.rs.
    let args: Vec<String> = std::env::args().collect();
    if let Some(caller) = companion_lib::bridge::native_host_caller(&args) {
        std::process::exit(companion_lib::bridge::native_host_main(caller));
    }
    companion_lib::run()
}
