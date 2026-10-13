//! Every command the webview may call is listed here: tauri-build turns each into an
//! `allow-<command>` permission, and capabilities/default.json grants them (through the
//! `app-commands` set in permissions/app-commands.toml) to the main window only. A command missing
//! from this list cannot be invoked at all; a unit test (lib.rs) keeps it equal to generate_handler!.

pub const COMMANDS: &[&str] = &[
    "device_status", "read_address", "confirm_pairing", "forget_pairing", "select_account", "rename_account",
    "forget_account", "wallet", "quote", "receipt", "default_rpc", "sign_start", "sign_cancel", "simulate",
    "broadcast_verified", "fee_estimate", "max_sendable", "check_address", "history_list", "history_mark",
    "history_add_incoming", "history_reconcile", "spot_usd", "prices_usd", "replacement_quote",
    "watch_configure", "watch_scan_status", "nft_list", "nft_scan", "nft_add_contract", "nft_metadata",
    "dapp_icon", "sign_message", "sign_typed_data", "attest_phone", "attestation_cached", "developer_mode",
    "set_developer_mode", "token_list", "token_balances", "token_quote", "wc_plan_session",
    "wc_session_namespaces", "wc_add_chain", "wc_session_matches", "wc_prepare", "bridge_status",
    "bridge_pending", "bridge_respond", "bridge_approve_connect", "bridge_update_site", "bridge_revoke",
    "bridge_set_nodes", "bridge_install", "bridge_uninstall", "open_backup_card", "btc_accounts",
    "btc_read_account", "btc_show_address", "btc_confirm_account", "btc_select", "btc_rename", "btc_forget",
    "btc_set_server", "btc_wallet", "btc_refresh", "btc_check_address", "btc_fees", "btc_quote",
    "btc_bump_quote", "btc_sign_start", "btc_sign_cancel", "btc_broadcast", "btc_tx_status", "btc_export",
    "btc_save_export",
];

fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)))
        .expect("tauri-build failed");
}
