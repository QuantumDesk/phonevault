//! Menu-bar item: the padlock, the balance on the selected network, Open, Copy receive address,
//! Quit. Closing the window keeps the app (and the watcher's notifications) running here.

use crate::{eth, pairing, price, verify, watcher};
use std::sync::OnceLock;
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, Wry};

struct Items { balance: MenuItem<Wry>, btc: MenuItem<Wry>, address: MenuItem<Wry> }
static ITEMS: OnceLock<Items> = OnceLock::new();

/// Menu-bar padlock: the brand's pixel padlock redrawn at 14×16 for the menu bar — stepped round
/// shackle, rounded body, cut-out keyhole — drawn 2 device pixels per art pixel on a 36×36 canvas
/// (18 pt at Retina, the menu-bar icon size), so edges stay crisp. A macOS template image: alpha
/// only, tinted by the system for light/dark menu bars and the highlighted state.
fn padlock_icon() -> Image<'static> {
    const ROWS: [&str; 16] = [
        "....######....",
        "...########...",
        "..###....###..",
        "..##......##..",
        "..##......##..",
        "..##......##..",
        ".############.",
        "##############",
        "##############",
        "#####....#####",
        "#####....#####",
        "######..######",
        "######..######",
        "##############",
        "##############",
        ".############.",
    ];
    const S: usize = 2; // device pixels per art pixel
    const W: usize = 36;
    let (ox, oy) = ((W - 14 * S) / 2, (W - 16 * S) / 2);
    let mut rgba = vec![0u8; W * W * 4];
    for (y, row) in ROWS.iter().enumerate() {
        for (x, c) in row.bytes().enumerate() {
            if c != b'#' { continue; }
            for dy in 0..S { for dx in 0..S {
                let i = ((oy + y * S + dy) * W + ox + x * S + dx) * 4;
                rgba[i + 3] = 255; // black, opaque: template images use alpha only
            } }
        }
    }
    Image::new_owned(rgba, W as u32, W as u32)
}

pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn copy_address(app: &AppHandle) {
    use tauri_plugin_notification::NotificationExt;
    let Ok(Some(addr)) = pairing::load() else { show_main(app); return };
    let addr = verify::checksum(&addr);
    let ok = std::process::Command::new("/usr/bin/pbcopy").stdin(std::process::Stdio::piped()).spawn()
        .and_then(|mut c| { use std::io::Write; c.stdin.take().map(|mut s| s.write_all(addr.as_bytes())).transpose()?; c.wait() })
        .map(|s| s.success()).unwrap_or(false);
    let body = if ok { format!("Receive address copied: {addr}. Compare it with your phone before sharing it for a large amount.") } else { "Couldn't copy the address. Open Phone Vault → Receive.".into() };
    let _ = app.notification().builder().title("Phone Vault").body(body).show();
}

pub fn setup(app: &AppHandle) -> tauri::Result<()> {
    let balance = MenuItem::with_id(app, "balance", "Balance: …", false, None::<&str>)?;
    let btc = MenuItem::with_id(app, "btc", "Bitcoin: not set up", false, None::<&str>)?;
    let address = MenuItem::with_id(app, "address", "Not paired", false, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Open Phone Vault", true, None::<&str>)?;
    let copy = MenuItem::with_id(app, "copy", "Copy receive address", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Phone Vault", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&balance, &btc, &address, &PredefinedMenuItem::separator(app)?, &open, &copy, &PredefinedMenuItem::separator(app)?, &quit])?;
    TrayIconBuilder::with_id("main")
        .icon(padlock_icon())
        .icon_as_template(true)
        .tooltip("Phone Vault")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main(app),
            "copy" => copy_address(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    let _ = ITEMS.set(Items { balance, btc, address });
    if let Ok(Some(a)) = pairing::load() { set_address(app, &verify::checksum(&a)); }
    Ok(())
}

pub fn set_address(_app: &AppHandle, checksum: &str) {
    if let Some(i) = ITEMS.get() { let _ = i.address.set_text(format!("Account {}…{}", &checksum[..6], &checksum[checksum.len() - 4..])); }
}

pub fn set_unpaired(_app: &AppHandle) {
    if let Some(i) = ITEMS.get() { let _ = i.balance.set_text("Balance: not paired"); let _ = i.address.set_text("Not paired"); }
}

/// "0.0421 ETH on Base · $103.29" (USD only when the cached price is available).
pub fn set_balance(app: &AppHandle, chain: u64, wei: u128) {
    let Some(i) = ITEMS.get() else { return };
    let Some((_, name, symbol, ..)) = watcher::network(chain) else { return };
    let eth_text = eth::format_eth(wei);
    let shown = match eth_text.split_once('.') { Some((w, f)) if f.len() > 5 => format!("{w}.{}", &f[..5]), _ => eth_text.clone() };
    let usd = if chain == 11155111 { None } else { price::spot(symbol).ok().map(|p| eth_text.parse::<f64>().unwrap_or(0.0) * p) };
    let text = match usd { Some(u) => format!("{shown} {symbol} on {name} · ${u:.2}"), None => format!("{shown} {symbol} on {name}") };
    let _ = i.balance.set_text(&text);
    if let Some(t) = app.tray_by_id("main") { let _ = t.set_tooltip(Some(format!("Phone Vault · {text}"))); }
}

/// "Bitcoin: 0.01234 BTC · $812.40" across the paired Bitcoin (mainnet) accounts; None = none paired.
pub fn set_btc_balance(_app: &AppHandle, sats: Option<u64>) {
    let Some(i) = ITEMS.get() else { return };
    let text = match sats {
        None => "Bitcoin: not set up".to_string(),
        Some(s) => {
            let btc = crate::btc::tx::format_btc(s);
            match price::spot("BTC").ok() { Some(p) => format!("Bitcoin: {btc} BTC · ${:.2}", s as f64 / 1e8 * p), None => format!("Bitcoin: {btc} BTC") }
        }
    };
    let _ = i.btc.set_text(text);
}
