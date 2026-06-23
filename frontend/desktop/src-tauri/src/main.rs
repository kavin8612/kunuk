// Punto di ingresso del binario desktop: nasconde la console su Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    kunuk_desktop_lib::run();
}
