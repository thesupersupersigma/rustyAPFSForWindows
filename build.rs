fn main() {
    #[cfg(windows)]
    winfsp::build::winfsp_link_delayload();
    // The app reads physical disks, which needs administrator rights: embed a manifest so Windows
    // asks for them (UAC prompt) when it starts. The command-line tool stays unelevated.
    #[cfg(windows)]
    if std::env::var_os("CARGO_FEATURE_GUI").is_some() {
        println!("cargo:rustc-link-arg-bin=apfs-gui=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg-bin=apfs-gui=/MANIFESTUAC:level='requireAdministrator' uiAccess='false'");
    }
}
