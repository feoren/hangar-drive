// The app registers no commands of its own yet. Once it does, they are listed here
// (`AppManifest::commands`), so Tauri generates one permission per command and the frontend may
// only call what capabilities/default.json grants.
fn main() {
    let attributes = tauri_build::Attributes::new();
    // A build script reports errors to Cargo by panicking; that is the intended interface.
    if let Err(error) = tauri_build::try_build(attributes) {
        panic!("Tauri build failed: {error:#}");
    }
}
