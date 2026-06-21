use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn main() {
    println!("cargo:rerun-if-changed=static");

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let static_dir = manifest_dir.join("static");
    let mut files = Vec::new();
    collect_assets(&static_dir, &static_dir, &mut files);
    files.sort_by(|left, right| left.0.cmp(&right.0));

    let mut generated =
        String::from("pub fn get(path: &str) -> Option<&'static [u8]> {\n    match path {\n");
    for (relative, absolute) in files {
        generated.push_str(&format!(
            "        {relative:?} => Some(include_bytes!({absolute:?})),\n",
            absolute = absolute.to_string_lossy(),
        ));
    }
    generated.push_str("        _ => None,\n    }\n}\n");

    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("embedded_assets.rs");
    fs::write(output, generated).expect("write embedded asset index");
}

fn collect_assets(root: &Path, directory: &Path, output: &mut Vec<(String, PathBuf)>) {
    for entry in fs::read_dir(directory).expect("read static asset directory") {
        let entry = entry.expect("read static asset entry");
        let path = entry.path();
        if path.is_dir() {
            // Templates are embedded by `src/html.rs` and must not be publicly served.
            if path != root.join("templates") {
                collect_assets(root, &path, output);
            }
        } else if path.is_file() {
            let relative = path
                .strip_prefix(root)
                .expect("asset is under static directory")
                .to_str()
                .expect("static asset paths must be UTF-8")
                .replace('\\', "/");
            output.push((relative, path));
        }
    }
}
