use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = PathBuf::from(out_dir).join("prefixes.rs");

    let content = fs::read_to_string("res/prefixes.txt").expect("Failed to read prefixes.txt");

    let array_content = content
        .lines()
        .map(|line| format!("\"{}\"", line))
        .collect::<Vec<String>>()
        .join(",\n");

    let generated_code = format!(
        "pub static PREFIXES: [&str; {}] = [{}];",
        content.lines().count(),
        array_content
    );

    fs::write(dest_path, generated_code).expect("Failed to write prefixes.rs");
}
