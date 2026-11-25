//! Test helper for passer-exec:
//! - `echo`: copies stdin to stdout until stdin closes;
//! - `args ...`: prints its arguments, one per line, and exits;
//! - `tick <file>`: appends a byte to that file every 20 ms, forever.

use std::io::{Read, Write};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("echo") => {
            let mut buf = [0u8; 8192];
            let (mut input, mut output) = (std::io::stdin(), std::io::stdout());
            while let Ok(n) = input.read(&mut buf) {
                if n == 0 || output.write_all(&buf[..n]).is_err() {
                    break;
                }
                let _ = output.flush();
            }
        }
        Some("args") => {
            for a in &args[1..] {
                println!("{a}");
            }
        }
        // Ignores its input and writes forever, like a command that misses the end.
        Some("stubborn") => loop {
            if std::io::stdout().write_all(&[0u8; 4096]).is_err() {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        },
        Some("tick") => loop {
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&args[1])
            {
                let _ = f.write_all(b".");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        },
        _ => std::process::exit(2),
    }
}
