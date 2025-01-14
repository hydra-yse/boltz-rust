use std::io::{self, Write};

pub fn pause_and_wait(msg: &str) {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    writeln!(stdout).unwrap();
    write!(stdout, "******{msg}******").unwrap();
    writeln!(stdout).unwrap();
    write!(stdout, "Press Enter to continue...").unwrap();
    stdout.flush().unwrap();
    let _ = stdin.read_line(&mut String::new()).unwrap();
}
