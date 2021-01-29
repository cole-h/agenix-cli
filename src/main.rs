mod cli;

#[doc(hidden)]
fn main() {
    if let Err(e) = cli::run() {
        eprintln!("{:?}", e);
    }
}
