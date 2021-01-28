mod cli;

fn main() {
    if let Err(e) = cli::run() {
        let _ = e;
        //
    }
}
