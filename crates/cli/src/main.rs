fn main() {
  if let Err(error) = codeoff_cli::run() {
    eprintln!("{error}");
    std::process::exit(1);
  }
}
