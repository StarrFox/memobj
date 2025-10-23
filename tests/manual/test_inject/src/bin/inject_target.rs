fn main() {
    // This process just waits, so it can be injected into.
    std::thread::sleep(std::time::Duration::from_secs(60 * 5));
}