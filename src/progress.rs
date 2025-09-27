use indicatif::{HumanDuration, ProgressBar, ProgressStyle};
use std::time::{Duration, Instant};

pub fn create_bar(prefix: &str, length: u64) -> ProgressBar {
    let bar = ProgressBar::new(length);
    bar.set_prefix(prefix.to_string());
    bar.set_style(
        ProgressStyle::with_template("{prefix:<18} [{bar:40.cyan/blue}] {percent:>3}% {msg}")
            .expect("valid progress template")
            .progress_chars("=- "),
    );
    bar.set_message(String::new());
    bar.set_position(0);
    bar.enable_steady_tick(Duration::from_millis(120));
    bar
}

pub fn complete_with_duration(pb: &ProgressBar, start: Instant) {
    if let Some(len) = pb.length() {
        pb.set_position(len);
    }
    pb.finish_with_message(format!("{}", HumanDuration(start.elapsed())));
}
