//! In-memory log capture for the TUI.
//!
//! Routes `log` crate records into a bounded ring buffer instead of the console
//! so the TUI can render them in a scrollable pane.
//!
//! The buffer captures at a verbose threshold (`duopipe` at `Info`+, other targets at
//! `Warn`+) and tags each line's `verbose_only` flag. The default ("concise") log view
//! hides `verbose_only` lines — the routine iroh/quinn `Warn` churn from relay
//! net-report / address-discovery probes — showing only our own `Info`+ and genuine
//! `Error`s from the stack below us. The TUI's verbose toggle reveals everything
//! captured; because the noisy lines are always buffered, toggling on doesn't lose
//! recent history.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;

use log::{Level, LevelFilter, Log, Metadata, Record};
use parking_lot::Mutex;

tokio::task_local! {
    /// The half of the interactive process a task belongs to ("serve" / "dial"), set
    /// by [`scoped`] and propagated to spawned children by [`inherit_source`]. The TUI
    /// logger prefixes each record with it so the single combined log is attributable.
    static LOG_SOURCE: &'static str;
}

/// Run `fut` tagged as originating from `source` (e.g. `"serve"` / `"dial"`). Every log
/// record emitted while it runs — and within any child future wrapped by
/// [`inherit_source`] — is prefixed with `[source]` in the TUI pane.
pub fn scoped<F: Future>(source: &'static str, fut: F) -> impl Future<Output = F::Output> {
    LOG_SOURCE.scope(source, fut)
}

/// Carry the current source tag into a future that is about to be `tokio::spawn`ed.
/// Task-locals are not inherited across spawns, so a spawned task would otherwise lose
/// the tag; call this on every spawned future that should stay attributed to its parent
/// half. A no-op when no source is set (single-role headless runs).
pub fn inherit_source<F: Future>(fut: F) -> impl Future<Output = F::Output> {
    let source = LOG_SOURCE.try_with(|s| *s).ok();
    async move {
        match source {
            Some(s) => LOG_SOURCE.scope(s, fut).await,
            None => fut.await,
        }
    }
}

/// A single captured log record.
#[derive(Clone)]
pub struct LogLine {
    pub level: Level,
    pub msg: String,
    pub ts: jiff::Zoned,
    /// True for records the concise (default) view hides and only the verbose view
    /// shows — i.e. the routine iroh/quinn `Warn` churn. The buffer always captures
    /// them so the verbose toggle can reveal them without missing recent history.
    pub verbose_only: bool,
}

/// Bounded ring buffer of log lines, shared between the logger and the TUI.
pub struct LogBuffer {
    lines: Mutex<VecDeque<LogLine>>,
    cap: usize,
}

impl LogBuffer {
    pub fn new(cap: usize) -> Arc<Self> {
        Arc::new(Self {
            lines: Mutex::new(VecDeque::with_capacity(cap.min(256))),
            cap,
        })
    }

    pub fn push(&self, line: LogLine) {
        let mut lines = self.lines.lock();
        if lines.len() == self.cap {
            lines.pop_front();
        }
        lines.push_back(line);
    }

    /// Snapshot the buffer (oldest first) for rendering.
    pub fn snapshot(&self) -> Vec<LogLine> {
        self.lines.lock().iter().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.lines.lock().len()
    }
}

/// `log::Log` implementation that appends records to a [`LogBuffer`].
struct TuiLogger {
    buffer: Arc<LogBuffer>,
}

impl TuiLogger {
    fn is_own(target: &str) -> bool {
        target == "duopipe" || target.starts_with("duopipe::")
    }

    /// Concise (default) policy: our own records at `Info`+, everything else (iroh/quinn
    /// internals) only at `Error`. Hides the routine `Warn` churn from iroh's relay
    /// net-report / address-discovery probes.
    fn concise_allowed(target: &str, level: Level) -> bool {
        if Self::is_own(target) {
            level <= Level::Info
        } else {
            level <= Level::Error
        }
    }

    /// Verbose policy (and the capture threshold): same for our own target, but admits
    /// non-`duopipe` `Warn` as well. The buffer always captures at this level; the
    /// extra lines are flagged `verbose_only` and shown only when verbose is toggled on.
    fn verbose_allowed(target: &str, level: Level) -> bool {
        if Self::is_own(target) {
            level <= Level::Info
        } else {
            level <= Level::Warn
        }
    }
}

impl Log for TuiLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        // Capture at the verbose threshold; the concise view filters further at render.
        Self::verbose_allowed(metadata.target(), metadata.level())
    }

    fn log(&self, record: &Record) {
        let target = record.metadata().target();
        let level = record.level();
        if !Self::verbose_allowed(target, level) {
            return;
        }
        // Prefix with the emitting half ("serve"/"dial") when one is set, so the single
        // combined buffer stays attributable; unscoped records pass through untagged.
        let msg = match LOG_SOURCE.try_with(|s| *s) {
            Ok(source) => format!("[{source}] {}", record.args()),
            Err(_) => record.args().to_string(),
        };
        self.buffer.push(LogLine {
            level,
            msg,
            ts: jiff::Zoned::now(),
            verbose_only: !Self::concise_allowed(target, level),
        });
    }

    fn flush(&self) {}
}

/// Install the TUI logger and return the shared buffer it writes to.
///
/// Must be called at most once per process (the `peer` command path). Returns an
/// error if a global logger was already set.
pub fn init_tui_logger(cap: usize) -> Result<Arc<LogBuffer>, log::SetLoggerError> {
    let buffer = LogBuffer::new(cap);
    let logger = TuiLogger {
        buffer: buffer.clone(),
    };
    log::set_boxed_logger(Box::new(logger))?;
    // Keep the macros from filtering at `Info`; per-record policy lives in `log()`.
    log::set_max_level(LevelFilter::Info);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(level: Level, msg: &str) -> LogLine {
        LogLine {
            level,
            msg: msg.to_string(),
            ts: jiff::Zoned::now(),
            verbose_only: false,
        }
    }

    #[test]
    fn ring_buffer_evicts_oldest_at_cap() {
        let buf = LogBuffer::new(3);
        for i in 0..5 {
            buf.push(line(Level::Info, &format!("msg{i}")));
        }
        let snap = buf.snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].msg, "msg2");
        assert_eq!(snap[2].msg, "msg4");
    }

    #[test]
    fn concise_filter_hides_iroh_warn_churn() {
        // Our own target: Info and above shown in the default view.
        assert!(TuiLogger::concise_allowed("duopipe", Level::Info));
        assert!(TuiLogger::concise_allowed("duopipe::iroh_mode", Level::Warn));
        assert!(!TuiLogger::concise_allowed("duopipe", Level::Debug));
        // Other targets: only Error — iroh/quinn Warn churn is hidden by default.
        assert!(!TuiLogger::concise_allowed("iroh", Level::Info));
        assert!(!TuiLogger::concise_allowed("iroh", Level::Warn));
        assert!(!TuiLogger::concise_allowed("iroh_relay", Level::Warn));
        assert!(TuiLogger::concise_allowed("quinn", Level::Error));
    }

    #[test]
    fn verbose_filter_admits_foreign_warn_but_still_drops_info() {
        // The capture/verbose threshold reveals non-duopipe Warn (the churn) and Error.
        assert!(TuiLogger::verbose_allowed("iroh", Level::Warn));
        assert!(TuiLogger::verbose_allowed("quinn", Level::Error));
        // But still not their Info/Debug — those never reach the buffer at all.
        assert!(!TuiLogger::verbose_allowed("iroh", Level::Info));
        assert!(!TuiLogger::verbose_allowed("iroh", Level::Debug));
        // Foreign Warn is captured but flagged verbose-only; our own lines never are.
        assert!(!TuiLogger::concise_allowed("iroh", Level::Warn));
        assert!(TuiLogger::concise_allowed("duopipe", Level::Info));
    }

    #[tokio::test]
    async fn source_tag_propagates_into_spawned_children() {
        // The tag is readable within the scope itself.
        let direct = scoped("serve", async { LOG_SOURCE.try_with(|s| *s).ok() }).await;
        assert_eq!(direct, Some("serve"));

        // inherit_source carries the tag across a tokio::spawn boundary.
        let wrapped = scoped("dial", async {
            tokio::spawn(inherit_source(async { LOG_SOURCE.try_with(|s| *s).ok() }))
                .await
                .unwrap()
        })
        .await;
        assert_eq!(wrapped, Some("dial"));

        // Without the wrapper, a spawned child does not inherit it (task-locals don't
        // cross spawns) — which is exactly why every spawn site is wrapped.
        let bare = scoped("dial", async {
            tokio::spawn(async { LOG_SOURCE.try_with(|s| *s).ok() })
                .await
                .unwrap()
        })
        .await;
        assert_eq!(bare, None);
    }
}
