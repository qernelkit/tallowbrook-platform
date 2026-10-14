//! ledgerd: loads the settings, builds the listeners and operator rooms, and runs the posting
//! loop. In production the platform's socket relay is the transport; `ledgerd --stdio` reads
//! posting requests as JSON lines on stdin, which is how the integration environment drives it.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use ledger::api::{IdempotencyCache, Outcome};
use ledger::approvals::{ApprovalStep, needs_approval};
use ledger::journal::posting::{self, Chart, largest_line};
use ledger::journal::signing::BatchSigner;
use ledger::messaging::alerts_room::{AlertsRoom, Severity};
use ledger::messaging::operator_room::{ApprovalNotice, OperatorRoom};
use ledger::model::{AccountId, BatchSource, Period, Posting};
use ledger::settings::Settings;
use ledger::storage::{BatchStore, FileBatchStore};
use ledger::{Destination, LedgerError, Transport, TransportError, tls};

#[derive(serde::Deserialize)]
struct PostingRequest {
    client: String,
    period: Period,
    source: BatchSource,
    postings: Vec<Posting>,
}

/// Development transport: requests on stdin, responses on stdout.
struct Stdio {
    next_id: u64,
}

impl Transport for Stdio {
    fn receive(&mut self) -> Result<Option<(u64, Vec<u8>)>, TransportError> {
        let mut line = String::new();
        if io::stdin().lock().read_line(&mut line)? == 0 {
            return Ok(None);
        }
        self.next_id += 1;
        Ok(Some((self.next_id, line.into_bytes())))
    }

    fn send(&mut self, to: Destination, bytes: Vec<u8>) -> Result<(), TransportError> {
        let mut out = io::stdout().lock();
        writeln!(out, "{to:?}\t{}", String::from_utf8_lossy(&bytes))?;
        Ok(())
    }
}

/// Minimal stderr logger; production ships logs through the platform's journald relay.
struct StderrLog;

impl log::Log for StderrLog {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!(
                "{:<5} {}: {}",
                record.level(),
                record.target(),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn run(config: PathBuf) -> Result<(), LedgerError> {
    let settings = Settings::load(&config)?;
    let _listener = tls::server::ledger_listener(&settings.tls)?;
    let _admin = tls::admin_listener::admin_listener(&settings.tls)?;
    let signer = BatchSigner::load(&settings.ledger.journal_signing_key)?;
    let mut store = FileBatchStore::open(&settings.ledger.data_dir)?;
    let mut operators = OperatorRoom::create(&settings.messaging.bot_identity)?;
    let mut alerts = AlertsRoom::create(&settings.messaging.bot_identity)?;
    let mut chart = Chart::new();
    for number in [1020, 1030, 1040, 1200, 2100, 4000, 5100, 6200] {
        chart.open(AccountId(number));
    }
    let mut seen = IdempotencyCache::default();
    let mut transport = Stdio { next_id: 0 };
    let mut next_batch = now() << 16;

    while let Some((client_id, raw)) = transport.receive()? {
        let request: PostingRequest = serde_json::from_slice(&raw)?;
        if let Outcome::Repeat { batch_id } = seen.check(&request.client, &request.postings, now())
        {
            let reply = serde_json::json!({ "batch": batch_id, "repeat": true });
            transport.send(
                Destination::Client(client_id),
                reply.to_string().into_bytes(),
            )?;
            continue;
        }
        next_batch += 1;
        let batch = posting::batch_from_postings(
            next_batch,
            request.period,
            request.source,
            now(),
            &request.postings,
        )?;
        posting::validate(&batch, &chart)?;
        if needs_approval(&batch, settings.ledger.approval_threshold_minor) {
            let currency = batch
                .currencies()
                .first()
                .map(|c| c.to_string())
                .unwrap_or_default();
            let notice = ApprovalNotice {
                batch_id: batch.id,
                step: ApprovalStep::Proposed,
                largest_line_minor: largest_line(&batch),
                currency: &currency,
                summary: "held for treasury approval",
            };
            let out = operators.post_notice(&notice)?;
            if let Some(bytes) = out.application {
                transport.send(
                    Destination::Room(settings.messaging.operator_room.clone()),
                    bytes,
                )?;
            }
        } else {
            store.append(&batch)?;
            let signature = signer.sign(&batch);
            let reply = serde_json::to_vec(&signature)?;
            transport.send(Destination::Client(client_id), reply)?;
        }
        seen.record(&request.client, &request.postings, batch.id, now());
    }
    if let Some(bytes) = alerts.post(Severity::Info, "ledgerd", "posting loop stopped", now())? {
        transport.send(
            Destination::Room(settings.messaging.alerts_room.clone()),
            bytes,
        )?;
    }
    Ok(())
}

fn main() -> ExitCode {
    static LOGGER: StderrLog = StderrLog;
    let _ = log::set_logger(&LOGGER).map(|()| log::set_max_level(log::LevelFilter::Info));
    let config = std::env::args()
        .skip(1)
        .find(|a| !a.starts_with("--"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/tallowbrook/ledger/ledger.toml"));
    match run(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("ledgerd stopped: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}
