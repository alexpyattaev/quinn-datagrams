use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use bytes::Bytes;
use clap::{Parser, ValueEnum};
use datagram_bench::{
    BoxError, DEFAULT_CONNECT_CONCURRENCY, DEFAULT_DATAGRAM_BUFFER_BYTES,
    DEFAULT_IDLE_TIMEOUT_SECS, DEFAULT_PAYLOAD_BYTES, SERVER_NAME, TransportOptions,
    format_bitrate, insecure_client_config, parse_byte_size, transport_config,
};
use quinn::{Connection, Endpoint};
use tokio::time::{Duration, Instant, MissedTickBehavior};

#[global_allocator]
static GLOBAL_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:4433")]
    server: SocketAddr,
    #[arg(long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,
    #[arg(long, default_value_t = 0)]
    connections: usize,
    #[arg(long, default_value_t = DEFAULT_CONNECT_CONCURRENCY)]
    connect_concurrency: usize,
    #[arg(long, default_value_t = DEFAULT_PAYLOAD_BYTES)]
    payload_bytes: usize,
    #[arg(long, value_enum, default_value_t = SendMode::Wait)]
    send_mode: SendMode,
    #[arg(long, default_value_t = DEFAULT_DATAGRAM_BUFFER_BYTES, value_parser = parse_byte_size)]
    datagram_receive_buffer: usize,
    #[arg(long, default_value_t = DEFAULT_DATAGRAM_BUFFER_BYTES, value_parser = parse_byte_size)]
    datagram_send_buffer: usize,
    #[arg(long, default_value_t = DEFAULT_IDLE_TIMEOUT_SECS)]
    idle_timeout_secs: u64,
    #[arg(long)]
    duration_secs: Option<u64>,
    #[arg(long, default_value_t = 0)]
    pps: u64,
    #[arg(long, default_value_t = false)]
    no_cc: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SendMode {
    Wait,
    Drop,
    Idle,
}

#[derive(Default)]
struct Metrics {
    open_connections: AtomicUsize,
    connect_attempts: AtomicU64,
    connected: AtomicU64,
    connect_errors: AtomicU64,
    closed: AtomicU64,
    datagrams_sent: AtomicU64,
    datagram_bytes_sent: AtomicU64,
    send_errors: AtomicU64,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    if args.connect_concurrency == 0 {
        return Err("connect_concurrency must be greater than zero".into());
    }
    if args.payload_bytes == 0 {
        return Err("payload_bytes must be greater than zero".into());
    }

    let transport = transport_config(TransportOptions {
        datagram_receive_buffer: args.datagram_receive_buffer,
        datagram_send_buffer: args.datagram_send_buffer,
        idle_timeout: Some(Duration::from_secs(args.idle_timeout_secs)),
        no_congestion_control: args.no_cc,
    })?;
    let client_config = insecure_client_config(transport)?;
    let endpoint = Endpoint::client(args.bind)?;
    endpoint.set_default_client_config(client_config);

    println!(
        "local={} server={} target_connections={} connect_concurrency={} payload_bytes={} send_mode={:?}",
        endpoint.local_addr()?,
        args.server,
        target_label(args.connections),
        args.connect_concurrency,
        args.payload_bytes,
        args.send_mode
    );

    let metrics = Arc::new(Metrics::default());
    let shutdown = Arc::new(AtomicBool::new(false));
    let limiter = Arc::new(ConnectionLimiter::new(args.connections));
    let payload = Bytes::from(vec![0u8; args.payload_bytes]);
    let connect_context = ConnectContext {
        endpoint: endpoint.clone(),
        server: args.server,
        limiter,
        payload,
        send_mode: args.send_mode,
        metrics: metrics.clone(),
        shutdown: shutdown.clone(),
        pps: args.pps,
    };

    tokio::spawn(report_metrics(metrics.clone()));
    for _ in 0..args.connect_concurrency {
        tokio::spawn(open_connections(connect_context.clone()));
    }

    match args.duration_secs {
        Some(duration_secs) => tokio::time::sleep(Duration::from_secs(duration_secs)).await,
        None => tokio::signal::ctrl_c().await?,
    }

    shutdown.store(true, Ordering::Relaxed);
    endpoint.close(0u32.into(), b"shutdown");
    endpoint.wait_idle().await;
    Ok(())
}

#[derive(Clone)]
struct ConnectContext {
    endpoint: Endpoint,
    server: SocketAddr,
    limiter: Arc<ConnectionLimiter>,
    payload: Bytes,
    send_mode: SendMode,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
    pps: u64,
}

async fn open_connections(context: ConnectContext) {
    loop {
        if context.shutdown.load(Ordering::Relaxed) {
            return;
        }
        if !context.limiter.try_reserve() {
            tokio::time::sleep(Duration::from_millis(1)).await;
            continue;
        }

        context
            .metrics
            .connect_attempts
            .fetch_add(1, Ordering::Relaxed);
        match context.endpoint.connect(context.server, SERVER_NAME) {
            Ok(connecting) => match connecting.await {
                Ok(connection) => {
                    context
                        .metrics
                        .open_connections
                        .fetch_add(1, Ordering::Relaxed);
                    context.metrics.connected.fetch_add(1, Ordering::Relaxed);
                    tokio::spawn(run_connection(
                        connection,
                        context.payload.clone(),
                        context.send_mode,
                        context.metrics.clone(),
                        context.shutdown.clone(),
                        context.limiter.clone(),
                        context.pps,
                    ));
                }
                Err(_error) => {
                    context.limiter.release();
                    context
                        .metrics
                        .connect_errors
                        .fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            },
            Err(_error) => {
                context.limiter.release();
                context
                    .metrics
                    .connect_errors
                    .fetch_add(1, Ordering::Relaxed);
                tokio::task::yield_now().await;
            }
        }
    }
}

struct ConnectionLimiter {
    target_connections: usize,
    active_connections: AtomicUsize,
}

impl ConnectionLimiter {
    fn new(target_connections: usize) -> Self {
        Self {
            target_connections,
            active_connections: AtomicUsize::new(0),
        }
    }

    fn try_reserve(&self) -> bool {
        if self.target_connections == 0 {
            self.active_connections.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        self.active_connections
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                (active < self.target_connections).then_some(active + 1)
            })
            .is_ok()
    }

    fn release(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn run_connection(
    connection: Connection,
    payload: Bytes,
    send_mode: SendMode,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
    limiter: Arc<ConnectionLimiter>,
    pps: u64,
) {
    if matches!(send_mode, SendMode::Idle) {
        keep_connection_open(&connection, shutdown).await;
        metrics.open_connections.fetch_sub(1, Ordering::Relaxed);
        metrics.closed.fetch_add(1, Ordering::Relaxed);
        limiter.release();
        return;
    }

    if !payload_fits(&connection, payload.len()).await {
        metrics.send_errors.fetch_add(1, Ordering::Relaxed);
        metrics.open_connections.fetch_sub(1, Ordering::Relaxed);
        metrics.closed.fetch_add(1, Ordering::Relaxed);
        limiter.release();
        return;
    }

    match send_mode {
        SendMode::Wait => {
            send_with_backpressure(&connection, payload, metrics.clone(), shutdown, pps).await
        }
        SendMode::Drop => {
            send_without_backpressure(&connection, payload, metrics.clone(), shutdown, pps).await
        }
        SendMode::Idle => unreachable!("idle mode returned before sending"),
    }

    metrics.open_connections.fetch_sub(1, Ordering::Relaxed);
    metrics.closed.fetch_add(1, Ordering::Relaxed);
    limiter.release();
}

async fn keep_connection_open(connection: &Connection, shutdown: Arc<AtomicBool>) {
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }

        tokio::select! {
            _ = connection.closed() => return,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

async fn payload_fits(connection: &Connection, payload_len: usize) -> bool {
    loop {
        match connection.max_datagram_size() {
            Some(max_datagram_size) => return payload_len <= max_datagram_size,
            None => {
                tokio::select! {
                    _ = connection.closed() => return false,
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                }
            }
        }
    }
}

async fn send_with_backpressure(
    connection: &Connection,
    payload: Bytes,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
    pps: u64,
) {
    let mut interval = (pps > 0).then(|| {
        let mut i = tokio::time::interval(Duration::from_nanos(1_000_000_000 / pps));
        i.set_missed_tick_behavior(MissedTickBehavior::Skip);
        i
    });
    while !shutdown.load(Ordering::Relaxed) {
        if let Some(ref mut interval) = interval {
            interval.tick().await;
        }
        let payload_len = payload.len();
        match connection.send_datagram_wait(payload.clone()).await {
            Ok(()) => {
                metrics.datagrams_sent.fetch_add(1, Ordering::Relaxed);
                metrics
                    .datagram_bytes_sent
                    .fetch_add(payload_len as u64, Ordering::Relaxed);
            }
            Err(_error) => {
                if shutdown.load(Ordering::Relaxed) {
                    return;
                }
                metrics.send_errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }
}

async fn send_without_backpressure(
    connection: &Connection,
    payload: Bytes,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
    pps: u64,
) {
    let mut interval = (pps > 0).then(|| {
        let mut i = tokio::time::interval(Duration::from_nanos(1_000_000_000 / pps));
        i.set_missed_tick_behavior(MissedTickBehavior::Skip);
        i
    });
    let mut since_yield = 0usize;
    while !shutdown.load(Ordering::Relaxed) {
        if let Some(ref mut interval) = interval {
            interval.tick().await;
        }
        let payload_len = payload.len();
        match connection.send_datagram(payload.clone()) {
            Ok(()) => {
                metrics.datagrams_sent.fetch_add(1, Ordering::Relaxed);
                metrics
                    .datagram_bytes_sent
                    .fetch_add(payload_len as u64, Ordering::Relaxed);
            }
            Err(_error) => {
                if shutdown.load(Ordering::Relaxed) {
                    return;
                }
                metrics.send_errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        if interval.is_none() {
            since_yield += 1;
            if since_yield == 1024 {
                since_yield = 0;
                tokio::task::yield_now().await;
            }
        }
    }
}

async fn report_metrics(metrics: Arc<Metrics>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    interval.tick().await;
    let mut last_tick = Instant::now();

    loop {
        interval.tick().await;
        let now = Instant::now();
        let elapsed = now.duration_since(last_tick);
        last_tick = now;

        let connect_attempts = metrics.connect_attempts.swap(0, Ordering::Relaxed);
        let connected = metrics.connected.swap(0, Ordering::Relaxed);
        let connect_errors = metrics.connect_errors.swap(0, Ordering::Relaxed);
        let closed = metrics.closed.swap(0, Ordering::Relaxed);
        let datagrams_sent = metrics.datagrams_sent.swap(0, Ordering::Relaxed);
        let datagram_bytes_sent = metrics.datagram_bytes_sent.swap(0, Ordering::Relaxed);
        let send_throughput = format_bitrate(datagram_bytes_sent, elapsed);
        let send_errors = metrics.send_errors.swap(0, Ordering::Relaxed);
        let open_connections = metrics.open_connections.load(Ordering::Relaxed);

        println!(
            "open_connections={open_connections} connect_attempts/s={connect_attempts} connected/s={connected} connect_errors/s={connect_errors} closed/s={closed} datagrams_sent/s={datagrams_sent} send_throughput={send_throughput} send_errors/s={send_errors}"
        );
    }
}

fn target_label(target_connections: usize) -> String {
    if target_connections == 0 {
        "unbounded".to_owned()
    } else {
        target_connections.to_string()
    }
}
