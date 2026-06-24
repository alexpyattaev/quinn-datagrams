use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use bytes::Bytes;
use clap::Parser;
use datagram_bench::{
    BoxError, CongestionControl, DEFAULT_DATAGRAM_BUFFER_BYTES, DEFAULT_IDLE_TIMEOUT_SECS,
    TransportOptions, format_bitrate, parse_byte_size, server_config, transport_config,
};
use quinn::{
    Connection, Endpoint, EndpointConfig, EndpointRuntimeConfig, Incoming, TokioRuntimeHandle,
};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::runtime::Builder;
use tokio::time::{Duration, Instant, MissedTickBehavior};

#[global_allocator]
static GLOBAL_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const DEFAULT_ENDPOINT_RUNTIME_THREADS: usize = 2;
const DEFAULT_CONNECTION_RUNTIME_THREADS: usize = 4;
const DATAGRAM_READ_BATCH_SIZE: usize = 64;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:4433")]
    bind: SocketAddrV4,
    #[arg(long, default_value = "10MB", value_parser = parse_byte_size)]
    socket_recv_buffer: usize,
    #[arg(long, default_value_t = DEFAULT_DATAGRAM_BUFFER_BYTES, value_parser = parse_byte_size)]
    datagram_receive_buffer: usize,
    #[arg(long, default_value_t = DEFAULT_DATAGRAM_BUFFER_BYTES, value_parser = parse_byte_size)]
    datagram_send_buffer: usize,
    #[arg(long, default_value_t = DEFAULT_IDLE_TIMEOUT_SECS)]
    idle_timeout_secs: u64,
    #[arg(long)]
    disable_congestion_control: bool,
    #[arg(long, default_value_t = 1)]
    accept_tasks: usize,
    /// Maximum number of concurrent in-flight handshakes. If unset, no limit is
    /// applied; if set, must be greater than zero.
    #[arg(long)]
    max_concurrent_handshakes: Option<usize>,
    #[arg(long, default_value_t = DEFAULT_ENDPOINT_RUNTIME_THREADS)]
    endpoint_runtime_threads: usize,
    #[arg(long, default_value_t = DEFAULT_CONNECTION_RUNTIME_THREADS)]
    connection_runtime_threads: usize,
}

#[derive(Default)]
struct Metrics {
    open_connections: AtomicUsize,
    accepted: AtomicU64,
    accept_errors: AtomicU64,
    datagrams: AtomicU64,
    datagram_bytes: AtomicU64,
}

fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    if args.endpoint_runtime_threads == 0 {
        return Err("endpoint_runtime_threads must be greater than zero".into());
    }
    if args.connection_runtime_threads == 0 {
        return Err("connection_runtime_threads must be greater than zero".into());
    }

    let endpoint_runtime = runtime(args.endpoint_runtime_threads, "dgram-endpt")?;
    let connection_runtime = runtime(args.connection_runtime_threads, "dgram-conn")?;
    let runtimes = EndpointRuntimeConfig::new(
        Arc::new(TokioRuntimeHandle::new(endpoint_runtime.handle().clone())),
        Arc::new(TokioRuntimeHandle::new(connection_runtime.handle().clone())),
    );

    connection_runtime.block_on(run_server(args, runtimes))
}

fn runtime(
    worker_threads: usize,
    thread_name_prefix: &'static str,
) -> std::io::Result<tokio::runtime::Runtime> {
    let next_thread = AtomicUsize::new(0);
    Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .thread_name_fn(move || {
            let thread_index = next_thread.fetch_add(1, Ordering::Relaxed);
            format!("{thread_name_prefix}-{thread_index}")
        })
        .enable_all()
        .build()
}

async fn run_server(args: Args, runtimes: EndpointRuntimeConfig) -> Result<(), BoxError> {
    if args.accept_tasks == 0 {
        return Err("accept_tasks must be greater than zero".into());
    }
    if args.socket_recv_buffer == 0 {
        return Err("socket_recv_buffer must be greater than zero".into());
    }
    if args.max_concurrent_handshakes == Some(0) {
        return Err("max_concurrent_handshakes must be greater than zero when set".into());
    }
    let handshake_semaphore = args
        .max_concurrent_handshakes
        .map(|permits| Arc::new(tokio::sync::Semaphore::new(permits)));

    let congestion_control = if args.disable_congestion_control {
        CongestionControl::Disabled
    } else {
        CongestionControl::Enabled
    };
    let transport = transport_config(TransportOptions {
        datagram_receive_buffer: args.datagram_receive_buffer,
        datagram_send_buffer: args.datagram_send_buffer,
        idle_timeout: Some(Duration::from_secs(args.idle_timeout_secs)),
        congestion_control,
    })?;
    let config = server_config(transport)?;
    let socket = server_socket(args.bind, args.socket_recv_buffer)?;
    let effective_recv_buffer = socket.recv_buffer_size()?;
    let endpoint = Endpoint::new_with_runtimes(
        EndpointConfig::default(),
        Some(config),
        socket.into(),
        runtimes,
    )?;
    let metrics = Arc::new(Metrics::default());

    println!(
        "listening={} accept_tasks={} max_concurrent_handshakes={} endpoint_runtime_threads={} connection_runtime_threads={} socket_recv_buffer_requested={} socket_recv_buffer_effective={} congestion_control={:?}",
        endpoint.local_addr()?,
        args.accept_tasks,
        args.max_concurrent_handshakes
            .map_or_else(|| "unlimited".to_string(), |n| n.to_string()),
        args.endpoint_runtime_threads,
        args.connection_runtime_threads,
        args.socket_recv_buffer,
        effective_recv_buffer,
        congestion_control
    );
    tokio::spawn(report_metrics(metrics.clone()));

    let mut accept_handles = Vec::with_capacity(args.accept_tasks);
    for _ in 0..args.accept_tasks {
        accept_handles.push(tokio::spawn(accept_loop(
            endpoint.clone(),
            metrics.clone(),
            handshake_semaphore.clone(),
        )));
    }

    tokio::signal::ctrl_c().await?;
    endpoint.close(0u32.into(), b"shutdown");
    for handle in accept_handles {
        let _ = handle.await;
    }

    endpoint.wait_idle().await;
    Ok(())
}

fn server_socket(bind: SocketAddrV4, recv_buffer_size: usize) -> std::io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_recv_buffer_size(recv_buffer_size)?;
    socket.bind(&SocketAddr::V4(bind).into())?;
    Ok(socket)
}

async fn accept_loop(
    endpoint: Endpoint,
    metrics: Arc<Metrics>,
    semaphore: Option<Arc<tokio::sync::Semaphore>>,
) {
    while let Some(incoming) = endpoint.accept().await {
        match &semaphore {
            // No limit configured: spawn unconditionally.
            None => {
                tokio::spawn(handle_incoming(incoming, metrics.clone(), None));
            }
            // Limit configured: only spawn if a permit is available.
            Some(semaphore) => match Arc::clone(semaphore).try_acquire_owned() {
                Ok(permit) => {
                    tokio::spawn(handle_incoming(incoming, metrics.clone(), Some(permit)));
                }
                Err(_) => {
                    incoming.ignore();
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            },
        }
    }
}

async fn handle_incoming(
    incoming: Incoming,
    metrics: Arc<Metrics>,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
) {
    match incoming.await {
        Ok(connection) => {
            metrics.open_connections.fetch_add(1, Ordering::Relaxed);
            drop(permit);
            metrics.accepted.fetch_add(1, Ordering::Relaxed);
            read_datagrams(connection, metrics.clone()).await;
            metrics.open_connections.fetch_sub(1, Ordering::Relaxed);
        }
        Err(_error) => {
            metrics.accept_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

async fn read_datagrams(connection: Connection, metrics: Arc<Metrics>) {
    let mut datagrams: [Bytes; DATAGRAM_READ_BATCH_SIZE] = std::array::from_fn(|_| Bytes::new());
    loop {
        match connection.read_datagrams(&mut datagrams).await {
            Ok(count) => {
                let mut datagram_bytes = 0;
                for datagram in &mut datagrams[..count] {
                    datagram_bytes += datagram.len() as u64;
                    *datagram = Bytes::new();
                }
                metrics.datagrams.fetch_add(count as u64, Ordering::Relaxed);
                metrics
                    .datagram_bytes
                    .fetch_add(datagram_bytes, Ordering::Relaxed);
            }
            Err(_error) => {
                return;
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

        let accepted = metrics.accepted.swap(0, Ordering::Relaxed);
        let accept_errors = metrics.accept_errors.swap(0, Ordering::Relaxed);
        let datagrams = metrics.datagrams.swap(0, Ordering::Relaxed);
        let datagram_bytes = metrics.datagram_bytes.swap(0, Ordering::Relaxed);
        let datagram_throughput = format_bitrate(datagram_bytes, elapsed);
        let open_connections = metrics.open_connections.load(Ordering::Relaxed);

        println!(
            "open_connections={open_connections} accepted/s={accepted} accept_errors/s={accept_errors} datagrams/s={datagrams} datagram_throughput={datagram_throughput}"
        );
    }
}
