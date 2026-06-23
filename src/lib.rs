use std::error::Error;
use std::io;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use std::any::Any;
use std::time::Instant;

use quinn::congestion::{Controller, ControllerFactory};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use quinn::rustls::{self, DigitallySignedStruct, SignatureScheme};
use quinn::{ClientConfig, ServerConfig, TransportConfig, VarInt};

pub const DEFAULT_DATAGRAM_BUFFER_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_PAYLOAD_BYTES: usize = 1024;
pub const DEFAULT_CONNECT_CONCURRENCY: usize = 512;
pub const SERVER_NAME: &str = "localhost";

pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

#[derive(Clone, Copy, Debug)]
pub struct TransportOptions {
    pub datagram_receive_buffer: usize,
    pub datagram_send_buffer: usize,
    pub idle_timeout: Option<Duration>,
    pub no_congestion_control: bool,
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            datagram_receive_buffer: DEFAULT_DATAGRAM_BUFFER_BYTES,
            datagram_send_buffer: DEFAULT_DATAGRAM_BUFFER_BYTES,
            idle_timeout: Some(Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS)),
            no_congestion_control: false,
        }
    }
}

// No-op congestion controller: window is always u64::MAX, all events ignored.
#[derive(Clone)]
struct NoCongestionControl;

impl Controller for NoCongestionControl {
    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _is_ecn: bool,
        _lost_bytes: u64,
    ) {
    }

    fn on_mtu_update(&mut self, _new_mtu: u16) {}

    fn window(&self) -> u64 {
        8000000
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        80000000
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

struct NoCongestionControlFactory;

impl ControllerFactory for NoCongestionControlFactory {
    fn build(self: Arc<Self>, _now: Instant, _current_mtu: u16) -> Box<dyn Controller> {
        Box::new(NoCongestionControl)
    }
}

pub fn transport_config(options: TransportOptions) -> Result<Arc<TransportConfig>, BoxError> {
    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(VarInt::from_u32(0));
    transport.max_concurrent_uni_streams(VarInt::from_u32(0));
    transport.datagram_receive_buffer_size(Some(options.datagram_receive_buffer));
    transport.datagram_send_buffer_size(options.datagram_send_buffer);

    let idle_timeout = options
        .idle_timeout
        .map(TryInto::try_into)
        .transpose()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("idle timeout is outside QUIC's valid range: {error}"),
            )
        })?;
    transport.max_idle_timeout(idle_timeout);

    if options.no_congestion_control {
        transport.congestion_controller_factory(Arc::new(NoCongestionControlFactory));
    }

    Ok(Arc::new(transport))
}

pub fn server_config(transport: Arc<TransportConfig>) -> Result<ServerConfig, BoxError> {
    let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()])?;
    let private_key = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let cert_chain = vec![cert.cert.der().clone()];
    let mut config = ServerConfig::with_single_cert(cert_chain, private_key)?;
    config.transport_config(transport);
    Ok(config)
}

pub fn insecure_client_config(transport: Arc<TransportConfig>) -> Result<ClientConfig, BoxError> {
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    let mut config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    config.transport_config(transport);
    Ok(config)
}

pub fn format_bitrate(bytes: u64, elapsed: Duration) -> String {
    let seconds = elapsed.as_secs_f64();
    if seconds == 0.0 || bytes == 0 {
        return "0bps".to_owned();
    }

    let mut bits_per_second = bytes as f64 * 8.0 / seconds;
    let mut unit = "bps";
    for next_unit in ["Kbps", "Mbps", "Gbps", "Tbps"] {
        if bits_per_second < 1000.0 {
            break;
        }
        bits_per_second /= 1000.0;
        unit = next_unit;
    }

    if unit == "bps" {
        format!("{bits_per_second:.0}{unit}")
    } else if bits_per_second < 10.0 {
        format!("{bits_per_second:.2}{unit}")
    } else if bits_per_second < 100.0 {
        format!("{bits_per_second:.1}{unit}")
    } else {
        format!("{bits_per_second:.0}{unit}")
    }
}

pub fn parse_byte_size(input: &str) -> Result<usize, String> {
    let value = input.trim();
    if value.is_empty() {
        return Err("size must not be empty".to_owned());
    }

    let number_end = value
        .find(|character: char| !character.is_ascii_digit() && character != '_')
        .unwrap_or(value.len());
    let number = value[..number_end].replace('_', "");
    if number.is_empty() {
        return Err("size must start with a number".to_owned());
    }

    let bytes = usize::from_str(&number).map_err(|error| format!("invalid size: {error}"))?;
    let unit = value[number_end..]
        .trim()
        .to_ascii_lowercase()
        .replace(' ', "");
    let multiplier = match unit.as_str() {
        "" | "b" => 1usize,
        "k" | "kb" => 1_000usize,
        "m" | "mb" => 1_000_000usize,
        "g" | "gb" => 1_000_000_000usize,
        unsupported => return Err(format!("unsupported size unit: {unsupported}")),
    };

    bytes
        .checked_mul(multiplier)
        .ok_or_else(|| "size is too large".to_owned())
}

#[derive(Debug)]
struct SkipServerVerification {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        })
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use bytes::Bytes;
    use quinn::Endpoint;

    #[tokio::test]
    async fn localhost_datagram_round_trip_reaches_server() {
        let transport = crate::transport_config(crate::TransportOptions::default()).unwrap();
        let server_config = crate::server_config(transport.clone()).unwrap();
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = Endpoint::server(server_config, server_addr).unwrap();
        let server_addr = server.local_addr().unwrap();

        let accept_task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), connection.read_datagram())
                .await
                .unwrap()
                .unwrap()
        });

        let client = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let client_config = crate::insecure_client_config(transport).unwrap();
        client.set_default_client_config(client_config);

        let connection = client
            .connect(server_addr, crate::SERVER_NAME)
            .unwrap()
            .await
            .unwrap();
        connection
            .send_datagram_wait(Bytes::from_static(b"datagram-bench"))
            .await
            .unwrap();

        let datagram = accept_task.await.unwrap();
        assert_eq!(datagram, Bytes::from_static(b"datagram-bench"));
    }

    #[test]
    fn formats_bitrates_with_si_units() {
        assert_eq!(crate::format_bitrate(0, Duration::from_secs(1)), "0bps");
        assert_eq!(crate::format_bitrate(100, Duration::from_secs(1)), "800bps");
        assert_eq!(
            crate::format_bitrate(125_000, Duration::from_secs(1)),
            "1.00Mbps"
        );
        assert_eq!(
            crate::format_bitrate(500_000_000, Duration::from_secs(1)),
            "4.00Gbps"
        );
    }

    #[test]
    fn parses_byte_sizes() {
        assert_eq!(crate::parse_byte_size("10MB").unwrap(), 10_000_000);
        assert_eq!(crate::parse_byte_size("10 mb").unwrap(), 10_000_000);
        assert_eq!(crate::parse_byte_size("64K").unwrap(), 64_000);
        assert_eq!(crate::parse_byte_size("1_024").unwrap(), 1_024);
        assert_eq!(crate::parse_byte_size("2GB").unwrap(), 2_000_000_000);
    }

    #[test]
    fn rejects_invalid_byte_sizes() {
        assert!(crate::parse_byte_size("").is_err());
        assert!(crate::parse_byte_size("MB").is_err());
        assert!(crate::parse_byte_size("1MiB").is_err());
        assert!(crate::parse_byte_size("1.5GB").is_err());
    }
}
