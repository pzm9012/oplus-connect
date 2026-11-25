//! ColorOS 15 `app:clipboardservice` gRPC-over-OAF bridge.
//!
//! The panta session owns the authenticated transport. It feeds decrypted OAF
//! payloads (which start with `ICDF`) into [`OafGrpcRoute::start_server`] or
//! [`OafGrpcRoute::start_client`], which decode the ICDF command stream
//! (`head`/`data`/`half-close` …) and return every [`GrpcOutput`] to the caller
//! for framing and socket writes. This module never touches a socket.
//!
//! Multiple routes can share one panta select loop: outputs and lifecycle events
//! carry the panta `session_id` supplied by the caller.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// OAF service profile advertised by ColorOS 15.
pub const CLIPBOARD_SERVICE_PROFILE: &str = "app:clipboardservice";
/// Client-streaming RPC used to copy text to the peer clipboard.
pub const COPY_TO_CLIP_PATH: &str = "/ClipBoardService/copyToClip";
/// Server-streaming RPC used to read the peer clipboard.
pub const GET_CLIP_DATA_PATH: &str = "/ClipBoardService/getClipData";
/// Maximum size of one protobuf/gRPC message (1 MiB).
pub const MAX_GRPC_MESSAGE_SIZE: usize = 1024 * 1024;
/// Largest protobuf message that still fits one OAF frame.
///
/// Panta prefixes every OAF frame with a `u16` length, so the frame is
/// `2` (transport header) + `1` (type byte) + `11` (ICDF header) + `8` (ICDF
/// data body) + payload bytes. Anything larger cannot be framed and would be
/// dropped by the writer, so it has to be refused here without disturbing the
/// route or the RPC that is waiting for its reply.
pub const MAX_ICDF_MESSAGE_SIZE: usize = u16::MAX as usize - (2 + 1 + 11 + 8);
/// Suggested capacity for the bounded panta route channels.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 64;

const ICDF_MAGIC: &[u8; 4] = b"ICDF";
/// `grpcchannel/inner/a.d(..., 15, body, false)` publishes the RPC method table
/// (method name, rpc type, channel id, compress/encrypt flags) before the first
/// request, on stream 0.
const ICDF_RPC_METHOD_CONFIG: u8 = 0x0f;
const ICDF_HEADER_SIZE: usize = 11;
/// Largest ICDF body accepted from the peer (one gRPC message plus framing).
const MAX_ICDF_BODY_SIZE: usize = 4 * 1024 * 1024;
const GRPC_PREFIX_SIZE: usize = 5;
const MAX_RPC_MESSAGES: usize = 256;
/// Concurrent request streams accepted from the phone per route.
const MAX_INBOUND_STREAMS: usize = 16;
/// A platform clipboard write slower than this is worth a log line.
const SLOW_WRITE_WARNING: Duration = Duration::from_secs(2);

/// How long one RPC may wait for the peer's close before its stream is
/// released. The phone answers in milliseconds; a missing reply means the
/// frame was lost, not that the peer is slow.
const RPC_REPLY_TIMEOUT: Duration = Duration::from_secs(5);
/// Repeats of an oversized clipboard warning are logged at most this often.
const OVERSIZED_WARN_INTERVAL: Duration = Duration::from_secs(60);

const GRPC_OK: u32 = 0;
const GRPC_UNIMPLEMENTED: u32 = 12;

/// Broadcast callback used by a panta session to publish the same JSON event as
/// `AppState::broadcast_event`. It is a callback rather than an `AppState` value
/// so one route can be owned by an individual authenticated session.
pub type EventBroadcaster = Arc<dyn Fn(&str) + Send + Sync>;

/// An encoded ICDF byte string destined for one panta session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcOutput {
    /// Panta session selected by the service registration.
    pub session_id: u16,
    /// Complete `ICDF` frames, without the outer OAF transport/GCM header.
    pub bytes: Vec<u8>,
}

/// Events emitted by a clipboard route to the panta owner.
#[derive(Debug, Clone)]
pub enum GrpcEvent {
    /// The RPC method table is published; requests may be sent now.
    Ready {
        /// Session that owns this route.
        session_id: u16,
    },
    /// Text received from the peer and applied to the local clipboard.
    RemoteText {
        /// Session that owns this route.
        session_id: u16,
        /// Text to install as the session's `last_clipboard` echo guard.
        text: Arc<String>,
    },
    /// The route has stopped and its channels/tasks can be cleaned up.
    Closed {
        /// Session that owns this route.
        session_id: u16,
    },
}

/// Commands accepted by a client route. RPCs are executed serially.
#[derive(Debug, Clone)]
pub enum GrpcCommand {
    /// Copy local text to the peer with `copyToClip`.
    SendText(String),
    /// Read the peer clipboard with `getClipData`.
    Pull,
}

/// Which RPC a stream carries, so the response can be decoded correctly.
#[derive(Clone, Copy)]
enum ClientRpcKind {
    SendText,
    Pull,
}

/// Entry points for one `app:clipboardservice` panta session.
pub struct OafGrpcRoute;

impl OafGrpcRoute {
    /// Serve clipboard RPCs requested by the phone.
    ///
    /// `inbound` contains decrypted OAF payload bytes beginning with `ICDF`.
    /// `outbound` receives complete ICDF byte strings tagged with `session_id`.
    /// Both channels should be bounded; all socket writes remain in the caller.
    pub async fn start_server(
        inbound: mpsc::Receiver<Vec<u8>>,
        outbound: mpsc::Sender<GrpcOutput>,
        events: mpsc::Sender<GrpcEvent>,
        broadcaster: Option<EventBroadcaster>,
        session_id: u16,
    ) {
        let result =
            run_icdf_server(inbound, outbound, events.clone(), broadcaster, session_id).await;
        if let Err(error) = result {
            warn!("clipboard server[{session_id}] stopped: {error}");
        }
        let _ = events.send(GrpcEvent::Closed { session_id }).await;
    }

    /// Connect to the phone's clipboard service.
    ///
    /// A `Ready` event is emitted once the RPC method table has been published.
    /// RPCs are serialized on one ICDF stream; `getClipData` is sent only for an
    /// explicit [`GrpcCommand::Pull`], never automatically at startup.
    pub async fn start_client(
        inbound: mpsc::Receiver<Vec<u8>>,
        outbound: mpsc::Sender<GrpcOutput>,
        mut commands: mpsc::Receiver<GrpcCommand>,
        events: mpsc::Sender<GrpcEvent>,
        broadcaster: Option<EventBroadcaster>,
        session_id: u16,
    ) {
        let result = run_icdf_client(
            inbound,
            outbound,
            &mut commands,
            events.clone(),
            broadcaster,
            session_id,
        )
        .await;
        if let Err(error) = result {
            warn!("clipboard client[{session_id}] stopped: {error}");
        }
        let _ = events.send(GrpcEvent::Closed { session_id }).await;
    }
}

/// Errors produced by the ICDF, protobuf, and gRPC codecs.
#[derive(Debug)]
pub enum OafError {
    /// An ICDF frame did not begin with `ICDF`.
    InvalidMagic,
    /// An ICDF size field was too small or too large.
    InvalidLength(&'static str),
    /// ClipData was not valid UTF-8 text.
    InvalidUtf8,
    /// ClipData was not a valid protobuf byte field.
    InvalidProtobuf(&'static str),
    /// A gRPC message prefix was malformed or compressed.
    InvalidGrpcPrefix(&'static str),
    /// A gRPC message exceeded [`MAX_GRPC_MESSAGE_SIZE`].
    MessageTooLarge(usize),
    /// One RPC exceeded the message-count limit.
    TooManyMessages(usize),
    /// A channel closed or a gRPC message ended midway through a frame.
    Truncated,
    /// A route channel closed.
    ChannelClosed,
}

impl fmt::Display for OafError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => formatter.write_str("invalid ICDF magic"),
            Self::InvalidLength(reason) => write!(formatter, "invalid ICDF length: {reason}"),
            Self::InvalidUtf8 => formatter.write_str("ClipData is not UTF-8"),
            Self::InvalidProtobuf(reason) => {
                write!(formatter, "invalid ClipData protobuf: {reason}")
            }
            Self::InvalidGrpcPrefix(reason) => write!(formatter, "invalid gRPC prefix: {reason}"),
            Self::MessageTooLarge(size) => {
                write!(formatter, "gRPC message is too large ({size} bytes)")
            }
            Self::TooManyMessages(count) => {
                write!(formatter, "RPC has too many messages ({count})")
            }
            Self::Truncated => formatter.write_str("truncated framed message"),
            Self::ChannelClosed => formatter.write_str("route channel closed"),
        }
    }
}

impl StdError for OafError {}

/// One complete ICDF frame: `ICDF`, size, stream id, command, body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcdfFrame {
    /// Stream id copied from the 16-bit ICDF metadata.
    pub stream_id: u16,
    /// ICDF command (`0x0f` method config, `0x07` head, `0x08` data, …).
    pub frame_type: u8,
    /// Command body, whose layout depends on [`Self::frame_type`].
    pub body: Vec<u8>,
}

/// Incrementally decodes a byte stream containing zero or more ICDF frames.
///
/// The pending buffer is capped at one maximum-sized ICDF frame. A malformed
/// frame poisons the decoder so later chunks cannot be misinterpreted.
#[derive(Debug, Default)]
pub struct IcdfDecoder {
    pending: Vec<u8>,
    failed: bool,
}

impl IcdfDecoder {
    /// Creates an empty decoder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Consumes a transport chunk and returns every completed ICDF frame.
    pub fn push(&mut self, mut chunk: &[u8]) -> Result<Vec<IcdfFrame>, OafError> {
        if self.failed {
            return Err(OafError::InvalidMagic);
        }

        let mut frames = Vec::new();
        loop {
            while self.pending.len() < ICDF_HEADER_SIZE && !chunk.is_empty() {
                let count = (ICDF_HEADER_SIZE - self.pending.len()).min(chunk.len());
                self.pending.extend_from_slice(&chunk[..count]);
                chunk = &chunk[count..];
            }
            if self.pending.len() < ICDF_HEADER_SIZE {
                break;
            }

            if &self.pending[..4] != ICDF_MAGIC {
                return Err(self.fail(OafError::InvalidMagic));
            }
            let size = u32::from_be_bytes(self.pending[4..8].try_into().unwrap()) as usize;
            if size < 3 {
                return Err(self.fail(OafError::InvalidLength("size is smaller than 3")));
            }
            let payload_size = size - 3;
            if payload_size > MAX_ICDF_BODY_SIZE {
                return Err(self.fail(OafError::InvalidLength("body exceeds ICDF limit")));
            }
            let total_size = ICDF_HEADER_SIZE + payload_size;
            while self.pending.len() < total_size && !chunk.is_empty() {
                let count = (total_size - self.pending.len()).min(chunk.len());
                self.pending.extend_from_slice(&chunk[..count]);
                chunk = &chunk[count..];
            }
            if self.pending.len() < total_size {
                break;
            }

            let encoded: Vec<u8> = self.pending.drain(..total_size).collect();
            frames.push(IcdfFrame {
                stream_id: u16::from_be_bytes(encoded[8..10].try_into().unwrap()),
                frame_type: encoded[10],
                body: encoded[11..].to_vec(),
            });
        }
        Ok(frames)
    }

    /// Verifies that no partial ICDF frame remains.
    pub fn finish(&mut self) -> Result<(), OafError> {
        if self.failed {
            return Err(OafError::InvalidMagic);
        }
        if self.pending.is_empty() {
            Ok(())
        } else {
            Err(OafError::Truncated)
        }
    }

    fn fail(&mut self, error: OafError) -> OafError {
        self.failed = true;
        self.pending.clear();
        error
    }
}

/// Encodes one ICDF frame: magic, size, stream id, command, body.
fn encode_icdf_payload(stream_id: u16, frame_type: u8, payload: &[u8]) -> Vec<u8> {
    let size = u32::try_from(payload.len() + 3).expect("ICDF payload limit fits in u32");
    let mut encoded = Vec::with_capacity(ICDF_HEADER_SIZE + payload.len());
    encoded.extend_from_slice(ICDF_MAGIC);
    encoded.extend_from_slice(&size.to_be_bytes());
    encoded.extend_from_slice(&stream_id.to_be_bytes());
    encoded.push(frame_type);
    encoded.extend_from_slice(payload);
    encoded
}

/// Body of the `ICDF` type-0x0f "RPC method configuration" message:
/// `count u32`, then per method `len u32`, method, `rpcType u16`, `channel u16`,
/// `flags u32` (1 = compress, 2 = encrypt) and a reserved `u32`.
fn rpc_method_config_body() -> Vec<u8> {
    let method = "ClipBoardService/copyToClip";
    let mut body = Vec::with_capacity(47);
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&(method.len() as u32).to_be_bytes());
    body.extend_from_slice(method.as_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&104u16.to_be_bytes());
    body.extend_from_slice(&2u32.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes());
    body
}

/// Complete ICDF frame for the RPC method table, published on stream 0 before
/// the first request.
fn icdf_rpc_method_config() -> Vec<u8> {
    encode_icdf_payload(0, ICDF_RPC_METHOD_CONFIG, &rpc_method_config_body())
}

/// Protobuf `ClipData { bytes data = 1; }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipData {
    data: Vec<u8>,
}

impl ClipData {
    /// Creates ClipData from UTF-8 text.
    pub fn from_text(text: impl Into<String>) -> Self {
        Self {
            data: text.into().into_bytes(),
        }
    }

    /// Consumes this value and returns its UTF-8 text.
    pub fn into_text(self) -> Result<String, OafError> {
        String::from_utf8(self.data).map_err(|_| OafError::InvalidUtf8)
    }

    /// Encodes the protobuf message.
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(2 + self.data.len());
        if !self.data.is_empty() {
            encoded.push(0x0a);
            encode_varint(self.data.len() as u64, &mut encoded);
            encoded.extend_from_slice(&self.data);
        }
        encoded
    }

    /// Decodes the protobuf message, skipping unknown fields.
    pub fn decode(mut input: &[u8]) -> Result<Self, OafError> {
        if input.len() > MAX_GRPC_MESSAGE_SIZE {
            return Err(OafError::MessageTooLarge(input.len()));
        }
        let mut data = Vec::new();
        while !input.is_empty() {
            let (tag, remaining) = read_varint(input)?;
            input = remaining;
            let field_number = tag >> 3;
            let wire_type = (tag & 7) as u8;
            if field_number == 0 {
                return Err(OafError::InvalidProtobuf("zero field number"));
            }
            if field_number == 1 && wire_type == 2 {
                let (length, remaining) = read_varint(input)?;
                input = remaining;
                let length = usize::try_from(length)
                    .map_err(|_| OafError::InvalidProtobuf("field length overflow"))?;
                if length > input.len() {
                    return Err(OafError::InvalidProtobuf("truncated byte field"));
                }
                data.clear();
                data.extend_from_slice(&input[..length]);
                input = &input[length..];
            } else {
                input = skip_protobuf_field(input, wire_type)?;
            }
        }
        Ok(Self { data })
    }
}

fn read_varint(input: &[u8]) -> Result<(u64, &[u8]), OafError> {
    let mut value = 0u64;
    for (index, byte) in input.iter().copied().take(10).enumerate() {
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            if index == 9 && byte > 1 {
                return Err(OafError::InvalidProtobuf("varint overflow"));
            }
            return Ok((value, &input[index + 1..]));
        }
    }
    Err(OafError::InvalidProtobuf("invalid varint"))
}

fn encode_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn skip_protobuf_field(input: &[u8], wire_type: u8) -> Result<&[u8], OafError> {
    match wire_type {
        0 => {
            let (_, remaining) = read_varint(input)?;
            Ok(remaining)
        }
        1 => {
            if input.len() < 8 {
                Err(OafError::InvalidProtobuf("truncated fixed64"))
            } else {
                Ok(&input[8..])
            }
        }
        2 => {
            let (length, remaining) = read_varint(input)?;
            let length = usize::try_from(length)
                .map_err(|_| OafError::InvalidProtobuf("field length overflow"))?;
            if length > remaining.len() {
                Err(OafError::InvalidProtobuf(
                    "truncated length-delimited field",
                ))
            } else {
                Ok(&remaining[length..])
            }
        }
        5 => {
            if input.len() < 4 {
                Err(OafError::InvalidProtobuf("truncated fixed32"))
            } else {
                Ok(&input[4..])
            }
        }
        _ => Err(OafError::InvalidProtobuf("unsupported wire type")),
    }
}

/// Incrementally decodes uncompressed gRPC messages from DATA command bodies.
#[derive(Debug, Default)]
pub struct GrpcMessageDecoder {
    pending: Vec<u8>,
    failed: bool,
}

impl GrpcMessageDecoder {
    /// Creates an empty gRPC message decoder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Consumes a DATA chunk and returns all complete message payloads.
    pub fn push(&mut self, mut chunk: &[u8]) -> Result<Vec<Vec<u8>>, OafError> {
        if self.failed {
            return Err(OafError::InvalidGrpcPrefix("decoder is poisoned"));
        }

        let mut messages = Vec::new();
        loop {
            while self.pending.len() < GRPC_PREFIX_SIZE && !chunk.is_empty() {
                let count = (GRPC_PREFIX_SIZE - self.pending.len()).min(chunk.len());
                self.pending.extend_from_slice(&chunk[..count]);
                chunk = &chunk[count..];
            }
            if self.pending.len() < GRPC_PREFIX_SIZE {
                break;
            }
            if self.pending[0] != 0 {
                return Err(self.fail(OafError::InvalidGrpcPrefix(
                    "compressed messages are unsupported",
                )));
            }
            let size = u32::from_be_bytes(self.pending[1..5].try_into().unwrap()) as usize;
            if size > MAX_GRPC_MESSAGE_SIZE {
                return Err(self.fail(OafError::MessageTooLarge(size)));
            }
            let total_size = GRPC_PREFIX_SIZE + size;
            while self.pending.len() < total_size && !chunk.is_empty() {
                let count = (total_size - self.pending.len()).min(chunk.len());
                self.pending.extend_from_slice(&chunk[..count]);
                chunk = &chunk[count..];
            }
            if self.pending.len() < total_size {
                break;
            }
            messages.push(
                self.pending
                    .drain(..total_size)
                    .skip(GRPC_PREFIX_SIZE)
                    .collect(),
            );
        }
        Ok(messages)
    }

    /// Verifies that no partial gRPC message remains.
    pub fn finish(&mut self) -> Result<Vec<Vec<u8>>, OafError> {
        if self.failed {
            return Err(OafError::InvalidGrpcPrefix("decoder is poisoned"));
        }
        if self.pending.is_empty() {
            Ok(Vec::new())
        } else {
            Err(OafError::Truncated)
        }
    }

    fn fail(&mut self, error: OafError) -> OafError {
        self.failed = true;
        self.pending.clear();
        error
    }
}

#[derive(Clone)]
struct RouteContext {
    session_id: u16,
    events: mpsc::Sender<GrpcEvent>,
    broadcaster: Option<EventBroadcaster>,
    /// Last text this route installed locally, so repeated pushes of the same
    /// clipboard content do not rewrite it over and over.
    last_applied: Arc<std::sync::Mutex<Option<Arc<String>>>>,
    /// Last time this route warned about a payload that cannot be framed. The
    /// peer re-pushes its clipboard on every `Ready`, so an oversized local
    /// clipboard would otherwise repeat the same warning every few seconds.
    oversized_warned: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
}

impl RouteContext {
    /// Whether an oversized payload is worth a warning rather than a debug line.
    fn oversized_warning_due(&self) -> bool {
        let Ok(mut last) = self.oversized_warned.lock() else {
            return true;
        };
        let now = std::time::Instant::now();
        let due = last.is_none_or(|at| now.duration_since(at) >= OVERSIZED_WARN_INTERVAL);
        if due {
            *last = Some(now);
        }
        due
    }

    async fn apply_remote_text(&self, text: Arc<String>) -> Result<(), OafError> {
        // The phone re-pushes its clipboard for every `IcdfStatus=Ready`, so the
        // same text arrives every few seconds. Rewriting the platform clipboard
        // each time churns clipboard ownership and floods managers/history, so
        // skip it when this route already applied exactly this text, or when the
        // clipboard still holds it.
        let already_applied = self
            .last_applied
            .lock()
            .ok()
            .and_then(|applied| {
                applied
                    .as_ref()
                    .map(|applied| applied.as_str() == text.as_str())
            })
            .unwrap_or(false);
        let already_local = already_applied
            || match crate::platform::clipboard::request_read() {
                Some(mut read) => read.finish().await,
                None => None,
            }
            .as_deref()
            .is_some_and(|current| current.as_str() == text.as_str());
        let mut applied = already_local;
        if already_local {
            debug!(
                "clipboard[{}]: remote text already local ({}B), skipping write",
                self.session_id,
                text.len()
            );
        } else {
            let started = std::time::Instant::now();
            applied = crate::platform::clipboard::write_text_async(Arc::clone(&text)).await;
            if applied && started.elapsed() >= SLOW_WRITE_WARNING {
                info!(
                    "clipboard[{}]: platform write completed slowly ({}B)",
                    self.session_id,
                    text.len()
                );
            }
        }
        if !applied {
            warn!(
                "clipboard[{}]: platform clipboard write failed",
                self.session_id
            );
        }

        // Remember the text only once it really reached the clipboard: recording
        // a failed write would make the phone's next push look already applied
        // and the text would never be retried.
        if applied && let Ok(mut last_applied) = self.last_applied.lock() {
            *last_applied = Some(Arc::clone(&text));
        }

        // Notify even when the platform write failed: the main loop must still
        // install the echo guard for text that may already be on the clipboard.
        let preview = text
            .char_indices()
            .nth(120)
            .map_or(text.as_str(), |(index, _)| &text[..index]);
        // The phone re-pushes its clipboard for every Ready poll, so log repeats
        // at debug level instead of spamming one INFO line every few seconds.
        if already_local {
            debug!(
                "clipboard[{}]: remote text repeat ({}B): {}",
                self.session_id,
                text.len(),
                preview
            );
        } else {
            info!(
                "clipboard[{}]: remote text ({}B): {}",
                self.session_id,
                text.len(),
                preview
            );
        }
        let event = serde_json::json!({
            "event": "clipboard_callback",
            "type": "text",
            "source": "remote",
            "content": text.as_str(),
        });
        if let Some(broadcaster) = &self.broadcaster {
            broadcaster(&event.to_string());
        }
        self.events
            .send(GrpcEvent::RemoteText {
                session_id: self.session_id,
                text,
            })
            .await
            .map_err(|_| OafError::ChannelClosed)
    }
}

// ---------------------------------------------------------------------------
// ICDF command transport
//
// The phone's `app:clipboardservice` gRPC does not carry HTTP/2 frames on the
// wire. `grpcchannel/inner/a.d` multiplexes ICDF commands instead:
//
//   "ICDF" | BE32 size(3 + body) | BE16 streamId | u8 command | body
//
// with `0x0f` RPC method config, `0x07` head, `0x08` data, `0x09` half-close,
// `0x0a` cancel on the client side and `0x01` head, `0x02` data, `0x03` close
// on the server side. The head body is `method` + metadata + authority, each as
// BE32 length plus bytes; the data body is `BE32 seqNo` + `BE32 length` +
// `length` bytes.
// ---------------------------------------------------------------------------

/// Client → server: request head (opens the stream).
const ICDF_CMD_HEAD: u8 = 0x07;
/// Client → server: request body chunk (`BE32 seqNo`, `BE32 length`, bytes).
const ICDF_CMD_DATA: u8 = 0x08;
/// Client → server: half-close, the request side is done.
const ICDF_CMD_HALF_CLOSE: u8 = 0x09;
/// Server → client: response head.
const ICDF_CMD_PEER_HEAD: u8 = 0x01;
/// Server → client: response body chunk, laid out like [`ICDF_CMD_DATA`].
const ICDF_CMD_PEER_DATA: u8 = 0x02;
/// Server → client: response trailers (also the observed end of a response).
const ICDF_CMD_PEER_TRAILER: u8 = 0x03;
/// Server → client: stream finished.
const ICDF_CMD_PEER_CLOSE: u8 = 0x04;

/// BE32 length prefix used by the ICDF head body fields.
fn icdf_length_prefixed(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// `head` body: method name, metadata pairs, authority — each length-prefixed.
fn icdf_head_body(method: &str, metadata: &[(Vec<u8>, Vec<u8>)], authority: &str) -> Vec<u8> {
    let mut body = icdf_length_prefixed(method.as_bytes());
    body.extend_from_slice(&(metadata.len() as u32).to_be_bytes());
    for (name, value) in metadata {
        body.extend_from_slice(&icdf_length_prefixed(name));
        body.extend_from_slice(&icdf_length_prefixed(value));
    }
    body.extend_from_slice(&icdf_length_prefixed(authority.as_bytes()));
    body
}

/// `data` body: `seqNo`, payload length, payload.
fn icdf_data_body(seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + payload.len());
    body.extend_from_slice(&seq.to_be_bytes());
    body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    body.extend_from_slice(payload);
    body
}

/// Splits a peer `data` body into its payload, mirroring [`icdf_data_body`].
fn icdf_data_payload(body: &[u8]) -> Option<&[u8]> {
    if body.len() < 8 {
        return None;
    }
    let length = u32::from_be_bytes(body[4..8].try_into().ok()?) as usize;
    body.get(8..8 + length)
}

async fn write_icdf_command(
    outbound: &mpsc::Sender<GrpcOutput>,
    session_id: u16,
    stream_id: u16,
    command: u8,
    body: &[u8],
) -> Result<(), OafError> {
    let bytes = encode_icdf_payload(stream_id, command, body);
    outbound
        .send(GrpcOutput { session_id, bytes })
        .await
        .map_err(|_| OafError::ChannelClosed)
}

/// One inbound request being assembled from ICDF `head`/`data`/`half-close`.
struct IcdfServerStream {
    method: String,
    payload: Vec<u8>,
}

/// Extracts the method name from a `head` body: BE32 length + bytes.
fn icdf_head_method(body: &[u8]) -> Option<String> {
    if body.len() < 4 {
        return None;
    }
    let length = u32::from_be_bytes(body[0..4].try_into().ok()?) as usize;
    let name = body.get(4..4 + length)?;
    String::from_utf8(name.to_vec()).ok()
}

/// `head` body with key/value metadata pairs.
fn icdf_head_pairs(pairs: &[(&str, &str)]) -> Vec<u8> {
    icdf_head_body(
        "",
        &pairs
            .iter()
            .map(|(name, value)| (name.as_bytes().to_vec(), value.as_bytes().to_vec()))
            .collect::<Vec<_>>(),
        "",
    )
}

/// Sends a response head with the metadata gRPC clients expect.
async fn icdf_send_head(
    outbound: &mpsc::Sender<GrpcOutput>,
    session_id: u16,
    stream_id: u16,
) -> Result<(), OafError> {
    let pairs: &[(&str, &str)] = &[
        ("grpc-encoding", "identity"),
        ("content-type", "application/grpc"),
    ];
    let body = icdf_head_pairs(pairs);
    write_icdf_command(outbound, session_id, stream_id, ICDF_CMD_PEER_HEAD, &body).await
}

/// Sends one response message.
async fn icdf_send_data(
    outbound: &mpsc::Sender<GrpcOutput>,
    session_id: u16,
    stream_id: u16,
    seq: u32,
    message: &[u8],
) -> Result<(), OafError> {
    let body = icdf_data_body(seq, message);
    write_icdf_command(outbound, session_id, stream_id, ICDF_CMD_PEER_DATA, &body).await
}

/// Closes the stream with a gRPC status (`0` = OK).
async fn icdf_send_close(
    outbound: &mpsc::Sender<GrpcOutput>,
    session_id: u16,
    stream_id: u16,
    status: u8,
) -> Result<(), OafError> {
    let mut body = vec![0u8; 4];
    body.push(status);
    write_icdf_command(
        outbound,
        session_id,
        stream_id,
        ICDF_CMD_PEER_TRAILER,
        &body,
    )
    .await
}

async fn icdf_handle_request(
    outbound: &mpsc::Sender<GrpcOutput>,
    context: &RouteContext,
    session_id: u16,
    stream_id: u16,
    stream: IcdfServerStream,
) -> Result<(), OafError> {
    let method = stream.method.trim_start_matches('/');
    let response = match method {
        "ClipBoardService/copyToClip" => {
            if !stream.payload.is_empty() {
                // One unusable message (a non-text or malformed `ClipData`) is
                // not a reason to tear the whole channel down: the phone keeps
                // using this route for every later copy.
                match ClipData::decode(&stream.payload).and_then(ClipData::into_text) {
                    Ok(text) => context.apply_remote_text(Arc::new(text)).await?,
                    Err(error) => warn!(
                        "clipboard[{session_id}] ignoring unusable clipboard payload on \
                         stream={stream_id}: {error}"
                    ),
                }
            }
            Vec::new()
        }
        "ClipBoardService/getClipData" => {
            let text = match crate::platform::clipboard::request_read() {
                Some(mut read) => read.finish().await,
                None => None,
            };
            match text {
                Some(text) => ClipData::from_text(text.as_str()).encode(),
                None => Vec::new(),
            }
        }
        // `HealthCheckResponse { status: SERVING }`: field 1, varint 1.
        "grpc.health.v1.Health/Check" => vec![0x08, 0x01],
        _ => {
            icdf_send_head(outbound, session_id, stream_id).await?;
            return icdf_send_close(outbound, session_id, stream_id, GRPC_UNIMPLEMENTED as u8)
                .await;
        }
    };
    icdf_send_head(outbound, session_id, stream_id).await?;
    if response.len() > MAX_ICDF_MESSAGE_SIZE {
        warn!(
            "clipboard[{session_id}] response too large for one OAF frame \
             ({}B > {MAX_ICDF_MESSAGE_SIZE}B), sending an empty clipboard",
            response.len()
        );
    } else if !response.is_empty() {
        // One response message per RPC, so the DATA sequence is always 0.
        icdf_send_data(outbound, session_id, stream_id, 0, &response).await?;
    }
    icdf_send_close(outbound, session_id, stream_id, GRPC_OK as u8).await
}

/// Serves the phone's clipboard RPCs over the ICDF command transport.
async fn run_icdf_server(
    mut inbound: mpsc::Receiver<Vec<u8>>,
    outbound: mpsc::Sender<GrpcOutput>,
    events: mpsc::Sender<GrpcEvent>,
    broadcaster: Option<EventBroadcaster>,
    session_id: u16,
) -> Result<(), OafError> {
    let context = RouteContext {
        session_id,
        events: events.clone(),
        broadcaster,
        last_applied: Arc::new(std::sync::Mutex::new(None)),
        oversized_warned: Arc::new(std::sync::Mutex::new(None)),
    };
    let mut decoder = IcdfDecoder::new();
    let mut streams: HashMap<u16, IcdfServerStream> = HashMap::new();
    let outbound_closed = outbound.clone();
    let outbound_closed = outbound_closed.closed();
    tokio::pin!(outbound_closed);

    loop {
        tokio::select! {
            chunk = inbound.recv() => {
                let Some(chunk) = chunk else {
                    return Err(OafError::ChannelClosed);
                };
                for frame in decoder.push(&chunk)? {
                    debug!(
                        "clipboard[{session_id}] ICDF srv rx stream={} cmd={:#04x} len={}",
                        frame.stream_id,
                        frame.frame_type,
                        frame.body.len()
                    );
                    match frame.frame_type {
                        ICDF_CMD_HEAD => {
                            if streams.len() >= MAX_INBOUND_STREAMS {
                                warn!(
                                    "clipboard[{session_id}] ICDF stream limit reached, \
                                     dropping stream={}",
                                    frame.stream_id
                                );
                                continue;
                            }
                            let method = icdf_head_method(&frame.body).unwrap_or_default();
                            streams.insert(
                                frame.stream_id,
                                IcdfServerStream {
                                    method,
                                    payload: Vec::new(),
                                },
                            );
                        }
                        ICDF_CMD_DATA => {
                            if let Some(stream) = streams.get_mut(&frame.stream_id)
                                && let Some(payload) = icdf_data_payload(&frame.body)
                            {
                                stream.payload.extend_from_slice(payload);
                                if stream.payload.len() > MAX_GRPC_MESSAGE_SIZE {
                                    warn!(
                                        "clipboard[{session_id}] ICDF request payload too large, \
                                         dropping stream={}",
                                        frame.stream_id
                                    );
                                    streams.remove(&frame.stream_id);
                                }
                            }
                        }
                        ICDF_CMD_HALF_CLOSE => {
                            let Some(stream) = streams.remove(&frame.stream_id) else {
                                continue;
                            };
                            icdf_handle_request(
                                &outbound,
                                &context,
                                session_id,
                                frame.stream_id,
                                stream,
                            )
                            .await?;
                        }
                        _ => {}
                    }
                }
            }
            _ = &mut outbound_closed => return Err(OafError::ChannelClosed),
        }
    }
}

/// Applies one decoded response message from the phone.
async fn process_client_message(
    kind: ClientRpcKind,
    message: Vec<u8>,
    context: &RouteContext,
) -> Result<(), OafError> {
    if message.is_empty() {
        return Ok(());
    }
    match kind {
        // `copyToClip` answers with an empty message; a payload here is an
        // unsolicited echo we do not want to apply back to the clipboard.
        ClientRpcKind::SendText => Ok(()),
        ClientRpcKind::Pull => {
            // Same rule as the server side: a bad response must not end the
            // route, which is still needed for every following command.
            match ClipData::decode(&message).and_then(ClipData::into_text) {
                Ok(text) => context.apply_remote_text(Arc::new(text)).await,
                Err(error) => {
                    warn!(
                        "clipboard[{}] ignoring unusable clipboard response: {error}",
                        context.session_id
                    );
                    Ok(())
                }
            }
        }
    }
}

/// Splits one ICDF DATA payload into gRPC messages.
///
/// The phone sends bare protobuf messages (the ICDF frame already carries the
/// length). A gRPC 5-byte prefix is tolerated for firmware variants that add it.
fn split_response_messages(payload: &[u8]) -> Result<Vec<Vec<u8>>, OafError> {
    let prefixed = payload.len() >= GRPC_PREFIX_SIZE
        && payload[0] == 0
        && u32::from_be_bytes(payload[1..GRPC_PREFIX_SIZE].try_into().unwrap()) as usize
            == payload.len() - GRPC_PREFIX_SIZE;
    if !prefixed {
        return Ok(vec![payload.to_vec()]);
    }
    let mut decoder = GrpcMessageDecoder::new();
    let mut messages = decoder.push(payload)?;
    messages.extend(decoder.finish()?);
    Ok(messages)
}

/// Sleeps until `deadline`, or forever when there is nothing to wait for, so a
/// `select!` arm can stay armed without allocating a timer per iteration.
async fn sleep_until_deadline(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Runs the clipboard RPCs over the phone's ICDF command transport.
async fn run_icdf_client(
    mut inbound: mpsc::Receiver<Vec<u8>>,
    outbound: mpsc::Sender<GrpcOutput>,
    commands: &mut mpsc::Receiver<GrpcCommand>,
    events: mpsc::Sender<GrpcEvent>,
    broadcaster: Option<EventBroadcaster>,
    session_id: u16,
) -> Result<(), OafError> {
    outbound
        .send(GrpcOutput {
            session_id,
            bytes: icdf_rpc_method_config(),
        })
        .await
        .map_err(|_| OafError::ChannelClosed)?;
    events
        .send(GrpcEvent::Ready { session_id })
        .await
        .map_err(|_| OafError::ChannelClosed)?;

    let context = RouteContext {
        session_id,
        events: events.clone(),
        broadcaster,
        last_applied: Arc::new(std::sync::Mutex::new(None)),
        oversized_warned: Arc::new(std::sync::Mutex::new(None)),
    };
    let mut decoder = IcdfDecoder::new();
    let mut next_stream: u16 = 1;
    let mut seq: u32 = 0;
    let mut active: Option<(u16, ClientRpcKind)> = None;
    let mut messages_on_stream = 0usize;
    let mut reply_deadline: Option<tokio::time::Instant> = None;

    let outbound_closed = outbound.clone();
    let outbound_closed = outbound_closed.closed();
    tokio::pin!(outbound_closed);

    loop {
        tokio::select! {
            command = commands.recv(), if active.is_none() => {
                let Some(command) = command else {
                    return Err(OafError::ChannelClosed);
                };
                // The ICDF data frame already carries an explicit length, so the
                // payload is the bare protobuf message: adding the gRPC 5-byte
                // prefix makes the phone's parser fail with
                // `Protocol message contained an invalid tag (zero)`.
                let (path, payload, kind) = match command {
                    GrpcCommand::SendText(text) => (
                        COPY_TO_CLIP_PATH,
                        ClipData::from_text(text).encode(),
                        ClientRpcKind::SendText,
                    ),
                    GrpcCommand::Pull => (
                        GET_CLIP_DATA_PATH,
                        // `Clipboard.Type{type = 0}`.
                        vec![0x08, 0x00],
                        ClientRpcKind::Pull,
                    ),
                };
                // A payload that cannot fit one OAF frame would be dropped by
                // the writer before the phone ever sees the RPC, leaving this
                // stream `active` forever and every later command queued behind
                // it. Refuse it here instead, where the route stays usable.
                if payload.len() > MAX_ICDF_MESSAGE_SIZE {
                    if context.oversized_warning_due() {
                        warn!(
                            "clipboard[{session_id}] {path} payload too large for one OAF frame \
                             ({}B > {MAX_ICDF_MESSAGE_SIZE}B), dropping (repeats at debug)",
                            payload.len()
                        );
                    } else {
                        debug!(
                            "clipboard[{session_id}] {path} oversized payload again ({}B)",
                            payload.len()
                        );
                    }
                    continue;
                }
                // gRPC stream ids are odd and increasing; wrap keeps it positive.
                let stream = next_stream;
                next_stream = next_stream.wrapping_add(2).max(3);
                let method = path.trim_start_matches('/');
                let head = icdf_head_body(method, &[], "");
                write_icdf_command(&outbound, session_id, stream, ICDF_CMD_HEAD, &head).await?;
                let body = icdf_data_body(seq, &payload);
                seq = seq.wrapping_add(1);
                write_icdf_command(&outbound, session_id, stream, ICDF_CMD_DATA, &body).await?;
                write_icdf_command(&outbound, session_id, stream, ICDF_CMD_HALF_CLOSE, &[]).await?;
                debug!("clipboard[{session_id}] ICDF {method} stream={stream} sent");
                active = Some((stream, kind));
                reply_deadline = Some(tokio::time::Instant::now() + RPC_REPLY_TIMEOUT);
            }
            chunk = inbound.recv() => {
                let Some(chunk) = chunk else {
                    return Err(OafError::ChannelClosed);
                };
                let frames = match decoder.push(&chunk) {
                    Ok(frames) => frames,
                    Err(error) => {
                        warn!("clipboard[{session_id}] ICDF command decode failed: {error}");
                        return Err(error);
                    }
                };
                for frame in frames {
                    debug!(
                        "clipboard[{session_id}] ICDF rx stream={} cmd={:#04x} len={} hex={}",
                        frame.stream_id,
                        frame.frame_type,
                        frame.body.len(),
                        frame
                            .body
                            .iter()
                            .take(32)
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>()
                    );
                    match (frame.frame_type, active) {
                        (ICDF_CMD_PEER_DATA, Some((stream, kind))) if frame.stream_id == stream => {
                            let Some(payload) = icdf_data_payload(&frame.body) else {
                                warn!(
                                    "clipboard[{session_id}] ICDF data body too short on stream={}",
                                    frame.stream_id
                                );
                                continue;
                            };
                            let messages = split_response_messages(payload)?;
                            messages_on_stream += messages.len();
                            if messages_on_stream > MAX_RPC_MESSAGES {
                                return Err(OafError::TooManyMessages(messages_on_stream));
                            }
                            for message in messages {
                                process_client_message(kind, message, &context).await?;
                            }
                        }
                        // The phone finishes a response with `0x03` (close);
                        // treating only `0x04` as close left `active` set forever
                        // and every later RPC was dropped.
                        (ICDF_CMD_PEER_CLOSE | ICDF_CMD_PEER_TRAILER, Some((stream, _)))
                            if frame.stream_id == stream =>
                        {
                            debug!(
                                "clipboard[{session_id}] ICDF stream={stream} finished by peer \
                                 (cmd={:#04x})",
                                frame.frame_type
                            );
                            active = None;
                            messages_on_stream = 0;
                            reply_deadline = None;
                        }
                        // Trailers, method tables and stray streams carry no data.
                        _ => {}
                    }
                }
            }
            // A peer that never closes the stream would leave `active` set for
            // good, and the command branch is disabled while it is. Release the
            // stream so the next copy is not queued behind a lost reply.
            _ = sleep_until_deadline(reply_deadline) => {
                if let Some((stream, _)) = active.take() {
                    warn!(
                        "clipboard[{session_id}] ICDF stream={stream} had no reply within \
                         {RPC_REPLY_TIMEOUT:?}, releasing it"
                    );
                    messages_on_stream = 0;
                }
                reply_deadline = None;
            }
            _ = &mut outbound_closed => return Err(OafError::ChannelClosed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, timeout};

    fn frame(stream_id: u16, command: u8, body: &[u8]) -> Vec<u8> {
        encode_icdf_payload(stream_id, command, body)
    }

    #[test]
    fn decodes_fragmented_and_merged_frames() {
        let first = frame(1, ICDF_CMD_HEAD, &[0xaa, 0xbb]);
        let second = frame(2, ICDF_CMD_DATA, &[0xcc]);
        let mut stream = first.clone();
        stream.extend_from_slice(&second);

        let mut decoder = IcdfDecoder::new();
        // Split mid-header, then mid-body: the decoder must buffer both.
        let frames = decoder.push(&stream[..5]).unwrap();
        assert!(frames.is_empty());
        let frames = decoder.push(&stream[5..first.len() + 1]).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].stream_id, 1);
        assert_eq!(frames[0].frame_type, ICDF_CMD_HEAD);
        assert_eq!(frames[0].body, vec![0xaa, 0xbb]);
        let frames = decoder.push(&stream[first.len() + 1..]).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].stream_id, 2);
        assert_eq!(frames[0].frame_type, ICDF_CMD_DATA);
        assert_eq!(frames[0].body, vec![0xcc]);
        decoder.finish().unwrap();
    }

    #[test]
    fn rejects_malformed_headers() {
        let mut decoder = IcdfDecoder::new();
        assert!(matches!(
            decoder.push(b"NOPE\x00\x00\x00\x03\x00\x01\x07"),
            Err(OafError::InvalidMagic)
        ));
        let mut decoder = IcdfDecoder::new();
        assert!(matches!(
            decoder.push(b"ICDF\x00\x00\x00\x02\x00\x01\x07"),
            Err(OafError::InvalidLength(_))
        ));
    }

    #[test]
    fn head_and_data_bodies_round_trip() {
        let head = icdf_head_body(
            "ClipBoardService/copyToClip",
            &[("grpc-encoding".into(), "identity".into())],
            "",
        );
        assert_eq!(
            icdf_head_method(&head).as_deref(),
            Some("ClipBoardService/copyToClip")
        );

        let data = icdf_data_body(7, &[0x0a, 0x02, b'h', b'i']);
        assert_eq!(data[..4], 7u32.to_be_bytes());
        assert_eq!(
            icdf_data_payload(&data),
            Some(&[0x0a, 0x02, b'h', b'i'][..])
        );
        assert_eq!(icdf_data_payload(&data[..4]), None);
    }

    #[test]
    fn response_messages_accept_bare_and_prefixed_payloads() {
        // The phone sends bare protobuf; a gRPC prefix is tolerated.
        assert_eq!(
            split_response_messages(&[0x0a, 0x02, b'h', b'i']).unwrap(),
            vec![vec![0x0a, 0x02, b'h', b'i']]
        );
        let mut prefixed = vec![0x00, 0x00, 0x00, 0x00, 0x04];
        prefixed.extend_from_slice(&[0x0a, 0x02, b'h', b'i']);
        assert_eq!(
            split_response_messages(&prefixed).unwrap(),
            vec![vec![0x0a, 0x02, b'h', b'i']]
        );
        assert!(split_response_messages(&[]).is_ok());
    }

    #[test]
    fn rpc_method_config_lists_copy_to_clip() {
        let config = icdf_rpc_method_config();
        assert_eq!(&config[..4], ICDF_MAGIC);
        assert_eq!(config[10], ICDF_RPC_METHOD_CONFIG);
        let body = &config[ICDF_HEADER_SIZE..];
        // count = 1, then the method name.
        assert_eq!(&body[..4], 1u32.to_be_bytes());
        assert_eq!(&body[8..8 + 27], b"ClipBoardService/copyToClip");
    }

    /// Client and server routes wired to each other over in-memory channels,
    /// the way panta connects them inside one session.
    struct Pair {
        commands: mpsc::Sender<GrpcCommand>,
        server_events: mpsc::Receiver<GrpcEvent>,
        forwarded: Vec<tokio::task::JoinHandle<()>>,
        client: tokio::task::JoinHandle<()>,
        server: tokio::task::JoinHandle<()>,
    }

    impl Pair {
        async fn shutdown(self) {
            let Pair {
                commands,
                forwarded,
                client,
                server,
                ..
            } = self;
            drop(commands);
            for task in forwarded {
                task.abort();
            }
            let _ = client.await;
            let _ = server.await;
        }
    }

    async fn pair() -> Pair {
        let (client_in_tx, client_in_rx) = mpsc::channel(16);
        let (client_out_tx, client_out_rx) = mpsc::channel::<GrpcOutput>(16);
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let (commands_tx, commands_rx) = mpsc::channel(4);

        let client = tokio::spawn(OafGrpcRoute::start_client(
            client_in_rx,
            client_out_tx,
            commands_rx,
            events_tx,
            None,
            9,
        ));

        // The peer answers list the client's session and vice versa, so the
        // forwarding tasks own the halves they move.
        let (server_in_tx, server_in_rx) = mpsc::channel(16);
        let (server_out_tx, server_out_rx) = mpsc::channel::<GrpcOutput>(16);
        let (server_events_tx, server_events_rx) = mpsc::channel(8);
        let server = tokio::spawn(OafGrpcRoute::start_server(
            server_in_rx,
            server_out_tx,
            server_events_tx,
            None,
            77,
        ));

        let forward = |mut from: mpsc::Receiver<GrpcOutput>, to: mpsc::Sender<Vec<u8>>| {
            tokio::spawn(async move {
                while let Some(output) = from.recv().await {
                    if to.send(output.bytes).await.is_err() {
                        break;
                    }
                }
            })
        };
        let forwarded = vec![
            forward(client_out_rx, server_in_tx),
            forward(server_out_rx, client_in_tx),
        ];

        let ready = timeout(Duration::from_secs(2), events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(ready, GrpcEvent::Ready { session_id: 9 }));

        Pair {
            commands: commands_tx,
            server_events: server_events_rx,
            forwarded,
            client,
            server,
        }
    }

    /// One `copyToClip` RPC carrying `payload` as its single request message.
    fn copy_to_clip_frames(stream: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = frame(
            stream,
            ICDF_CMD_HEAD,
            &icdf_head_body("ClipBoardService/copyToClip", &[], ""),
        );
        bytes.extend(frame(stream, ICDF_CMD_DATA, &icdf_data_body(0, payload)));
        bytes.extend(frame(stream, ICDF_CMD_HALF_CLOSE, &[]));
        bytes
    }

    #[tokio::test]
    async fn client_copy_to_clip_reaches_the_server() {
        let mut link = pair().await;

        // Two RPCs in a row: the client must release the stream after the phone's
        // `0x03` close, otherwise the second command is dropped.
        for text in ["hello", "again"] {
            link.commands
                .send(GrpcCommand::SendText(text.into()))
                .await
                .unwrap();
            let event = timeout(Duration::from_secs(2), link.server_events.recv())
                .await
                .unwrap()
                .unwrap();
            match event {
                GrpcEvent::RemoteText {
                    session_id,
                    text: received,
                } => {
                    assert_eq!(session_id, 77);
                    assert_eq!(received.as_str(), text);
                }
                other => panic!("unexpected event: {other:?}"),
            }
        }

        link.shutdown().await;
    }

    #[tokio::test]
    async fn oversized_send_text_is_dropped_and_the_route_survives() {
        let mut link = pair().await;

        // Larger than one OAF frame can carry: panta would drop the frame,
        // leaving this RPC `active` forever and every later copy queued behind
        // it.
        let oversized = "x".repeat(MAX_ICDF_MESSAGE_SIZE);
        link.commands
            .send(GrpcCommand::SendText(oversized))
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(300), link.server_events.recv())
                .await
                .is_err(),
            "an unframeable command must never reach the peer"
        );

        // The route is still usable, so the next copy goes through.
        link.commands
            .send(GrpcCommand::SendText("after".into()))
            .await
            .unwrap();
        let event = timeout(Duration::from_secs(2), link.server_events.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            event,
            GrpcEvent::RemoteText { text, .. } if text.as_str() == "after"
        ));

        link.shutdown().await;
    }

    /// Stream ids of the `head`/`data`/`half-close` frames one RPC emits.
    async fn rpc_streams(out: &mut mpsc::Receiver<GrpcOutput>) -> Vec<u16> {
        let mut streams = Vec::new();
        for _ in 0..3 {
            let output = timeout(Duration::from_secs(2), out.recv())
                .await
                .expect("the RPC must be written")
                .expect("the route must stay alive");
            streams.push(u16::from_be_bytes([output.bytes[8], output.bytes[9]]));
        }
        streams
    }

    #[tokio::test]
    async fn silent_peer_does_not_wedge_the_client() {
        tokio::time::pause();

        let (_in_tx, in_rx) = mpsc::channel(8);
        let (out_tx, mut out_rx) = mpsc::channel::<GrpcOutput>(16);
        let (events_tx, mut events) = mpsc::channel(8);
        let (commands, commands_rx) = mpsc::channel(8);
        let client = tokio::spawn(OafGrpcRoute::start_client(
            in_rx,
            out_tx,
            commands_rx,
            events_tx,
            None,
            9,
        ));
        assert!(matches!(
            events.recv().await.unwrap(),
            GrpcEvent::Ready { session_id: 9 }
        ));
        // The RPC method table is published before the first request.
        let config = out_rx.recv().await.unwrap();
        assert!(!config.bytes.is_empty());

        commands
            .send(GrpcCommand::SendText("one".into()))
            .await
            .unwrap();
        assert_eq!(rpc_streams(&mut out_rx).await, vec![1, 1, 1]);

        // The peer never answers. Without the reply timeout `active` would stay
        // set and every later command would queue behind it forever.
        tokio::time::advance(RPC_REPLY_TIMEOUT + Duration::from_millis(1)).await;
        tokio::time::resume();

        commands
            .send(GrpcCommand::SendText("two".into()))
            .await
            .unwrap();
        assert_eq!(rpc_streams(&mut out_rx).await, vec![3, 3, 3]);

        drop(commands);
        let _ = client.await;
    }

    #[tokio::test]
    async fn non_utf8_copy_to_clip_keeps_the_server_running() {
        let (inbound, inbound_rx) = mpsc::channel(8);
        let (outbound, mut outbound_rx) = mpsc::channel::<GrpcOutput>(8);
        let (events, mut events_rx) = mpsc::channel(8);
        let server = tokio::spawn(OafGrpcRoute::start_server(
            inbound_rx, outbound, events, None, 77,
        ));
        let drain = tokio::spawn(async move { while outbound_rx.recv().await.is_some() {} });

        // `ClipData { data: [0xff, 0xfe] }` decodes as protobuf but not as UTF-8.
        inbound
            .send(copy_to_clip_frames(1, &[0x0a, 0x02, 0xff, 0xfe]))
            .await
            .unwrap();
        // The next copy on a fresh stream must still be applied.
        inbound
            .send(copy_to_clip_frames(
                3,
                &ClipData::from_text("after").encode(),
            ))
            .await
            .unwrap();

        let event = timeout(Duration::from_secs(2), events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            event,
            GrpcEvent::RemoteText { text, .. } if text.as_str() == "after"
        ));

        drop(inbound);
        drain.abort();
        let _ = server.await;
    }
}
