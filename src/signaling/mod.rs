//! Iroh signaling codecs.

pub mod codec;

// Connection-level authentication.
pub use codec::{
    decode_auth_request, decode_auth_response, encode_auth_request, encode_auth_response,
    AuthRequest, AuthResponse,
};

// Per-stream dispatch and remote-forward negotiation.
pub use codec::{
    decode_remote_forward_request, decode_remote_forward_response, decode_stream_ack,
    decode_stream_hello, encode_remote_forward_request, encode_remote_forward_response,
    encode_stream_ack, encode_stream_hello, read_length_prefixed, RemoteForwardRequest,
    RemoteForwardResponse, StreamAck, StreamHello,
};
