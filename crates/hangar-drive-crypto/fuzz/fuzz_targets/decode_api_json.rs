//! The JSON of the server API (security review, info): every request and answer type the
//! server or the client reads from the other side decodes or refuses without a panic, and a
//! decoded value that validates itself is checked.
#![no_main]

use hangar_drive_protocol::api::{
    ChallengeRequest, ChallengeResponse, CommitRequest, CommitResponse, CreateAccountRequest,
    DeltaPage, ErrorBody, FeedPage, LogAppendRequest, LogPage, MissingObjectsRequest,
    PairingRequest, ProofRequest, RecordPut, RecordResponse, SessionResponse,
};
use libfuzzer_sys::fuzz_target;

fn decode<T: serde::de::DeserializeOwned>(data: &[u8]) -> Option<T> {
    serde_json::from_slice(data).ok()
}

fuzz_target!(|data: &[u8]| {
    let _ = decode::<ChallengeRequest>(data);
    let _ = decode::<ChallengeResponse>(data);
    let _ = decode::<ProofRequest>(data);
    let _ = decode::<SessionResponse>(data);
    let _ = decode::<CreateAccountRequest>(data);
    let _ = decode::<LogPage>(data);
    let _ = decode::<LogAppendRequest>(data);
    let _ = decode::<FeedPage>(data);
    let _ = decode::<DeltaPage>(data);
    let _ = decode::<CommitRequest>(data);
    let _ = decode::<CommitResponse>(data);
    let _ = decode::<MissingObjectsRequest>(data);
    let _ = decode::<RecordPut>(data);
    let _ = decode::<RecordResponse>(data);
    let _ = decode::<ErrorBody>(data);
    if let Some(request) = decode::<PairingRequest>(data) {
        let _ = request.validate();
    }
});
