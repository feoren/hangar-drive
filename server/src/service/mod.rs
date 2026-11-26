//! Business logic. The HTTP handlers only parse, call one function here and answer; every rule
//! of ADR 0001 that the server enforces lives in these modules.

pub mod accounts;
pub mod admin;
pub mod commits;
pub mod devicelog;
pub mod feed;
pub mod folders;
pub mod notices;
pub mod objects;
pub mod pairing;
pub mod records;
pub mod retention;
pub mod sessions;
pub mod usage;
