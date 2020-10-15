// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
/// Standard error for the interface
pub enum Error {
    /// Cryptographic invalidity
    #[error("Generic Error in signature scheme")]
    Generic,
    /// Invalid secret key
    #[error("Invalid seed provided to generate Secret key")]
    InvalidSeed,
    /// Invalid data as an output
    #[error("Invalid data gievn for signature")]
    InvalidData,
    /// Invalid signature
    #[error("Invalid signature for verification")]
    InvalidSignature,
}

impl Error {
    /// Return a generic error from any type. Represents a cryptographic mistake
    pub fn generic<T>(_e: T) -> Error {
        Error::Generic
    }
}

impl Into<io::Error> for Error {
    fn into(self) -> io::Error {
        match self {
            _ => io::Error::new(io::ErrorKind::Other, format!("{}", self)),
        }
    }
}
