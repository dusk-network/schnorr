// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "std")]
use std::fmt;

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// Standard error for the interface
pub enum Error {
    /// Invalid secret key
    InvalidSeed,
    /// Invalid data as an output
    InvalidData,
    /// Invalid signature
    InvalidSignature,
    /// Serialisation error
    SerialisationError
}

#[cfg(feature = "std")]
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Schnorr Signature Error: {:?}", &self)
    }
}
