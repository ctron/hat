/*******************************************************************************
 * Copyright (c) 2018 Red Hat Inc
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/

use sha2::Digest;
use sha2::{Sha256, Sha512};

pub enum HashFunction {
    Sha256,
    Sha512,
}

impl std::str::FromStr for HashFunction {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sha-256" => Ok(HashFunction::Sha256),
            "sha-512" => Ok(HashFunction::Sha512),
            _ => Err("Invalid value")
        }
    }
}

fn do_hash<D: Digest + Default>(salt: &[u8], password: &str) -> String {
    let mut md = D::default();
    md.input(salt);
    md.input(password);
    let dig = md.result();
    base64::encode(&dig)
}

impl HashFunction {
    pub fn name(&self) -> &str {
        match self {
            HashFunction::Sha256 => "sha-256",
            HashFunction::Sha512 => "sha-512",
        }
    }

    pub fn hash(&self, salt: &[u8], password: &str) -> String {

        match self {
            HashFunction::Sha256 => do_hash::<Sha256>(salt, password),
            HashFunction::Sha512 => do_hash::<Sha512>(salt, password),
        }

    }
}