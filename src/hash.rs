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

use rand::rngs::EntropyRng;
use rand::RngCore;

pub enum HashFunction {
    Sha256,
    Sha512,
    Bcrypt,
}

use crate::error;
type Result<T> = std::result::Result<T, error::Error>;

impl std::str::FromStr for HashFunction {
    type Err = &'static str;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "sha-256" => Ok(HashFunction::Sha256),
            "sha-512" => Ok(HashFunction::Sha512),
            "bcrypt" => Ok(HashFunction::Bcrypt),
            _ => Err("Invalid value"),
        }
    }
}

fn do_hash<D: Digest + Default>(salt: &[u8], password: &str) -> (String, Option<String>) {
    let mut md = D::default();
    md.input(salt);
    md.input(password);

    let dig = md.result();

    return (base64::encode(&dig), Some(base64::encode(&salt)));
}

fn do_bcrypt(password: &str) -> Result<(String, Option<String>)> {
    let mut hash = bcrypt::hash(password, 10)?;

    hash.replace_range(1..3, "2a");

    return Ok((hash, None));
}

fn gen_salt(size: usize) -> Vec<u8> {
    let mut rnd = EntropyRng::new();
    let mut salt = vec![0; size];

    rnd.fill_bytes(&mut salt);
    salt
}

impl HashFunction {
    pub fn name(&self) -> &str {
        match self {
            HashFunction::Sha256 => "sha-256",
            HashFunction::Sha512 => "sha-512",
            HashFunction::Bcrypt => "bcrypt",
        }
    }

    pub fn hash(&self, password: &str) -> Result<(String, Option<String>)> {
        match self {
            HashFunction::Sha256 => Ok(do_hash::<Sha256>(gen_salt(16).as_slice(), password)),
            HashFunction::Sha512 => Ok(do_hash::<Sha512>(gen_salt(16).as_slice(), password)),
            HashFunction::Bcrypt => do_bcrypt(password),
        }
    }
}
