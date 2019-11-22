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

use std::fmt;

use serde_json::value::{Map, Value};

pub enum HashFunction {
    Plain,
    Sha256,
    Sha512,
    Bcrypt(u8),
}

use crate::error;
type Result<T> = std::result::Result<T, error::Error>;

impl std::str::FromStr for HashFunction {
    type Err = &'static str;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "plain" => Ok(HashFunction::Plain),
            "sha-256" => Ok(HashFunction::Sha256),
            "sha-512" => Ok(HashFunction::Sha512),
            "bcrypt" => Ok(HashFunction::Bcrypt(10)),
            _ => HashFunction::from_bcrypt(s).unwrap_or_else(|| Err("Unknown hash function")),
        }
    }
}

impl fmt::Display for HashFunction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HashFunction::Plain => write!(f, "plain"),
            HashFunction::Sha256 => write!(f, "sha-256"),
            HashFunction::Sha512 => write!(f, "sha-512"),
            HashFunction::Bcrypt(i) => write!(f, "bcrypt:{}", i),
        }
    }
}

fn do_hash<D: Digest + Default>(salt: &[u8], password: &str) -> (String, Option<String>) {
    let mut md = D::default();
    md.input(salt);
    md.input(password);

    let dig = md.result();

    (base64::encode(&dig), Some(base64::encode(&salt)))
}

fn do_bcrypt(password: &str, iterations: u8) -> Result<(String, Option<String>)> {
    let mut hash = bcrypt::hash(password, u32::from(iterations))?;

    hash.replace_range(1..3, "2a");

    Ok((hash, None))
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
            HashFunction::Plain => "plain",
            HashFunction::Sha256 => "sha-256",
            HashFunction::Sha512 => "sha-512",
            HashFunction::Bcrypt(_) => "bcrypt", // we omit the iterations here
        }
    }

    fn from_bcrypt(s: &str) -> Option<std::result::Result<HashFunction, &'static str>> {
        let v: Vec<&str> = s.splitn(2, ':').collect();

        match (v.get(0), v.get(1)) {
            (Some(t), None) if *t == "bcrypt" => Some(Ok(HashFunction::Bcrypt(10))),
            (Some(t), Some(i)) if *t == "bcrypt" => {
                let iter = i.parse::<u8>();

                Some(
                    iter.map(HashFunction::Bcrypt)
                        .map_err(|_| "Failed to parse number of iterations"),
                )
            }
            _ => None,
        }
    }

    fn insert_hash<D: Digest + Default>(
        &self,
        new_pair: &mut Map<String, Value>,
        password: &str,
    ) -> Result<()> {
        new_pair.insert("hash-function".into(), self.name().into());
        let r = do_hash::<D>(gen_salt(16).as_slice(), password);
        new_pair.insert("pwd-hash".into(), r.0.into());
        if let Some(salt) = r.1 {
            new_pair.insert("salt".into(), salt.into());
        }
        Ok(())
    }

    fn insert_bcrypt(
        &self,
        new_pair: &mut Map<String, Value>,
        password: &str,
        i: u8,
    ) -> Result<()> {
        new_pair.insert("hash-function".into(), self.name().into());
        let r = do_bcrypt(password, i)?;
        new_pair.insert("pwd-hash".into(), r.0.into());
        Ok(())
    }

    pub fn insert(&self, new_pair: &mut Map<String, Value>, password: &str) -> Result<()> {
        match self {
            HashFunction::Plain => {
                new_pair.insert("pwd-plain".into(), password.into());
                Ok(())
            }
            HashFunction::Sha256 => self.insert_hash::<Sha256>(new_pair, password),
            HashFunction::Sha512 => self.insert_hash::<Sha512>(new_pair, password),
            HashFunction::Bcrypt(i) => self.insert_bcrypt(new_pair, password, *i),
        }
    }
}
