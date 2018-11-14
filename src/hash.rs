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

use crypto::digest::Digest;
use crypto::sha2::{Sha256,Sha512};

pub enum HashFunction {
    Sha256,
    Sha512,
}

impl std::str::FromStr for HashFunction {
    type Err = &'static str;

    fn from_str(s:&str) -> Result<Self, Self::Err> {
        match s {
            "sha-256" => Ok(HashFunction::Sha256),
            "sha-512" => Ok(HashFunction::Sha512),
            _ => Err("Invalid value")
        }
    }
}

impl HashFunction {

    pub fn name(&self) -> &str {
        match self {
            HashFunction::Sha256 => "sha-256",
            HashFunction::Sha512 => "sha-512",
        }
    }

    pub fn digest(&self) -> Box<Digest> {
        match self {
            HashFunction::Sha256 => Box::new(Sha256::new()),
            HashFunction::Sha512 => Box::new(Sha512::new()),
        }
    }

    pub fn hash(&self, salt: &[u8], password:&str) -> String {
        let mut md = self.digest();

        md.input(salt);
        md.input_str(password);

        let mut dig = vec![0; md.output_bytes()];
        md.result(& mut dig);

        base64::encode(&dig)
    }
}