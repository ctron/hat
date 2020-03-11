/*******************************************************************************
 * Copyright (c) 2020 Red Hat Inc
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

use crate::context::Context;
use crate::error;
use crate::overrides::Overrides;

type Result<T> = std::result::Result<T, error::Error>;

pub struct Client {
    pub client: reqwest::Client,
}

impl Client {
    pub async fn new(context: &Context, overrides: &Overrides) -> Result<Self> {
        let client = context.create_client(overrides).await?;

        Ok(Client { client })
    }
}
