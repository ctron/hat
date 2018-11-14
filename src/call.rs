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

use hono;

/*
pub fn map_status_code(response: reqwest::Response) -> Result<reqwest::Response,hono::Error> {
    match response.status() {
        StatusCode::NOT_FOUND => Err(NotFound().into()),
        StatusCode::OK => Ok(response),
        StatusCode::CREATED => Ok(response),
        StatusCode::NO_CONTENT => Ok(response),
        _ => Err(UnexpectedResult(response.status()).into())
    }
}
*/

/*
pub fn call_get(url: url::Url) -> Result<reqwest::Response,hono::Error> {

    let client = reqwest::Client::new();

    client.request(Method::GET, url)
        .send()
        .map_err(hono::Error::from)
        .and_then(map_status_code)

}

pub fn call_get_json<T: for<'de> Deserialize<'de>>(url: url::Url) -> Result<T,hono::Error> {

    call_get(url)?
        .json()
        .map_err(hono::Error::from)

}
*/