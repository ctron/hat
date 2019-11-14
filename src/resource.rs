/*******************************************************************************
 * Copyright (c) 2018, 2019 Red Hat Inc
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

use url;
use url::Url;

use std::collections::HashMap;

use http::header::{CONTENT_TYPE, ETAG, IF_MATCH, LOCATION};
use http::Method;
use http::StatusCode;

use crate::error::ErrorKind::{MalformedRequest, NotFound, Response, UnexpectedResult};

use crate::context::Context;
use crate::error;

use crate::output::display_json_value;
use crate::overrides::Overrides;
use serde::de::DeserializeOwned;
use serde::Serialize;

type Result<T> = std::result::Result<T, error::Error>;

pub trait AuthExt
where
    Self: Sized,
{
    fn apply_auth(self, context: &Context) -> Result<Self>;
}

impl AuthExt for reqwest::RequestBuilder {
    fn apply_auth(self, context: &Context) -> Result<Self> {
        if context.use_kubernetes() {
            // we already got configured, do nothing in addition
            Ok(self)
        } else if let Some(token) = context.token() {
            Ok(self.bearer_auth(token))
        } else if let Some(user) = context.username() {
            Ok(self.basic_auth(user, context.password().clone()))
        } else {
            Ok(self)
        }
    }
}

pub trait IfMatch {
    fn if_match(self, value: Option<&http::header::HeaderValue>) -> Self;
}

impl IfMatch for reqwest::RequestBuilder {
    fn if_match(self, value: Option<&http::header::HeaderValue>) -> Self {
        if let Some(etag) = value {
            self.header(IF_MATCH, etag.clone())
        } else {
            self
        }
    }
}

pub trait Tracer {
    fn trace(self) -> Self;
}

impl Tracer for reqwest::RequestBuilder {
    fn trace(self) -> Self {
        info!("{:#?}", self);
        self
    }
}

impl Tracer for reqwest::Client {
    fn trace(self) -> Self {
        info!("{:#?}", self);
        self
    }
}

impl Tracer for std::result::Result<reqwest::Response, reqwest::Error> {
    fn trace(self) -> Self {
        info!("{:#?}", self);
        self
    }
}

pub fn resource_url<S>(
    context: &Context,
    overrides: &Overrides,
    resource: &str,
    segments: S,
) -> Result<url::Url>
where
    S: IntoIterator,
    S::Item: AsRef<str>,
{
    resource_url_query(context, overrides, resource, segments, None)
}

pub fn resource_append_path<S>(url: url::Url, segments: S) -> Result<url::Url>
where
    S: IntoIterator,
    S::Item: AsRef<str>,
{
    let mut url = url.clone();
    {
        let mut path = url
            .path_segments_mut()
            .map_err(|_| error::ErrorKind::UrlError)?;

        path.extend(segments);
    }

    Ok(url)
}

pub fn resource_url_query<S>(
    context: &Context,
    overrides: &Overrides,
    resource: &str,
    segments: S,
    query: Option<&HashMap<String, String>>,
) -> Result<url::Url>
where
    S: IntoIterator,
    S::Item: AsRef<str>,
{
    let url = context.to_url(overrides)?;
    let url = resource_append_path(url, Some(resource))?;
    let mut url = resource_append_path(url, segments)?;

    if let Some(q) = query {
        let mut query = url.query_pairs_mut();
        for (name, value) in q {
            query.append_pair(name, value);
        }
    }

    Ok(url)
}

pub fn resource_delete(
    context: &Context,
    overrides: &Overrides,
    url: &url::Url,
    resource_type: &str,
    resource_name: &str,
) -> Result<()> {
    let client = context.create_client(overrides)?;

    client
        .request(Method::DELETE, url.clone())
        .apply_auth(context)?
        .trace()
        .send()
        .trace()
        .map_err(error::Error::from)
        .and_then(|response| match response.status() {
            StatusCode::NO_CONTENT => Ok(response),
            StatusCode::NOT_FOUND => Ok(response),
            _ => Err(UnexpectedResult(response.status()).into()),
        })?;

    println!("{} deleted: {}", resource_type, resource_name);

    Ok(())
}

pub fn resource_get(
    context: &Context,
    overrides: &Overrides,
    url: &url::Url,
    resource_type: &str,
) -> Result<()> {
    let client = context.create_client(overrides)?;

    let result: serde_json::value::Value = client
        .request(Method::GET, url.clone())
        .apply_auth(context)?
        .trace()
        .send()
        .trace()
        .map_err(error::Error::from)
        .and_then(|response| match response.status() {
            StatusCode::OK => Ok(response),
            StatusCode::NOT_FOUND => Err(NotFound(resource_type.to_string()).into()),
            _ => Err(UnexpectedResult(response.status()).into()),
        })?
        .json()?;

    display_json_value(&result)?;

    Ok(())
}

pub fn resource_modify_with_create<C, F, T>(
    context: &Context,
    overrides: &Overrides,
    read_url: &Url,
    update_url: &Url,
    resource_name: &str,
    creator: C,
    modifier: F,
) -> Result<reqwest::Response>
where
    F: Fn(&mut T) -> Result<()>,
    C: Fn() -> Result<T>,
    T: Serialize + DeserializeOwned + std::fmt::Debug,
{
    let client = context.create_client(overrides)?;

    // get

    let mut response = client
        .request(Method::GET, read_url.clone())
        .apply_auth(context)?
        .trace()
        .send()
        .trace()
        .map_err(error::Error::from)?;

    let mut payload: T = match response.status() {
        StatusCode::OK => response.json().map_err(error::Error::from),
        StatusCode::NOT_FOUND => creator(),
        _ => Err(UnexpectedResult(response.status()).into()),
    }?;

    info!("GET Payload: {:#?}", payload);

    // call consumer

    modifier(&mut payload)?;

    info!("PUT Payload: {:#?}", payload);

    // retrieve ETag header

    let etag = response.headers().get(ETAG);

    // update

    client
        .request(Method::PUT, update_url.clone())
        .apply_auth(context)?
        .header(CONTENT_TYPE, "application/json")
        .if_match(etag)
        .json(&payload)
        .trace()
        .send()
        .trace()
        .map_err(error::Error::from)
        .and_then(|mut response| match response.status() {
            StatusCode::NO_CONTENT => Ok(response),
            StatusCode::NOT_FOUND => Err(NotFound(resource_name.into()).into()),
            StatusCode::BAD_REQUEST => resource_err_bad_request(&mut response),
            _ => Err(UnexpectedResult(response.status()).into()),
        })
}

pub fn resource_err_bad_request<T>(response: &mut reqwest::Response) -> Result<T> {
    Err(MalformedRequest(response.text().unwrap_or_else(|_| "<unknown>".into())).into())
}

pub fn resource_modify<F, T>(
    context: &Context,
    overrides: &Overrides,
    read_url: &Url,
    update_url: &Url,
    resource_name: &str,
    modifier: F,
) -> Result<reqwest::Response>
where
    F: Fn(&mut T) -> Result<()>,
    T: Serialize + DeserializeOwned + std::fmt::Debug,
{
    resource_modify_with_create(
        context,
        overrides,
        read_url,
        update_url,
        resource_name,
        || Err(NotFound(resource_name.into()).into()),
        modifier,
    )
}

pub fn resource_id_from_location(response: reqwest::Response) -> Result<String> {
    let loc = response.headers().get(LOCATION);

    if let Some(s) = loc {
        let id: String = s.to_str()?.into();

        let s = id.split('/').last();

        s.map(|s| s.into())
            .ok_or_else(|| Response(String::from("Missing ID element in 'Location' header")).into())
    } else {
        Err(Response(String::from("Missing 'Location' header in response")).into())
    }
}
