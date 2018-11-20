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

use url;

use http::Method;
use http::StatusCode;
use http::header::CONTENT_TYPE;

use error::{self};
use error::ErrorKind::{UnexpectedResult, NotFound, MalformedRequest};

use context::Context;

use serde_json::{Map,Value};

type Result<T> = std::result::Result<T, error::Error>;

pub trait AuthExt {
    fn apply_auth ( self, context:&Context ) -> Self;
}

impl AuthExt for reqwest::RequestBuilder {
    fn apply_auth ( self, context:&Context ) -> Self {

        if context.username().is_some() && context.password().is_some() {

            self.basic_auth(context.username().unwrap(), context.password())

        } else {

            self

        }
    }
}

pub trait Tracer {
    fn trace(self) -> Self;
}

impl Tracer for reqwest::RequestBuilder {
    fn trace ( self, ) -> Self {
        info!("{:#?}", self);
        self
    }
}

pub fn resource_url<S:ToString+Sized>(context: &Context, resource: &str, segments: &[&S]) -> Result<url::Url> {
    let mut url = context.to_url()?;

    {
        let mut path = url.path_segments_mut().map_err(|_| error::ErrorKind::UrlError())?;
        path.push(resource);

        for seg in segments {
            path.push(seg.to_string().as_str());
        }
    }

    return Ok(url);
}

pub fn resource_delete(context:&Context, url: &url::Url, resource_type: &str, resource_name: &str) -> Result<()> {

    let client = reqwest::Client::new();

    client
        .request(Method::DELETE, url.clone())
        .apply_auth(context)
        .send()
        .map_err(error::Error::from)
        .and_then(|response|{
            match response.status() {
                StatusCode::NO_CONTENT => Ok(response),
                StatusCode::NOT_FOUND => Ok(response),
                _ => Err(UnexpectedResult(response.status()).into())
            }
        })?;

    println!("{} deleted: {}", resource_type, resource_name);

    return Ok(());
}

pub fn resource_get(context:&Context, url: &url::Url, resource_type: &str) -> Result<()> {

    let client = reqwest::Client::new();

    let result :serde_json::value::Value = client
        .request(Method::GET, url.clone())
        .apply_auth(context)
        .trace()
        .send()
        .map_err(error::Error::from)
        .and_then(|response|{
            match response.status() {
                StatusCode::OK => Ok(response),
                StatusCode::NOT_FOUND => Err(NotFound(resource_type.to_string()).into()),
                _ => Err(UnexpectedResult(response.status()).into())
            }
        })?
        .json()?;

    println!("{}", ::serde_json::to_string_pretty(&result)?);

    Ok(())

}

pub fn resource_modify_with_create<C, F>(context:&Context, url:&url::Url, resource_name: &str, creator: C, modifier : F) -> Result<reqwest::Response>
    where
        F: Fn(& mut Map<String,Value>) -> Result<()>,
        C: Fn() -> Result<Map<String,Value>>
{

    let client = reqwest::Client::new();

    // get

    let mut payload : Map<String,Value> = client
        .request(Method::GET, url.clone())
        .apply_auth(context)
        .trace()
        .send()
        .map_err(error::Error::from)
        .and_then(|mut response|{
            match response.status() {
                StatusCode::OK => response.json().map_err(error::Error::from),
                StatusCode::NOT_FOUND => creator(),
                _ => Err(UnexpectedResult(response.status()).into())
            }
        })?;

    // call consumer

    modifier(& mut payload)?;

    // update

    client
        .request(Method::PUT, url.clone())
        .apply_auth(context)
        .header(CONTENT_TYPE, "application/json" )
        .json(&payload)
        .trace()
        .send()
        .map_err(error::Error::from)
        .and_then(|response|{
            match response.status() {
                StatusCode::NO_CONTENT => Ok(response),
                StatusCode::NOT_FOUND => Err(NotFound(resource_name.into()).into()),
                StatusCode::BAD_REQUEST => Err(MalformedRequest().into()),
                _ => Err(UnexpectedResult(response.status()).into())
            }
        })
}

pub fn resource_modify<F>(context:&Context, url:&url::Url, resource_name: &str, modifier : F) -> Result<reqwest::Response>
    where F: Fn(& mut Map<String,Value>) -> Result<()>  {

    resource_modify_with_create(context, url, resource_name, || Err(NotFound(resource_name.into()).into()), modifier)
}