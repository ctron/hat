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

use clap::{App, ArgMatches};

use help::help;
use context::Context;
use reqwest;

use http::method::Method;
use http::header::*;
use http::status::StatusCode;

use serde_json::value::*;

use hono;
use hono::ErrorKind::*;

use resource::{resource_delete, resource_get, resource_modify};

type Result<T> = std::result::Result<T, hono::Error>;

static KEY_ENABLED : &'static str = "enabled";

pub fn tenant(app: & mut App, matches: &ArgMatches, context: &Context) -> Result<()> {

    let result = match matches.subcommand() {
        ( "create", Some(cmd_matches)) => tenant_create(
            context,
            cmd_matches.value_of("tenant").unwrap(),
            cmd_matches.value_of("payload")
        )?,
        ( "update", Some(cmd_matches)) => tenant_update(
            context,
            cmd_matches.value_of("tenant").unwrap(),
            cmd_matches.value_of("payload")
        )?,
        ( "get", Some(cmd_matches)) => tenant_get(
            context,
            cmd_matches.value_of("tenant").unwrap(),
        )?,
        ( "delete", Some(cmd_matches)) => tenant_delete(
            context,
            cmd_matches.value_of("tenant").unwrap(),
        )?,
        ( "enable", Some(cmd_matches)) => tenant_enable(
            context,
            cmd_matches.value_of("tenant").unwrap(),
        )?,
        ( "disable", Some(cmd_matches)) => tenant_disable(
            context,
            cmd_matches.value_of("tenant").unwrap(),
        )?,
        _ => help(app)?
    };

    Ok(result)
}

fn tenant_url(context: &Context, tenant:Option<&str> ) -> Result<url::Url> {

    let mut url = context.to_url()?;

    {
        let mut path = url.path_segments_mut().map_err(|_| hono::ErrorKind::UrlError())?;

        path
            .push("tenant");

        tenant.map(|t| path.push(t));
    }

    return Ok(url);
}

fn tenant_create(context: &Context, tenant:&str, payload:Option<&str>) -> Result<()> {

    let url = tenant_url(context, None)?;

    let mut payload = match payload {
        Some(_) => serde_json::from_str(payload.unwrap())?,
        _ => serde_json::value::Map::new()
    };

    payload.insert("tenant-id".to_string(), serde_json::value::to_value(tenant)?);

    let client = reqwest::Client::new();

    client
        .request(Method::POST, url)
        .header(CONTENT_TYPE, "application/json" )
        .json(&payload)
        .send()
        .map_err(hono::Error::from)
        .and_then(|response|{
            match response.status() {
                StatusCode::CREATED => Ok(response),
                StatusCode::CONFLICT => Err(AlreadyExists(tenant.to_string()).into()),
                StatusCode::BAD_REQUEST => Err(MalformedRequest().into()),
                _ => Err(UnexpectedResult(response.status()).into())
            }
        })?;

    println!("Created tenant: {}", tenant);

    return Ok(());
}

fn tenant_update(context: &Context, tenant:&str, payload:Option<&str>) -> Result<()> {

    let url = tenant_url(context, Some(tenant))?;

    let mut payload = match payload {
        Some(_) => serde_json::from_str(payload.unwrap())?,
        _ => serde_json::value::Map::new()
    };

    payload.insert("tenant-id".to_string(), serde_json::value::to_value(tenant)?);

    let client = reqwest::Client::new();

    client
        .request(Method::PUT, url)
        .header(CONTENT_TYPE, "application/json" )
        .json(&payload)
        .send()
        .map_err(hono::Error::from)
        .and_then(|response|{
            match response.status() {
                StatusCode::NO_CONTENT => Ok(response),
                StatusCode::NOT_FOUND => Err(NotFound(tenant.to_string()).into()),
                StatusCode::BAD_REQUEST => Err(MalformedRequest().into()),
                _ => Err(UnexpectedResult(response.status()).into())
            }
        })?;

    println!("Updated tenant: {}", tenant);

    return Ok(());
}

fn tenant_delete(context: &Context, tenant:&str) -> Result<()> {
    let url = tenant_url(context, Some(tenant))?;
    resource_delete(&url, "Tenant", tenant)
}

fn tenant_enable(context: &Context, tenant:&str) -> Result<()> {

    let url = tenant_url(context, Some(tenant))?;

    resource_modify(&url, tenant, |payload| {
        payload.insert(KEY_ENABLED.into(), Value::Bool(true));
        Ok(())
    })?;

    println!("Tenant {} enabled", tenant);

    return Ok(());
}

fn tenant_disable(context: &Context, tenant:&str) -> Result<()> {

    let url = tenant_url(context, Some(tenant))?;

    resource_modify(&url, tenant, |payload| {
        payload.insert(KEY_ENABLED.into(), Value::Bool(false));
        Ok(())
    })?;

    println!("Tenant {} disabled", tenant);

    return Ok(());
}

fn tenant_get(context: &Context, tenant:&str) -> Result<()> {
    let url = tenant_url(context, Some(tenant))?;
    resource_get(&url, "Tenant")
}