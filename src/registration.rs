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
use http::header::CONTENT_TYPE;
use http::status::StatusCode;

use hono;
use hono::ErrorKind::*;

use resource::{resource_delete, resource_get, resource_url, AuthExt};

type Result<T> = std::result::Result<T, hono::Error>;
static RESOURCE_NAME : &str = "registration";

pub fn registration(app: & mut App, matches: &ArgMatches, context: &Context) -> Result<()> {

    let result = match matches.subcommand() {
        ( "create", Some(cmd_matches)) => registration_create(
            context,
            cmd_matches.value_of("tenant"),
            cmd_matches.value_of("device").unwrap(),
            cmd_matches.value_of("payload")
        )?,
        ( "update", Some(cmd_matches)) => registration_update(
            context,
            cmd_matches.value_of("tenant"),
            cmd_matches.value_of("device").unwrap(),
            cmd_matches.value_of("payload")
        )?,
        ( "get", Some(cmd_matches)) => registration_get(
            context,
            cmd_matches.value_of("tenant"),
            cmd_matches.value_of("device").unwrap()
        )?,
        ( "delete", Some(cmd_matches)) => registration_delete(
            context,
            cmd_matches.value_of("tenant"),
            cmd_matches.value_of("device").unwrap()
        )?,
        _ => help(app)?
    };

    Ok(result)
}

fn registration_create(context: &Context, tenant:Option<&str>, device:&str, payload:Option<&str>) -> Result<()> {

    let tenant = context.make_tenant(tenant)?;
    let url = resource_url(context, RESOURCE_NAME, &[&tenant])?;

    let mut payload = match payload {
        Some(_) => serde_json::from_str(payload.unwrap())?,
        _ => serde_json::value::Map::new()
    };

    payload.insert("device-id".to_string(), serde_json::value::to_value(device)?);

    let client = reqwest::Client::new();

    client
        .request(Method::POST, url)
        .apply_auth(context)
        .header(CONTENT_TYPE, "application/json" )
        .json(&payload)
        .send()
        .map_err(hono::Error::from)
        .and_then(|response|{
            match response.status() {
                StatusCode::CREATED => Ok(response),
                StatusCode::CONFLICT => Err(AlreadyExists(device.to_string()).into()),
                StatusCode::BAD_REQUEST => Err(MalformedRequest().into()),
                _ => Err(UnexpectedResult(response.status()).into())
            }
        })?;

    println!("Registered device: {}", tenant);

    return Ok(());
}


fn registration_update(context: &Context, tenant:Option<&str>, device:&str, payload:Option<&str>) -> Result<()> {

    let tenant = context.make_tenant(tenant)?;
    let url = resource_url(context, RESOURCE_NAME, &[&tenant, &device.to_string()])?;

    let mut payload = match payload {
        Some(_) => serde_json::from_str(payload.unwrap())?,
        _ => serde_json::value::Map::new()
    };

    payload.insert("device-id".to_string(), serde_json::value::to_value(device)?);

    let client = reqwest::Client::new();

    client
        .request(Method::PUT, url)
        .apply_auth(context)
        .header(CONTENT_TYPE, "application/json" )
        .json(&payload)
        .send()
        .map_err(hono::Error::from)
        .and_then(|response|{
            match response.status() {
                StatusCode::NO_CONTENT => Ok(response),
                StatusCode::NOT_FOUND => Err(NotFound(device.to_string()).into()),
                StatusCode::BAD_REQUEST => Err(MalformedRequest().into()),
                _ => Err(UnexpectedResult(response.status()).into())
            }
        })?;

    println!("Updated device registration: {}", tenant);

    return Ok(());
}

fn registration_delete(context: &Context, tenant:Option<&str>, device:&str) -> Result<()> {
    let url = resource_url(context, RESOURCE_NAME, &[&context.make_tenant(tenant)?, &device.into()])?;
    resource_delete(&context, &url, "Registration", &device)
}

fn registration_get(context: &Context, tenant:Option<&str>, device:&str) -> Result<()> {
    let url = resource_url(context, RESOURCE_NAME, &[&context.make_tenant(tenant)?, &device.into()])?;
    resource_get(&context, &url, "Registration")
}