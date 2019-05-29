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

use clap::{App, ArgMatches};

use crate::context::Context;
use crate::help::help;
use reqwest;

use http::header::CONTENT_TYPE;
use http::method::Method;
use http::status::StatusCode;

use crate::error;
use crate::error::ErrorKind::*;

use crate::utils::Either;

use crate::overrides::Overrides;
use crate::resource::Tracer;
use crate::resource::{
    resource_append_path, resource_delete, resource_get, resource_id_from_location,
    resource_modify, resource_url, AuthExt,
};

type Result<T> = std::result::Result<T, error::Error>;
const RESOURCE_NAME: &'static str = "devices";
const RESOURCE_LABEL: &'static str = "Device";
const PROP_ENABLED: &'static str = "enabled";

pub fn registration(
    app: &mut App,
    matches: &ArgMatches,
    overrides: &Overrides,
    context: &Context,
) -> Result<()> {
    let result = match matches.subcommand() {
        ("create", Some(cmd_matches)) => registration_create(
            context,
            overrides,
            cmd_matches.value_of("device"),
            cmd_matches.value_of("payload"),
        )?,
        ("update", Some(cmd_matches)) => registration_update(
            context,
            overrides,
            cmd_matches.value_of("device").unwrap(),
            cmd_matches.value_of("payload"),
        )?,
        ("get", Some(cmd_matches)) => {
            registration_get(context, overrides, cmd_matches.value_of("device").unwrap())?
        }
        ("delete", Some(cmd_matches)) => {
            registration_delete(context, overrides, cmd_matches.value_of("device").unwrap())?
        }
        ("enable", Some(cmd_matches)) => registration_enable(
            context,
            overrides,
            cmd_matches.value_of("device").unwrap(),
            true,
        )?,
        ("disable", Some(cmd_matches)) => registration_enable(
            context,
            overrides,
            cmd_matches.value_of("device").unwrap(),
            false,
        )?,
        _ => help(app)?,
    };

    Ok(result)
}

fn registration_create(
    context: &Context,
    overrides: &Overrides,
    device: Option<&str>,
    payload: Option<&str>,
) -> Result<()> {
    let tenant = context.make_tenant(overrides)?;
    let url = resource_url(context, RESOURCE_NAME, &[&tenant])?;

    // if we have a pre-defined id, use it
    debug!("Device ID: {:?}", device);
    let url = resource_append_path(url, device)?;
    debug!("URL: {:?}", url);

    let payload = match payload {
        Some(_) => serde_json::from_str(payload.unwrap())?,
        _ => serde_json::value::Map::new(),
    };

    let client = reqwest::Client::new();

    let device = client
        .request(Method::POST, url)
        .apply_auth(context)
        .header(CONTENT_TYPE, "application/json")
        .json(&payload)
        .trace()
        .send()
        .trace()
        .map_err(error::Error::from)
        .and_then(|response| match response.status() {
            StatusCode::CREATED => Ok(response),
            StatusCode::CONFLICT => Err(AlreadyExists(device.unwrap().to_string()).into()),
            StatusCode::BAD_REQUEST => Err(MalformedRequest.into()),
            _ => Err(UnexpectedResult(response.status()).into()),
        })
        .and_then(|response| resource_id_from_location(response))?;

    println!("Registered device {} for tenant {}", device, tenant);

    return Ok(());
}

fn registration_update(
    context: &Context,
    overrides: &Overrides,
    device: &str,
    payload: Option<&str>,
) -> Result<()> {
    let tenant = context.make_tenant(overrides)?;
    let url = resource_url(context, RESOURCE_NAME, &[&tenant, &device.to_string()])?;

    let payload = match payload {
        Some(_) => serde_json::from_str(payload.unwrap())?,
        _ => serde_json::value::Map::new(),
    };

    let client = reqwest::Client::new();

    client
        .request(Method::PUT, url)
        .apply_auth(context)
        .header(CONTENT_TYPE, "application/json")
        .json(&payload)
        .trace()
        .send()
        .trace()
        .map_err(error::Error::from)
        .and_then(|response| match response.status() {
            StatusCode::NO_CONTENT => Ok(response),
            StatusCode::NOT_FOUND => Err(NotFound(device.to_string()).into()),
            StatusCode::BAD_REQUEST => Err(MalformedRequest.into()),
            _ => Err(UnexpectedResult(response.status()).into()),
        })?;

    println!("Updated device device {} for tenant {}", device, tenant);

    return Ok(());
}

fn registration_delete(context: &Context, overrides: &Overrides, device: &str) -> Result<()> {
    let url = resource_url(
        context,
        RESOURCE_NAME,
        &[&context.make_tenant(overrides)?, &device.into()],
    )?;
    resource_delete(&context, &url, RESOURCE_LABEL, &device)
}

fn registration_get(context: &Context, overrides: &Overrides, device: &str) -> Result<()> {
    let url = resource_url(
        context,
        RESOURCE_NAME,
        &[&context.make_tenant(overrides)?, &device.into()],
    )?;
    resource_get(&context, &url, RESOURCE_LABEL)
}

fn registration_enable(
    context: &Context,
    overrides: &Overrides,
    device: &str,
    status: bool,
) -> Result<()> {
    let url = resource_url(
        context,
        RESOURCE_NAME,
        &[&context.make_tenant(overrides)?, &device.into()],
    )?;

    resource_modify(&context, &url, &url, RESOURCE_LABEL, |reg| {
        reg.insert(PROP_ENABLED.into(), serde_json::value::Value::Bool(status));
        Ok(())
    })?;

    println!(
        "Registration for device {} {}",
        device,
        status.either("enabled", "disabled")
    );

    Ok(())
}
