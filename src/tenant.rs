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

use crate::context::{ApiFlavor, Context};
use crate::help::help;
use reqwest;

use http::header::*;
use http::method::Method;
use http::status::StatusCode;

use serde_json::value::*;

use crate::error;
use crate::error::ErrorKind::*;

use crate::resource::{
    resource_delete, resource_get, resource_id_from_location, resource_modify, resource_url,
    AuthExt,
};

use crate::overrides::Overrides;
use crate::resource::Tracer;

type Result<T> = std::result::Result<T, error::Error>;

static KEY_ENABLED: &'static str = "enabled";
static RESOURCE_NAME: &str = "devices";

pub fn tenant(
    app: &mut App,
    matches: &ArgMatches,
    _overrides: &Overrides,
    context: &Context,
) -> Result<()> {
    let result = match matches.subcommand() {
        ("create", Some(cmd_matches)) => tenant_create(
            context,
            cmd_matches.value_of("tenant_name"),
            cmd_matches.value_of("payload"),
        )?,
        ("update", Some(cmd_matches)) => tenant_update(
            context,
            cmd_matches.value_of("tenant_name").unwrap(),
            cmd_matches.value_of("payload"),
        )?,
        ("get", Some(cmd_matches)) => {
            tenant_get(context, cmd_matches.value_of("tenant_name").unwrap())?
        }
        ("delete", Some(cmd_matches)) => {
            tenant_delete(context, cmd_matches.value_of("tenant_name").unwrap())?
        }
        ("enable", Some(cmd_matches)) => {
            tenant_enable(context, cmd_matches.value_of("tenant_name").unwrap())?
        }
        ("disable", Some(cmd_matches)) => {
            tenant_disable(context, cmd_matches.value_of("tenant_name").unwrap())?
        }
        _ => help(app)?,
    };

    Ok(result)
}

fn tenant_create(context: &Context, tenant: Option<&str>, payload: Option<&str>) -> Result<()> {
    if tenant.is_none() {
        // only works in the V1 api
        context.api_required(&[&ApiFlavor::EclipseHonoV1])?;
    }

    let url = resource_url(context, RESOURCE_NAME, tenant)?;

    let payload = match payload {
        Some(_) => serde_json::from_str(payload.unwrap())?,
        _ => serde_json::value::Map::new(),
    };

    let client = reqwest::Client::new();

    let tenant = client
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
            StatusCode::CONFLICT => Err(AlreadyExists(tenant.unwrap().to_string()).into()),
            StatusCode::BAD_REQUEST => Err(MalformedRequest.into()),
            _ => Err(UnexpectedResult(response.status()).into()),
        })
        .and_then(|response| resource_id_from_location(response))?;

    println!("Created tenant: {}", tenant);

    return Ok(());
}

fn tenant_update(context: &Context, tenant: &str, payload: Option<&str>) -> Result<()> {
    let url = resource_url(context, RESOURCE_NAME, Some(tenant))?;

    let mut payload = match payload {
        Some(_) => serde_json::from_str(payload.unwrap())?,
        _ => serde_json::value::Map::new(),
    };

    payload.insert(
        "tenant-id".to_string(),
        serde_json::value::to_value(tenant)?,
    );

    let client = reqwest::Client::new();

    client
        .request(Method::PUT, url)
        .apply_auth(context)
        .header(CONTENT_TYPE, "application/json")
        .json(&payload)
        .trace()
        .send()
        .map_err(error::Error::from)
        .and_then(|response| match response.status() {
            StatusCode::NO_CONTENT => Ok(response),
            StatusCode::NOT_FOUND => Err(NotFound(tenant.to_string()).into()),
            StatusCode::BAD_REQUEST => Err(MalformedRequest.into()),
            _ => Err(UnexpectedResult(response.status()).into()),
        })?;

    println!("Updated tenant: {}", tenant);

    return Ok(());
}

fn tenant_delete(context: &Context, tenant: &str) -> Result<()> {
    let url = resource_url(context, RESOURCE_NAME, Some(tenant))?;
    resource_delete(&context, &url, "Tenant", tenant)
}

fn tenant_enable(context: &Context, tenant: &str) -> Result<()> {
    let url = resource_url(context, RESOURCE_NAME, Some(tenant))?;

    resource_modify(&context, &url, &url, tenant, |payload| {
        payload.insert(KEY_ENABLED.into(), Value::Bool(true));
        Ok(())
    })?;

    println!("Tenant {} enabled", tenant);

    return Ok(());
}

fn tenant_disable(context: &Context, tenant: &str) -> Result<()> {
    let url = resource_url(context, RESOURCE_NAME, Some(tenant))?;

    resource_modify(&context, &url, &url, tenant, |payload| {
        payload.insert(KEY_ENABLED.into(), Value::Bool(false));
        Ok(())
    })?;

    println!("Tenant {} disabled", tenant);

    return Ok(());
}

fn tenant_get(context: &Context, tenant: &str) -> Result<()> {
    let url = resource_url(context, RESOURCE_NAME, Some(tenant))?;
    resource_get(&context, &url, "Tenant")
}
