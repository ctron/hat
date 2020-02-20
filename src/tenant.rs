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

use http::header::*;
use http::method::Method;
use http::status::StatusCode;

use serde_json::value::*;

use crate::error;
use crate::error::ErrorKind::*;

use crate::resource::{
    resource_delete, resource_err_bad_request, resource_get, resource_id_from_location,
    resource_modify, resource_url, AuthExt,
};

use crate::client::Client;
use crate::overrides::Overrides;
use crate::resource::Tracer;

type Result<T> = std::result::Result<T, error::Error>;

static KEY_ENABLED: &str = "enabled";
static RESOURCE_NAME: &str = "devices";

pub fn tenant(
    app: &mut App,
    matches: &ArgMatches,
    overrides: &Overrides,
    context: &Context,
) -> Result<()> {
    let client = Client::new(context, overrides)?;

    match matches.subcommand() {
        ("create", Some(cmd_matches)) => tenant_create(
            context,
            overrides,
            cmd_matches.value_of("tenant_name"),
            cmd_matches.value_of("payload"),
        )?,
        ("update", Some(cmd_matches)) => tenant_update(
            context,
            overrides,
            cmd_matches.value_of("tenant_name").unwrap(),
            cmd_matches.value_of("payload"),
        )?,
        ("get", Some(cmd_matches)) => tenant_get(
            context,
            overrides,
            cmd_matches.value_of("tenant_name").unwrap(),
        )?,
        ("delete", Some(cmd_matches)) => tenant_delete(
            context,
            overrides,
            cmd_matches.value_of("tenant_name").unwrap(),
        )?,
        ("enable", Some(cmd_matches)) => tenant_enable(
            &client,
            context,
            overrides,
            cmd_matches.value_of("tenant_name").unwrap(),
        )?,
        ("disable", Some(cmd_matches)) => tenant_disable(
            &client,
            context,
            overrides,
            cmd_matches.value_of("tenant_name").unwrap(),
        )?,
        _ => help(app)?,
    };

    Ok(())
}

fn tenant_create(
    context: &Context,
    overrides: &Overrides,
    tenant: Option<&str>,
    payload: Option<&str>,
) -> Result<()> {
    if tenant.is_none() {
        // only works in the V1 api
        context.api_required(&[ApiFlavor::EclipseHonoV1])?;
    }

    let url = resource_url(context, overrides, RESOURCE_NAME, tenant)?;

    let payload = match payload {
        Some(_) => serde_json::from_str(payload.unwrap())?,
        _ => serde_json::value::Map::new(),
    };

    let client = context.create_client(overrides)?;

    let tenant = client
        .request(Method::POST, url)
        .apply_auth(context)?
        .header(CONTENT_TYPE, "application/json")
        .json(&payload)
        .trace()
        .send()
        .trace()
        .map_err(error::Error::from)
        .and_then(|mut response| match response.status() {
            StatusCode::CREATED => Ok(response),
            StatusCode::CONFLICT => Err(AlreadyExists(tenant.unwrap().to_string()).into()),
            StatusCode::BAD_REQUEST => resource_err_bad_request(&mut response),
            _ => Err(UnexpectedResult(response.status()).into()),
        })
        .and_then(resource_id_from_location)?;

    println!("Created tenant: {}", tenant);

    Ok(())
}

fn tenant_update(
    context: &Context,
    overrides: &Overrides,
    tenant: &str,
    payload: Option<&str>,
) -> Result<()> {
    let url = resource_url(context, overrides, RESOURCE_NAME, Some(tenant))?;

    let mut payload = match payload {
        Some(_) => serde_json::from_str(payload.unwrap())?,
        _ => serde_json::value::Map::new(),
    };

    payload.insert(
        "tenant-id".to_string(),
        serde_json::value::to_value(tenant)?,
    );

    let client = context.create_client(overrides)?;

    client
        .request(Method::PUT, url)
        .apply_auth(context)?
        .header(CONTENT_TYPE, "application/json")
        .json(&payload)
        .trace()
        .send()
        .map_err(error::Error::from)
        .and_then(|mut response| match response.status() {
            StatusCode::NO_CONTENT => Ok(response),
            StatusCode::NOT_FOUND => Err(NotFound(tenant.to_string()).into()),
            StatusCode::BAD_REQUEST => resource_err_bad_request(&mut response),
            _ => Err(UnexpectedResult(response.status()).into()),
        })?;

    println!("Updated tenant: {}", tenant);

    Ok(())
}

fn tenant_delete(context: &Context, overrides: &Overrides, tenant: &str) -> Result<()> {
    let url = resource_url(context, overrides, RESOURCE_NAME, Some(tenant))?;
    resource_delete(&context, overrides, &url, "Tenant", tenant)
}

fn tenant_enable(
    client: &Client,
    context: &Context,
    overrides: &Overrides,
    tenant: &str,
) -> Result<()> {
    let url = resource_url(context, overrides, RESOURCE_NAME, Some(tenant))?;

    resource_modify(
        client,
        &context,
        &url,
        &url,
        tenant,
        |payload: &mut Map<String, Value>| {
            payload.insert(KEY_ENABLED.into(), Value::Bool(true));
            Ok(())
        },
    )?;

    println!("Tenant {} enabled", tenant);

    Ok(())
}

fn tenant_disable(
    client: &Client,
    context: &Context,
    overrides: &Overrides,
    tenant: &str,
) -> Result<()> {
    let url = resource_url(context, overrides, RESOURCE_NAME, Some(tenant))?;

    resource_modify(
        client,
        &context,
        &url,
        &url,
        tenant,
        |payload: &mut Map<String, Value>| {
            payload.insert(KEY_ENABLED.into(), Value::Bool(false));
            Ok(())
        },
    )?;

    println!("Tenant {} disabled", tenant);

    Ok(())
}

fn tenant_get(context: &Context, overrides: &Overrides, tenant: &str) -> Result<()> {
    let url = resource_url(context, overrides, RESOURCE_NAME, Some(tenant))?;
    resource_get(&context, overrides, &url, "Tenant")
}
