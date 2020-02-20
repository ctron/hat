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

use crate::context::{ApiFlavor, Context};
use crate::help::help;

use serde_json::value::{Map, Value};

use http::header::CONTENT_TYPE;
use http::method::Method;
use http::status::StatusCode;

use crate::error;
use crate::error::ErrorKind::*;

use crate::utils::Either;

use crate::client::Client;
use crate::overrides::Overrides;
use crate::resource::Tracer;
use crate::resource::{
    resource_append_path, resource_delete, resource_err_bad_request, resource_get,
    resource_id_from_location, resource_modify, resource_url, AuthExt,
};

type Result<T> = std::result::Result<T, error::Error>;
const RESOURCE_NAME: &str = "devices";
const RESOURCE_LABEL: &str = "Device";
const PROP_ENABLED: &str = "enabled";
const PROP_VIA: &str = "via";

pub fn registration(
    app: &mut App,
    matches: &ArgMatches,
    overrides: &Overrides,
    context: &Context,
) -> Result<()> {
    match matches.subcommand() {
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
        ("set-via", Some(cmd_matches)) => registration_via(
            &client,
            context,
            overrides,
            cmd_matches.value_of("device").unwrap(),
            cmd_matches.values_of("via"),
        )?,
        _ => help(app)?,
    };

    Ok(())
}

fn registration_create(
    context: &Context,
    overrides: &Overrides,
    device: Option<&str>,
    payload: Option<&str>,
) -> Result<()> {
    if device.is_none() {
        // only works in the V1 api
        context.api_required(&[ApiFlavor::EclipseHonoV1])?;
    }

    let tenant = context.make_tenant(overrides)?;
    let url = resource_url(context, overrides, RESOURCE_NAME, &[&tenant])?;

    let url = resource_append_path(url, device)?;

    let payload = match payload {
        Some(_) => serde_json::from_str(payload.unwrap())?,
        _ => serde_json::value::Map::new(),
    };

    let client = context.create_client(overrides)?;

    let device = client
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
            StatusCode::CONFLICT => Err(AlreadyExists(device.unwrap().to_string()).into()),
            StatusCode::BAD_REQUEST => resource_err_bad_request(&mut response),
            _ => Err(UnexpectedResult(response.status()).into()),
        })
        .and_then(resource_id_from_location)?;

    println!("Registered device {} for tenant {}", device, tenant);

    Ok(())
}

fn registration_update(
    context: &Context,
    overrides: &Overrides,
    device: &str,
    payload: Option<&str>,
) -> Result<()> {
    let tenant = context.make_tenant(overrides)?;
    let url = resource_url(
        context,
        overrides,
        RESOURCE_NAME,
        &[&tenant, &device.into()],
    )?;

    let payload = match payload {
        Some(_) => serde_json::from_str(payload.unwrap())?,
        _ => serde_json::value::Map::new(),
    };

    let client = context.create_client(overrides)?;

    client
        .request(Method::PUT, url)
        .apply_auth(context)?
        .header(CONTENT_TYPE, "application/json")
        .json(&payload)
        .trace()
        .send()
        .trace()
        .map_err(error::Error::from)
        .and_then(|mut response| match response.status() {
            StatusCode::NO_CONTENT => Ok(response),
            StatusCode::NOT_FOUND => Err(NotFound(device.to_string()).into()),
            StatusCode::BAD_REQUEST => resource_err_bad_request(&mut response),
            _ => Err(UnexpectedResult(response.status()).into()),
        })?;

    println!("Updated device device {} for tenant {}", device, tenant);

    Ok(())
}

fn registration_delete(context: &Context, overrides: &Overrides, device: &str) -> Result<()> {
    let url = resource_url(
        context,
        overrides,
        RESOURCE_NAME,
        &[&context.make_tenant(overrides)?, &device.into()],
    )?;
    resource_delete(&context, overrides, &url, RESOURCE_LABEL, &device)
}

fn registration_get(context: &Context, overrides: &Overrides, device: &str) -> Result<()> {
    let url = resource_url(
        context,
        overrides,
        RESOURCE_NAME,
        &[&context.make_tenant(overrides)?, &device.into()],
    )?;
    resource_get(&context, overrides, &url, RESOURCE_LABEL)
}

fn registration_enable(
    context: &Context,
    overrides: &Overrides,
    device: &str,
    status: bool,
) -> Result<()> {
    let client = Client::new(context, overrides)?;

    let url = resource_url(
        context,
        overrides,
        RESOURCE_NAME,
        &[&context.make_tenant(overrides)?, &device.into()],
    )?;

    resource_modify(
        &client,
        &context,
        &url,
        &url,
        RESOURCE_LABEL,
        |reg: &mut Map<String, Value>| {
            reg.insert(PROP_ENABLED.into(), serde_json::value::Value::Bool(status));
            Ok(())
        },
    )?;

    println!(
        "Registration for device {} {}",
        device,
        status.either("enabled", "disabled")
    );

    Ok(())
}

fn registration_url<S>(context: &Context, overrides: &Overrides, device: S) -> Result<url::Url>
where
    S: Into<String>,
{
    resource_url(
        context,
        overrides,
        RESOURCE_NAME,
        &[&context.make_tenant(overrides)?, &device.into()],
    )
}

fn registration_via(
    client: &Client,
    context: &Context,
    overrides: &Overrides,
    device: &str,
    via: Option<clap::Values>,
) -> Result<()> {
    let url = registration_url(context, overrides, device)?;

    resource_modify(
        client,
        &context,
        &url,
        &url,
        RESOURCE_LABEL,
        |reg: &mut Map<String, Value>| {
            match via {
                None => {
                    reg.remove(PROP_VIA.into());
                }
                Some(ref v) => {
                    let json = serde_json::value::to_value::<Vec<&str>>(v.clone().collect())?;
                    reg.insert(PROP_VIA.into(), json);
                }
            };

            Ok(())
        },
    )?;

    match via {
        None => println!("Gateways cleared for device {}", device),
        Some(v) => {
            println!(
                "Gateway(s) set for device {} {:#?}",
                device,
                v.collect::<Vec<&str>>()
            );
        }
    }

    Ok(())
}
