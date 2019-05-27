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

use crate::help::help;

use std::collections::HashMap;

use crate::context::ApiFlavor::BoschIoTHub;
use crate::context::{ApiFlavor, Context};

use reqwest;

use http::header::*;
use http::method::Method;
use http::status::StatusCode;

use crate::error;
use crate::error::ErrorKind::*;

use crate::hash::HashFunction;

use crate::resource::{
    resource_delete, resource_get, resource_modify, resource_url, resource_url_query, AuthExt,
    Tracer,
};

use serde_json::value::{Map, Value};

use rand::{EntropyRng, RngCore};

use crate::overrides::Overrides;

use crate::utils::Either;

type Result<T> = std::result::Result<T, error::Error>;

static RESOURCE_NAME: &str = "credentials";

pub fn credentials(
    app: &mut App,
    matches: &ArgMatches,
    overrides: &Overrides,
    context: &Context,
) -> Result<()> {
    let result = match matches.subcommand() {
        ("create", Some(cmd_matches)) => credentials_create(
            context,
            overrides,
            cmd_matches.value_of("device").unwrap(),
            cmd_matches.value_of("auth-id").unwrap(),
            cmd_matches.value_of("type").unwrap(),
            cmd_matches.value_of("payload"),
        )?,
        ("update", Some(cmd_matches)) => credentials_update(
            context,
            overrides,
            cmd_matches.value_of("auth-id").unwrap(),
            cmd_matches.value_of("type").unwrap(),
            cmd_matches.value_of("payload"),
        )?,
        ("get", Some(cmd_matches)) => {
            credentials_get(context, overrides, cmd_matches.value_of("device").unwrap())?
        }
        ("get-for", Some(cmd_matches)) => credentials_get_for(
            context,
            overrides,
            cmd_matches.value_of("auth-id").unwrap(),
            cmd_matches.value_of("type").unwrap(),
        )?,
        ("delete", Some(cmd_matches)) => {
            credentials_delete(context, overrides, cmd_matches.value_of("device").unwrap())?
        }
        ("delete-for", Some(cmd_matches)) => credentials_delete_for(
            context,
            overrides,
            cmd_matches.value_of("auth-id").unwrap(),
            cmd_matches.value_of("type").unwrap(),
        )?,
        ("enable", Some(cmd_matches)) => credentials_enable(
            context,
            overrides,
            cmd_matches.value_of("auth-id").unwrap(),
            cmd_matches.value_of("type").unwrap(),
            true,
        )?,
        ("disable", Some(cmd_matches)) => credentials_enable(
            context,
            overrides,
            cmd_matches.value_of("auth-id").unwrap(),
            cmd_matches.value_of("type").unwrap(),
            false,
        )?,
        ("add-password", Some(cmd_matches)) => credentials_add_password(
            context,
            overrides,
            cmd_matches.value_of("device"),
            cmd_matches.value_of("auth-id").unwrap(),
            cmd_matches.value_of("password").unwrap(),
            &value_t!(cmd_matches.value_of("hash-function"), HashFunction).unwrap(),
            false,
            cmd_matches.is_present("no-salt"),
        )?,
        ("set-password", Some(cmd_matches)) => credentials_add_password(
            context,
            overrides,
            cmd_matches.value_of("device"),
            cmd_matches.value_of("auth-id").unwrap(),
            cmd_matches.value_of("password").unwrap(),
            &value_t!(cmd_matches.value_of("hash-function"), HashFunction).unwrap(),
            true,
            cmd_matches.is_present("no-salt"),
        )?,
        _ => help(app)?,
    };

    Ok(result)
}

fn read_url_for(
    context: &Context,
    overrides: &Overrides,
    auth_id: &str,
    type_name: &str,
) -> Result<url::Url> {
    let tenant = context.make_tenant(overrides)?;

    match context.api_flavor() {
        ApiFlavor::BoschIoTHub => {
            let mut query = HashMap::new();
            query.insert(String::from("auth-id"), auth_id.into());
            query.insert(String::from("type"), type_name.into());
            resource_url_query(context, RESOURCE_NAME, &[&tenant], Some(&query))
        }
        _ => resource_url(
            context,
            RESOURCE_NAME,
            &[&tenant, &auth_id.into(), &type_name.into()],
        ),
    }
}

fn update_url_for(
    context: &Context,
    overrides: &Overrides,
    auth_id: &str,
    type_name: &str,
) -> Result<url::Url> {
    let tenant = context.make_tenant(overrides)?;

    match context.api_flavor() {
        ApiFlavor::BoschIoTHub => resource_url(context, RESOURCE_NAME, &[&tenant]),
        _ => resource_url(
            context,
            RESOURCE_NAME,
            &[&tenant, &auth_id.into(), &type_name.into()],
        ),
    }
}

fn credentials_delete(context: &Context, overrides: &Overrides, device: &str) -> Result<()> {
    if let BoschIoTHub = context.api_flavor() {
        return Err(WrongApiFlavor.into());
    }

    let tenant = context.make_tenant(overrides)?;
    let url = resource_url(context, RESOURCE_NAME, &[&tenant, &device.into()])?;

    resource_delete(&context, &url, "Credentials", device)
}

fn credentials_delete_for(
    context: &Context,
    overrides: &Overrides,
    auth_id: &str,
    type_name: &str,
) -> Result<()> {
    let url = read_url_for(context, overrides, auth_id, type_name)?;
    resource_delete(
        &context,
        &url,
        "Credentials",
        &format!("{} / {}", auth_id, type_name),
    )
}

fn credentials_create(
    context: &Context,
    overrides: &Overrides,
    device: &str,
    auth_id: &str,
    type_name: &str,
    payload: Option<&str>,
) -> Result<()> {
    let tenant = context.make_tenant(overrides)?;
    let url = resource_url(context, RESOURCE_NAME, &[&tenant])?;

    let mut payload = match payload {
        Some(_) => serde_json::from_str(payload.unwrap())?,
        _ => serde_json::value::Map::new(),
    };

    payload.insert("device-id".into(), device.into());
    payload.insert("type".into(), type_name.into());
    payload.insert("auth-id".to_string(), auth_id.into());

    let client = reqwest::Client::new();

    client
        .request(Method::POST, url)
        .apply_auth(context)
        .header(CONTENT_TYPE, "application/json")
        .json(&payload)
        .trace()
        .send()
        .map_err(error::Error::from)
        .and_then(|response| match response.status() {
            StatusCode::CREATED => Ok(response),
            StatusCode::CONFLICT => Err(AlreadyExists(device.to_string()).into()),
            StatusCode::BAD_REQUEST => Err(MalformedRequest.into()),
            _ => Err(UnexpectedResult(response.status()).into()),
        })?;

    println!("Created device secrets: {} / {}", device, auth_id);

    return Ok(());
}

fn credentials_update(
    context: &Context,
    overrides: &Overrides,
    auth_id: &str,
    type_name: &str,
    payload: Option<&str>,
) -> Result<()> {
    let tenant = context.make_tenant(overrides)?;
    let url = resource_url(
        context,
        RESOURCE_NAME,
        &[&tenant, &auth_id.into(), &type_name.into()],
    )?; // FIXME: remove auth and type name

    let mut payload = match payload {
        Some(_) => serde_json::from_str(payload.unwrap())?,
        _ => serde_json::value::Map::new(),
    };

    payload.insert("type".into(), type_name.into());
    payload.insert("auth-id".into(), auth_id.into());

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
            StatusCode::NOT_FOUND => Err(NotFound(format!("{}/{}", auth_id, type_name)).into()),
            StatusCode::BAD_REQUEST => Err(MalformedRequest.into()),
            _ => Err(UnexpectedResult(response.status()).into()),
        })?;

    println!("Updated device secrets: {}/{}", auth_id, type_name);

    return Ok(());
}

fn credentials_get(context: &Context, overrides: &Overrides, device: &str) -> Result<()> {
    if let BoschIoTHub = context.api_flavor() {
        return Err(WrongApiFlavor.into());
    }

    let tenant = context.make_tenant(overrides)?;
    let url = resource_url(context, RESOURCE_NAME, &[&tenant, &device.into()])?;

    resource_get(&context, &url, "Credentials")
}

fn credentials_get_for(
    context: &Context,
    overrides: &Overrides,
    auth_id: &str,
    type_name: &str,
) -> Result<()> {
    let url = read_url_for(context, overrides, auth_id, type_name)?;
    resource_get(&context, &url, "Credentials")
}

fn credentials_modify<F>(
    context: &Context,
    overrides: &Overrides,
    auth_id: &str,
    type_name: &str,
    modifier: F,
) -> Result<reqwest::Response>
where
    F: Fn(&mut Map<String, Value>) -> Result<()>,
{
    let read_url = read_url_for(context, overrides, auth_id, type_name)?;
    let update_url = read_url_for(context, overrides, auth_id, type_name)?;

    resource_modify(
        &context,
        &read_url,
        &update_url,
        &format!("{}/{}", auth_id, type_name),
        modifier,
    )
}

fn credentials_enable(
    context: &Context,
    overrides: &Overrides,
    auth_id: &str,
    type_name: &str,
    state: bool,
) -> Result<()> {
    credentials_modify(context, overrides, auth_id, type_name, |payload| {
        payload.insert("enabled".into(), state.into());
        Ok(())
    })?;

    println!("Credentials {}", state.either("enabled", "disabled"));

    return Ok(());
}

fn credentials_add_password(
    context: &Context,
    overrides: &Overrides,
    device: Option<&str>,
    auth_id: &str,
    password: &str,
    hash_function: &HashFunction,
    clear: bool,
    nosalt: bool,
) -> Result<()> {
    let type_name = "hashed-password";

    let read_url = read_url_for(context, overrides, auth_id, type_name)?;
    let update_url = update_url_for(context, overrides, auth_id, type_name)?;

    let entry = new_entry(password, hash_function, nosalt);

    resource_modify(
        &context,
        &read_url,
        &update_url,
        &format!("{}/{}", auth_id, type_name),
        |payload| {
            if !payload.contains_key("secrets") {
                payload.insert("secrets".into(), Value::Array(Vec::new()));
            }

            let secrets = payload.get_mut("secrets").unwrap().as_array_mut().unwrap();

            if clear {
                secrets.clear();
            }

            secrets.push(entry.clone());

            Ok(())
        },
    )
    .and(Ok(()))
    .or_else(|err| {
        if !device.is_some() {
            return Err(err);
        }

        match err.kind() {
            NotFound(_) => {
                println!("No credential set found, creating new one.");

                let mut payload = Map::new();

                payload.insert("secrets".into(), Value::Array([entry.clone()].to_vec()));

                let payload = serde_json::to_string(&payload)?;

                credentials_create(
                    context,
                    overrides,
                    device.unwrap(),
                    auth_id,
                    type_name,
                    Some(&payload),
                )
            }
            _ => Err(err),
        }
    })?;

    if clear {
        println!("Password set for {}/{}", auth_id, type_name);
    } else {
        println!("Password added to {}/{}", auth_id, type_name);
    }

    return Ok(());
}

/// Create a new secrets entry, based on `hashed-password`
fn new_entry(plain_password: &str, hash_function: &HashFunction, nosalt: bool) -> Value {
    let mut new_pair = Map::new();

    let mut rnd = EntropyRng::new();

    let salt = match nosalt {
        true => vec![0; 0],
        false => {
            let mut salt = vec![0; 8];
            rnd.fill_bytes(&mut salt);
            salt
        }
    };

    // hash it

    let hash = hash_function.hash(&salt, &plain_password);
    let salt = base64::encode(&salt);

    // put to result

    new_pair.insert("hash-function".into(), hash_function.name().into());
    new_pair.insert("pwd-hash".into(), hash.into());
    if !nosalt {
        new_pair.insert("salt".into(), salt.into());
    }

    // return as value

    return Value::Object(new_pair);
}
