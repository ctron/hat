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

use clap::value_t;
use clap::{App, ArgMatches};

use log::{debug, info};

use crate::help::help;

use crate::context::Context;

use http::header::*;
use http::method::Method;
use http::status::StatusCode;

use crate::error;
use crate::error::ErrorKind::*;

use crate::hash::HashFunction;

use crate::resource::{
    resource_err_bad_request, resource_get, resource_modify, resource_url, AuthExt, Tracer,
};

use serde_json::value::{Map, Value};

use crate::client::Client;
use crate::overrides::Overrides;
use failure::Fail;
use futures::executor::block_on;

type Result<T> = std::result::Result<T, error::Error>;

static RESOURCE_NAME: &str = "credentials";
static TYPE_HASHED_PASSWORD: &str = "hashed-password";
static TYPE_PSK: &str = "psk";
static TYPE_X509: &str = "x509-cert";

pub async fn credentials(
    app: &mut App<'_, '_>,
    matches: &ArgMatches<'_>,
    overrides: &Overrides,
    context: &Context,
) -> Result<()> {
    let client = Client::new(context, overrides).await?;

    match matches.subcommand() {
        ("set", Some(cmd_matches)) => {
            credentials_set(
                context,
                overrides,
                cmd_matches.value_of("device").unwrap(),
                cmd_matches.value_of("payload"),
            )
            .await?
        }
        ("get", Some(cmd_matches)) => {
            credentials_get(context, overrides, cmd_matches.value_of("device").unwrap()).await?
        }
        ("add-password", Some(cmd_matches)) => {
            credentials_add_password(
                &client,
                context,
                overrides,
                cmd_matches.value_of("device").unwrap(),
                cmd_matches.value_of("auth-id").unwrap(),
                cmd_matches.value_of("password").unwrap(),
                &value_t!(cmd_matches.value_of("hash-function"), HashFunction).unwrap(),
                false,
            )
            .await?
        }
        ("set-password", Some(cmd_matches)) => {
            credentials_add_password(
                &client,
                context,
                overrides,
                cmd_matches.value_of("device").unwrap(),
                cmd_matches.value_of("auth-id").unwrap(),
                cmd_matches.value_of("password").unwrap(),
                &value_t!(cmd_matches.value_of("hash-function"), HashFunction).unwrap(),
                true,
            )
            .await?
        }
        ("add-psk", Some(cmd_matches)) => {
            credentials_add_psk(
                &client,
                context,
                overrides,
                cmd_matches.value_of("device").unwrap(),
                cmd_matches.value_of("auth-id").unwrap(),
                cmd_matches.value_of("psk").unwrap(),
                false,
            )
            .await?
        }
        ("set-psk", Some(cmd_matches)) => {
            credentials_add_psk(
                &client,
                context,
                overrides,
                cmd_matches.value_of("device").unwrap(),
                cmd_matches.value_of("auth-id").unwrap(),
                cmd_matches.value_of("psk").unwrap(),
                true,
            )
            .await?
        }
        ("enable-x509", Some(cmd_matches)) => {
            credentials_enable_x509(
                &client,
                context,
                overrides,
                cmd_matches.value_of("device").unwrap(),
                cmd_matches.value_of("auth-id").unwrap(),
                true,
            )
            .await?
        }
        ("disable-x509", Some(cmd_matches)) => {
            credentials_enable_x509(
                &client,
                context,
                overrides,
                cmd_matches.value_of("device").unwrap(),
                cmd_matches.value_of("auth-id").unwrap(),
                false,
            )
            .await?
        }
        ("delete", Some(cmd_matches)) => {
            let expected_type_name = cmd_matches.value_of("type").unwrap();
            let expected_auth_id = cmd_matches.value_of("auth-id").unwrap();

            info!(
                "Deleting credentials from device - type: {}, auth_id: {}",
                expected_type_name, expected_auth_id
            );

            credentials_delete(
                &client,
                context,
                overrides,
                cmd_matches.value_of("device").unwrap(),
                |_, type_name, auth_id| {
                    let result = expected_type_name == type_name && expected_auth_id == auth_id;
                    debug!(
                        "Testing - {}/{} == {}/{} => {}",
                        expected_type_name, expected_auth_id, type_name, auth_id, result
                    );
                    result
                },
            )
            .await?
        }
        ("delete-all", Some(cmd_matches)) => {
            credentials_delete(
                &client,
                context,
                overrides,
                cmd_matches.value_of("device").unwrap(),
                |_, _, _| true,
            )
            .await?
        }
        _ => help(app)?,
    };

    Ok(())
}

async fn credentials_set(
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
        _ => Vec::<Value>::new(),
    };

    let client = context.create_client(overrides).await?;

    client
        .request(Method::PUT, url)
        .apply_auth(context)?
        .header(CONTENT_TYPE, "application/json")
        .json(&payload)
        .trace()
        .send()
        .await
        .trace()
        .map_err(error::Error::from)
        .and_then(|response| match response.status() {
            StatusCode::NO_CONTENT => Ok(response),
            StatusCode::NOT_FOUND => Err(NotFound(device.to_string()).into()),
            StatusCode::BAD_REQUEST => block_on(resource_err_bad_request(response)),
            _ => Err(UnexpectedResult(response.status()).into()),
        })?;

    println!("Updated device secrets: {}", device);

    Ok(())
}

async fn credentials_get(context: &Context, overrides: &Overrides, device: &str) -> Result<()> {
    let tenant = context.make_tenant(overrides)?;
    let url = resource_url(
        context,
        overrides,
        RESOURCE_NAME,
        &[&tenant, &device.into()],
    )?;

    resource_get(&context, overrides, &url, "Credentials").await
}

fn credentials_url(context: &Context, overrides: &Overrides, device: &str) -> Result<url::Url> {
    resource_url(
        context,
        overrides,
        RESOURCE_NAME,
        &[&context.make_tenant(overrides)?, &device.into()],
    )
}

async fn credentials_delete<F>(
    client: &Client,
    context: &Context,
    overrides: &Overrides,
    device: &str,
    predicate: F,
) -> Result<()>
where
    F: Fn(&Map<String, Value>, &String, &String) -> bool,
{
    let mut count: usize = 0;
    let mut diff: usize = 0;

    credentials_modify(client, &context, overrides, device, |payload| {
        count = payload.len();
        payload.retain(|cred| match cred {
            Value::Object(o) => match (o.get("type"), o.get("auth-id")) {
                (Some(Value::String(t)), Some(Value::String(a))) => !predicate(o, t, a),
                _ => true,
            },
            _ => true,
        });
        diff = count - payload.len();
        Ok(())
    })
    .await?;

    println!("Deleted {} elements, {} remain.", diff, count);

    Ok(())
}

async fn credentials_modify<F>(
    client: &Client,
    context: &Context,
    overrides: &Overrides,
    device: &str,
    modifier: F,
) -> Result<()>
where
    F: FnMut(&mut Vec<Value>) -> Result<()>,
{
    let url = credentials_url(context, overrides, device)?;

    resource_modify(client, &context, &url, &url, device, modifier).await?;

    Ok(())
}

async fn credentials_add_psk(
    client: &Client,
    context: &Context,
    overrides: &Overrides,
    device: &str,
    auth_id: &str,
    psk: &str,
    clear: bool,
) -> Result<()> {
    let new_secret = new_psk_secret(psk)?;

    cred_add_or_insert(
        client,
        context,
        overrides,
        clear,
        TYPE_PSK,
        device,
        auth_id,
        Some(new_secret),
    )
    .await?;

    if clear {
        println!("PSK set for {}/{}", device, auth_id);
    } else {
        println!("PSK added to {}/{}", device, auth_id);
    }

    Ok(())
}

async fn credentials_add_password(
    client: &Client,
    context: &Context,
    overrides: &Overrides,
    device: &str,
    auth_id: &str,
    password: &str,
    hash_function: &HashFunction,
    clear: bool,
) -> Result<()> {
    let new_secret = new_password_secret(password, hash_function)?;

    cred_add_or_insert(
        client,
        context,
        overrides,
        clear,
        TYPE_HASHED_PASSWORD,
        device,
        auth_id,
        Some(new_secret),
    )
    .await?;

    if clear {
        println!("Password set for {}/{}", device, auth_id);
    } else {
        println!("Password added to {}/{}", device, auth_id);
    }

    Ok(())
}

async fn credentials_enable_x509(
    client: &Client,
    context: &Context,
    overrides: &Overrides,
    device: &str,
    auth_id: &str,
    enable: bool,
) -> Result<()> {
    let new_secret = match enable {
        true => Some(new_x509()),
        false => None,
    };

    cred_add_or_insert(
        client, context, overrides, true, TYPE_X509, device, auth_id, new_secret,
    )
    .await?;

    if enable {
        println!("X509 enabled for {}/{}", device, auth_id);
    } else {
        println!("X509 disabled for {}/{}", device, auth_id);
    }

    Ok(())
}

async fn cred_add_or_insert(
    client: &Client,
    context: &Context,
    overrides: &Overrides,
    clear: bool,
    type_name: &str,
    device: &str,
    auth_id: &str,
    new_secret: Option<Value>,
) -> Result<()> {
    credentials_modify(client, &context, overrides, device, |payload| {
        let cred = payload
            .iter_mut()
            .flat_map(|c| cred_for_type_and_auth(type_name, auth_id, c))
            .nth(0);

        let cred = match cred {
            Some(c) => c,
            None => {
                let cred = new_credential(type_name, auth_id);
                payload.push(cred);
                payload.last_mut().unwrap().as_object_mut().unwrap()
            }
        };

        let new_secret = new_secret.clone();

        if clear {
            cred.remove("secrets");
        }

        if let Some(secret) = new_secret {
            if let Some(Value::Array(s)) = cred.get_mut("secrets") {
                s.push(secret);
            } else {
                cred.insert("secrets".into(), vec![secret].into());
            }
        }

        // return success

        Ok(())
    })
    .await
}

fn cred_for_type_and_auth<'a, 'b, 'c>(
    type_name: &'b str,
    auth_id: &'c str,
    cred: &'a mut Value,
) -> Option<&'a mut Map<String, Value>> {
    match cred {
        Value::Object(o) => match (o.get("type"), o.get("auth-id")) {
            (Some(Value::String(t)), Some(Value::String(a))) if t == type_name && a == auth_id => {
                Some(o)
            }
            _ => None,
        },
        _ => None,
    }
}

fn new_credential(type_name: &str, auth_id: &str) -> Value {
    let mut new_pair = Map::new();

    new_pair.insert("auth-id".into(), auth_id.into());
    new_pair.insert("type".into(), type_name.into());

    Value::Object(new_pair)
}

/// Create a new secrets entry, based on `hashed-password`
fn new_password_secret(plain_password: &str, hash_function: &HashFunction) -> Result<Value> {
    let mut new_pair = Map::new();

    // put to result

    hash_function.insert(&mut new_pair, &plain_password)?;

    // return as value

    Ok(Value::Object(new_pair))
}

/// Create a new secrets entry, based on `psk`
fn new_psk_secret<S: Into<String>>(psk: S) -> Result<Value> {
    let mut new_pair = Map::new();

    // validate it is base64 encoded

    let psk = psk.into();
    base64::decode(psk.as_bytes())
        .map_err(|err| err.context(GenericError("Key must be base64 encoded".into())))?;

    // put to result

    new_pair.insert("key".into(), psk.into());

    // return as value

    Ok(Value::Object(new_pair))
}

fn new_x509() -> Value {
    Value::Object(Map::new())
}
