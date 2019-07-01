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

use crate::context::ApiFlavor::BoschIoTHub;
use crate::context::Context;

use reqwest;

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

use rand::rngs::EntropyRng;
use rand::RngCore;

use crate::overrides::Overrides;

type Result<T> = std::result::Result<T, error::Error>;

static RESOURCE_NAME: &str = "credentials";
static TYPE_HASHED_PASSWORD: &str = "hashed-password";

pub fn credentials(
    app: &mut App,
    matches: &ArgMatches,
    overrides: &Overrides,
    context: &Context,
) -> Result<()> {
    let result = match matches.subcommand() {
        ("set", Some(cmd_matches)) => credentials_set(
            context,
            overrides,
            cmd_matches.value_of("device").unwrap(),
            cmd_matches.value_of("payload"),
        )?,
        ("get", Some(cmd_matches)) => {
            credentials_get(context, overrides, cmd_matches.value_of("device").unwrap())?
        }
        ("add-password", Some(cmd_matches)) => credentials_add_password(
            context,
            overrides,
            cmd_matches.value_of("device").unwrap(),
            cmd_matches.value_of("auth-id").unwrap(),
            cmd_matches.value_of("password").unwrap(),
            &value_t!(cmd_matches.value_of("hash-function"), HashFunction).unwrap(),
            false,
            cmd_matches.is_present("no-salt"),
        )?,
        ("set-password", Some(cmd_matches)) => credentials_add_password(
            context,
            overrides,
            cmd_matches.value_of("device").unwrap(),
            cmd_matches.value_of("auth-id").unwrap(),
            cmd_matches.value_of("password").unwrap(),
            &value_t!(cmd_matches.value_of("hash-function"), HashFunction).unwrap(),
            true,
            cmd_matches.is_present("no-salt"),
        )?,
        ("delete", Some(cmd_matches)) => {
            let expected_type_name = cmd_matches.value_of("type").unwrap();
            let expected_auth_id = cmd_matches.value_of("auth-id").unwrap();

            credentials_delete(
                context,
                overrides,
                cmd_matches.value_of("device").unwrap(),
                |_, type_name, auth_id| {
                    expected_type_name == type_name && expected_auth_id == auth_id
                },
            )?
        }
        ("delete-all", Some(cmd_matches)) => credentials_delete(
            context,
            overrides,
            cmd_matches.value_of("device").unwrap(),
            |_, _, _| true,
        )?,
        _ => help(app)?,
    };

    Ok(result)
}

fn credentials_set(
    context: &Context,
    overrides: &Overrides,
    device: &str,
    payload: Option<&str>,
) -> Result<()> {
    let tenant = context.make_tenant(overrides)?;
    let url = resource_url(context, RESOURCE_NAME, &[&tenant, &device.into()])?;

    let payload = match payload {
        Some(_) => serde_json::from_str(payload.unwrap())?,
        _ => Vec::<Value>::new(),
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
        .and_then(|mut response| match response.status() {
            StatusCode::NO_CONTENT => Ok(response),
            StatusCode::NOT_FOUND => Err(NotFound(format!("{}", device)).into()),
            StatusCode::BAD_REQUEST => resource_err_bad_request(&mut response),
            _ => Err(UnexpectedResult(response.status()).into()),
        })?;

    println!("Updated device secrets: {}", device);

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

fn credentials_url(context: &Context, overrides: &Overrides, device: &str) -> Result<url::Url> {
    resource_url(
        context,
        RESOURCE_NAME,
        &[&context.make_tenant(overrides)?, &device.into()],
    )
}

fn credentials_delete<F>(
    context: &Context,
    overrides: &Overrides,
    device: &str,
    predicate: F,
) -> Result<()>
where
    F: Fn(&Map<String, Value>, &String, &String) -> bool,
{
    credentials_modify(&context, overrides, device, |payload| {
        payload.retain(|cred| match cred {
            Value::Object(o) => match (o.get("type"), o.get("auth-id")) {
                (Some(Value::String(t)), Some(Value::String(a))) => !predicate(o, t, a),
                _ => true,
            },
            _ => true,
        });
        Ok(())
    })
}

fn credentials_modify<F>(
    context: &Context,
    overrides: &Overrides,
    device: &str,
    modifier: F,
) -> Result<()>
where
    F: Fn(&mut Vec<Value>) -> Result<()>,
{
    let url = credentials_url(context, overrides, device)?;

    resource_modify(&context, &url, &url, device, modifier)?;

    Ok(())
}

fn credentials_add_password(
    context: &Context,
    overrides: &Overrides,
    device: &str,
    auth_id: &str,
    password: &str,
    hash_function: &HashFunction,
    clear: bool,
    nosalt: bool,
) -> Result<()> {
    cred_add_or_insert(
        context,
        overrides,
        clear,
        "hashed-password",
        device,
        auth_id,
        new_secret(password, hash_function, nosalt),
    )?;

    if clear {
        println!("Password set for {}/{}", device, auth_id);
    } else {
        println!("Password added to {}/{}", device, auth_id);
    }

    return Ok(());
}

fn cred_add_or_insert(
    context: &Context,
    overrides: &Overrides,
    clear: bool,
    type_name: &str,
    device: &str,
    auth_id: &str,
    new_secret: Value,
) -> Result<()> {
    credentials_modify(&context, overrides, device, |payload| {
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

        if let Some(Value::Array(s)) = cred.get_mut("secrets") {
            s.push(new_secret);
        } else {
            cred.insert("secrets".into(), vec![new_secret].into());
        }

        // return success

        Ok(())
    })
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

    return Value::Object(new_pair);
}

/// Create a new secrets entry, based on `hashed-password`
fn new_secret(plain_password: &str, hash_function: &HashFunction, nosalt: bool) -> Value {
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

    new_pair.insert("type".into(), TYPE_HASHED_PASSWORD.into());
    new_pair.insert("hash-function".into(), hash_function.name().into());
    new_pair.insert("pwd-hash".into(), hash.into());
    if !nosalt {
        new_pair.insert("salt".into(), salt.into());
    }

    // return as value

    return Value::Object(new_pair);
}
