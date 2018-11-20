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

use error;
use error::ErrorKind::*;

use hash::{HashFunction};

use resource::{resource_delete, resource_get, resource_url, resource_modify, AuthExt, Tracer};

use serde_json::value::{Map,Value};

use rand::{RngCore,EntropyRng};

type Result<T> = std::result::Result<T, error::Error>;

static RESOURCE_NAME : &str = "credentials";

pub fn credentials(app: & mut App, matches: &ArgMatches, context: &Context) -> Result<()> {

    let result = match matches.subcommand() {
        ( "create", Some(cmd_matches)) => credentials_create(
            context,
            cmd_matches.value_of("tenant"),
            cmd_matches.value_of("device").unwrap(),
            cmd_matches.value_of("auth-id").unwrap(),
            cmd_matches.value_of("type").unwrap(),
            cmd_matches.value_of("payload")
        )?,
        ( "update", Some(cmd_matches)) => credentials_update(
            context,
            cmd_matches.value_of("tenant"),
            cmd_matches.value_of("auth-id").unwrap(),
            cmd_matches.value_of("type").unwrap(),
            cmd_matches.value_of("payload")
        )?,
        ( "get", Some(cmd_matches)) => credentials_get(
            context,
            cmd_matches.value_of("tenant"),
            cmd_matches.value_of("device").unwrap()
        )?,
        ( "get-for", Some(cmd_matches)) => credentials_get_for(
            context,
            cmd_matches.value_of("tenant"),
            cmd_matches.value_of("auth-id").unwrap(),
            cmd_matches.value_of("type").unwrap()
        )?,
        ( "delete", Some(cmd_matches)) => credentials_delete(
            context,
            cmd_matches.value_of("tenant"),
            cmd_matches.value_of("device").unwrap()
        )?,
        ( "delete-for", Some(cmd_matches)) => credentials_delete_for(
            context,
            cmd_matches.value_of("tenant"),
            cmd_matches.value_of("auth-id").unwrap(),
            cmd_matches.value_of("type").unwrap()
        )?,
        ( "enable", Some(cmd_matches)) => credentials_enable(
            context,
            cmd_matches.value_of("tenant"),
            cmd_matches.value_of("auth-id").unwrap(),
            cmd_matches.value_of("type").unwrap()
        )?,
        ( "disable", Some(cmd_matches)) => credentials_disable(
            context,
            cmd_matches.value_of("tenant"),
            cmd_matches.value_of("auth-id").unwrap(),
            cmd_matches.value_of("type").unwrap()
        )?,
        ( "add-password", Some(cmd_matches)) => credentials_add_password(
            context,
            cmd_matches.value_of("tenant"),
            cmd_matches.value_of("device"),
            cmd_matches.value_of("auth-id").unwrap(),
            cmd_matches.value_of("password").unwrap(),
            &value_t!(cmd_matches.value_of("hash-function"), HashFunction).unwrap(),
            false
        )?,
        ( "set-password", Some(cmd_matches)) => credentials_add_password(
            context,
            cmd_matches.value_of("tenant"),
            cmd_matches.value_of("device"),
            cmd_matches.value_of("auth-id").unwrap(),
            cmd_matches.value_of("password").unwrap(),
            &value_t!(cmd_matches.value_of("hash-function"), HashFunction).unwrap(),
            true
        )?,
        _ => help(app)?
    };

    Ok(result)
}

fn credentials_delete(context: &Context, tenant:Option<&str>, device:&str) -> Result<()> {

    let tenant = context.make_tenant(tenant)?;
    let url = resource_url(context, RESOURCE_NAME, &[&tenant, &device.into()])?;

    resource_delete(&context, &url, "Credentials", device)

}


fn credentials_delete_for(context: &Context, tenant:Option<&str>, auth_id:&str, type_name:&str) -> Result<()> {

    let tenant = context.make_tenant(tenant)?;
    let url = resource_url(context, RESOURCE_NAME, &[&tenant, &auth_id.into(), &type_name.into()])?;

    resource_delete(&context, &url, "Credentials", &format!("{} / {}", auth_id, type_name))

}

fn credentials_create(context: &Context, tenant:Option<&str>, device:&str, auth_id: &str, type_name: &str, payload:Option<&str>) -> Result<()> {

    let tenant = context.make_tenant(tenant)?;
    let url = resource_url(context, RESOURCE_NAME, &[&tenant])?;

    let mut payload = match payload {
        Some(_) => serde_json::from_str(payload.unwrap())?,
        _ => serde_json::value::Map::new()
    };

    payload.insert("device-id".into(), device.into());
    payload.insert("type".into(), type_name.into());
    payload.insert("auth-id".to_string(), auth_id.into());

    let client = reqwest::Client::new();

    client
        .request(Method::POST, url)
        .apply_auth(context)
        .header(CONTENT_TYPE, "application/json" )
        .json(&payload)
        .trace()
        .send()
        .map_err(error::Error::from)
        .and_then(|response|{
            match response.status() {
                StatusCode::CREATED => Ok(response),
                StatusCode::CONFLICT => Err(AlreadyExists(device.to_string()).into()),
                StatusCode::BAD_REQUEST => Err(MalformedRequest().into()),
                _ => Err(UnexpectedResult(response.status()).into())
            }
        })?;

    println!("Created device secrets: {} / {}", device, auth_id);

    return Ok(());
}

fn credentials_update(context: &Context, tenant:Option<&str>, auth_id: &str, type_name: &str, payload:Option<&str>) -> Result<()> {

    let tenant = context.make_tenant(tenant)?;
    let url = resource_url(context, RESOURCE_NAME, &[&tenant, &auth_id.into(), &type_name.into()])?;

    let mut payload = match payload {
        Some(_) => serde_json::from_str(payload.unwrap())?,
        _ => serde_json::value::Map::new()
    };

    payload.insert("type".into(), type_name.into());
    payload.insert("auth-id".into(), auth_id.into());

    let client = reqwest::Client::new();

    client
        .request(Method::PUT, url)
        .apply_auth(context)
        .header(CONTENT_TYPE, "application/json" )
        .json(&payload)
        .trace()
        .send()
        .map_err(error::Error::from)
        .and_then(|response|{
            match response.status() {
                StatusCode::NO_CONTENT => Ok(response),
                StatusCode::NOT_FOUND => Err(NotFound(format!("{}/{}", auth_id, type_name)).into()),
                StatusCode::BAD_REQUEST => Err(MalformedRequest().into()),
                _ => Err(UnexpectedResult(response.status()).into())
            }
        })?;

    println!("Updated device secrets: {}/{}", auth_id, type_name);

    return Ok(());
}

fn credentials_get(context: &Context, tenant:Option<&str>, device:&str) -> Result<()> {

    let tenant = context.make_tenant(tenant)?;
    let url = resource_url(context, RESOURCE_NAME, &[&tenant, &device.into()])?;

    resource_get(&context, &url, "Credentials")

}

fn credentials_get_for(context: &Context, tenant:Option<&str>, auth_id:&str, type_name:&str) -> Result<()> {

    let tenant = context.make_tenant(tenant)?;
    let url = resource_url(context, RESOURCE_NAME, &[&tenant, &auth_id.into(), &type_name.into()])?;

    resource_get(&context, &url, "Credentials")

}

fn credentials_enable(context: &Context, tenant:Option<&str>, auth_id:&str, type_name:&str) -> Result<()> {

    let tenant = context.make_tenant(tenant)?;
    let url = resource_url(context, RESOURCE_NAME, &[&tenant, &auth_id.into(), &type_name.into()])?;

    resource_modify(&context, &url, &format!("{}/{}", auth_id, type_name), |payload| {
        payload.insert("enabled".into(), true.into());
        Ok(())
    })?;

    println!("Credentials enabled");

    return Ok(());
}

fn credentials_disable(context: &Context, tenant:Option<&str>, auth_id:&str, type_name:&str) -> Result<()> {

    let tenant = context.make_tenant(tenant)?;
    let url = resource_url(context, RESOURCE_NAME, &[&tenant, &auth_id.into(), &type_name.into()])?;

    resource_modify(&context, &url, &format!("{}/{}", auth_id, type_name), |payload| {
        payload.insert("enabled".into(), false.into());
        Ok(())
    })?;

    println!("Credentials disabled");

    return Ok(());
}

fn new_entry(plain_password: &str, hash_function:&HashFunction) -> Value {

    let mut new_pair = Map::new();

    let mut rnd = EntropyRng::new();

    let mut salt = vec![0;8];
    rnd.fill_bytes(& mut salt);

    // hash it

    let hash = hash_function.hash(&salt, &plain_password);
    let salt = base64::encode(&salt);

    // put to result

    new_pair.insert("hash-function".into(), hash_function.name().into());
    new_pair.insert("salt".into(), salt.into());
    new_pair.insert("pwd-hash".into(), hash.into());

    // return as value

    return Value::Object(new_pair);
}

fn credentials_add_password(context: &Context, tenant:Option<&str>, device: Option<&str>, auth_id:&str, password:&str, hash_function:&HashFunction, clear: bool) -> Result<()> {

    let tenant = context.make_tenant(tenant)?;
    let type_name = "hashed-password";

    let url = resource_url(context, RESOURCE_NAME, &[&tenant, &auth_id.into(), &type_name.into()])?;

    resource_modify(&context, &url, &format!("{}/{}", auth_id, type_name), |payload| {

        if !payload.contains_key("secrets") {
            payload.insert("secrets".into(), Value::Array(Vec::new()));
        }

        let secrets = payload
            .get_mut("secrets")
            .unwrap()
            .as_array_mut()
            .unwrap();

        if clear {
            secrets.clear();
        }

        let entry = new_entry(password, hash_function);
        secrets.push(entry);

        Ok(())
    })

    .and(Ok(()))

    .or_else(|err| {
        if !device.is_some() {
            return Err(err);
        }

        match err.kind() {
            NotFound(_) => {

                println!("No credential set found, creating new one.");

                let mut payload = Map::new();

                let entry = new_entry(password, hash_function);
                payload.insert("secrets".into(), Value::Array([entry].to_vec()));

                let payload = serde_json::to_string(&payload)?;

                credentials_create(context, Some(tenant.as_str()), device.unwrap(), auth_id, type_name, Some(&payload))

            },
            _ => Err(err)
        }
    })?;

    if clear {
        println!("Password set for {}/{}", auth_id, type_name);
    }
    else {
        println!("Password added to {}/{}", auth_id, type_name);
    }

    return Ok(());
}