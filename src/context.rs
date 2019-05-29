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

use std::fs::File;
use std::result::Result;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use url::percent_encoding::{percent_decode, utf8_percent_encode, DEFAULT_ENCODE_SET};
use url::Url;

use crate::help::help;
use clap::{App, ArgMatches};

use std::str::Utf8Error;

use std::io::prelude::*;
use std::path::*;

use crate::error;
use crate::error::ErrorKind;

use std::fmt;

use crate::Overrides;

use ansi_term::Style;
use colored_json::*;

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum ApiFlavor {
    EclipseHonoV1,
    EclipseHonoLegacy,
    BoschIoTHub,
}

impl fmt::Display for ApiFlavor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ApiFlavor::EclipseHonoV1 => write!(f, "Eclipse Hono V1"),
            ApiFlavor::EclipseHonoLegacy => write!(f, "Eclipse Hono (legacy)"),
            ApiFlavor::BoschIoTHub => write!(f, "Bosch IoT Hub"),
        }
    }
}

impl std::str::FromStr for ApiFlavor {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "EclipseHonoV1" | "hono-v1" | "hono" => Ok(ApiFlavor::EclipseHonoV1),
            "EclipseHono" | "EclipseHonoLegacy" | "hono-legacy" => Ok(ApiFlavor::EclipseHonoLegacy),
            "BoschIoTHub" | "bosch" | "iothub" => Ok(ApiFlavor::BoschIoTHub),
            _ => Err("Invalid value"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Context {
    url: String,
    username: Option<String>,
    password: Option<String>,
    default_tenant: Option<String>,
    api_flavor: Option<ApiFlavor>,
}

impl Context {
    pub fn to_url(&self) -> Result<url::Url, url::ParseError> {
        Url::parse(self.url.as_str())
    }

    pub fn username(&self) -> &Option<String> {
        return &self.username;
    }

    pub fn password(&self) -> &Option<String> {
        return &self.password;
    }

    #[allow(dead_code)]
    pub fn default_tenant(&self) -> &Option<String> {
        return &self.default_tenant;
    }

    pub fn make_tenant(&self, overrides: &Overrides) -> Result<String, error::Error> {
        return overrides.tenant().clone()
            .map(|s|s.to_string())
            .or(self.default_tenant.clone())
            .ok_or(error::Error::from(ErrorKind::GenericError("No tenant specified. Either set a default tenant for the context or use the argument --tenant to provide one.".into())));
    }

    pub fn api_flavor(&self) -> &ApiFlavor {
        match self.api_flavor {
            Some(ref v) => v,
            None => &ApiFlavor::EclipseHonoV1,
        }
    }

    // Tests if the context supports the requested API versions
    pub fn api_required(&self, apis: &[&ApiFlavor]) -> Result<(), error::Error> {
        let our = self.api_flavor();

        for api in apis {
            if *api == our {
                // found ... OK
                return Ok(());
            }
        }

        // not found .. Err
        let msg = format!("Operation not supported by API: {}", our);
        return Err(ErrorKind::GenericError(msg).into());
    }
}

pub fn context(app: &mut App, matches: &ArgMatches) -> Result<(), error::Error> {
    match matches.subcommand() {
        ("create", Some(cmd_matches)) => context_create(
            cmd_matches.value_of("context").unwrap(),
            cmd_matches.value_of("url").unwrap(),
            cmd_matches.value_of("username"),
            cmd_matches.value_of("password"),
            cmd_matches.value_of("default_tenant"),
            value_t!(cmd_matches.value_of("api_flavor"), ApiFlavor).ok(),
        ),
        ("update", Some(cmd_matches)) => context_update(
            cmd_matches.value_of("context").unwrap(),
            cmd_matches.value_of("url"),
            cmd_matches.value_of("username"),
            cmd_matches.value_of("password"),
            cmd_matches.value_of("default_tenant"),
            value_t!(cmd_matches.value_of("api_flavor"), ApiFlavor).ok(),
        ),
        ("switch", Some(cmd_matches)) => context_switch(cmd_matches.value_of("context").unwrap()),
        ("delete", Some(cmd_matches)) => context_delete(cmd_matches.value_of("context").unwrap()),
        ("list", Some(_)) => context_list(),
        ("show", Some(_)) => context_show(),
        ("current", Some(_)) => context_current(),
        _ => help(app),
    }
}

fn context_encode_file_name(context: &str) -> String {
    utf8_percent_encode(context, DEFAULT_ENCODE_SET).collect()
}

fn context_decode_file_name(name: &str) -> Result<String, Utf8Error> {
    let iter = percent_decode(name.as_bytes());

    Ok(iter.decode_utf8()?.to_string())
}

fn context_config_dir() -> Result<PathBuf, error::Error> {
    let dir = dirs::config_dir().expect("Unable to evaluate user's configuration directory");

    return Ok(dir.join("hat"));
}

fn context_contexts_dir() -> Result<PathBuf, error::Error> {
    context_config_dir().map(|path| path.join("contexts"))
}

fn context_file_path(context: &str) -> Result<PathBuf, error::Error> {
    let name = context.trim();

    if name.is_empty() {
        return Err(ErrorKind::ContextNameError(context.to_string()).into());
    }

    return context_contexts_dir().map(|path| path.join(context_encode_file_name(context)));
}

fn context_load(context: &str) -> Result<Context, error::Error> {
    let file = File::open(context_file_path(context)?);

    match file {
        Ok(file) => Ok(serde_yaml::from_reader(file)?),
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound => {
                Err(ErrorKind::ContextUnknownError(context.into()).into())
            }
            _ => Err(err.into()),
        },
    }
}

fn context_get_current() -> Result<Option<String>, error::Error> {
    let path = context_config_dir().map(|path| path.join("current"))?;

    if !path.exists() {
        return Ok(None);
    }

    let mut current = String::new();

    File::open(path)?.read_to_string(&mut current)?;

    return Ok(Some(current));
}

pub fn context_load_current(overrides: Option<&Overrides>) -> Result<Context, error::Error> {
    overrides
        .and_then(|o| o.context())
        .or(context_get_current()?)
        .ok_or_else(|| {
            ErrorKind::GenericError(
                "No context selected. Create a first context or select an existing one."
                    .to_string(),
            )
            .into()
        })
        .and_then(|current| context_load(current.as_str()))
}

#[cfg(unix)]
fn limit_access(file: &mut File) -> Result<(), error::Error> {
    let mut permissions = file.metadata()?.permissions();
    permissions.set_mode(0o600);
    file.set_permissions(permissions)?;

    Ok(())
}

#[cfg(not(unix))]
fn limit_access(_file: &mut File) -> Result<(), error::Error> {
    Ok(())
}

fn context_store(context_name: &str, context: Context) -> Result<(), error::Error> {
    let path = context_file_path(context_name)?;

    std::fs::create_dir_all(path.parent().unwrap())?;

    let mut file = File::create(path)?;

    limit_access(&mut file)?;

    file.write_all(serde_yaml::to_string(&context)?.as_bytes())?;

    return Ok(());
}

fn context_validate_url(url: &str) -> Result<(), error::Error> {
    Url::parse(&url)?;
    return Ok(());
}

fn context_switch(context: &str) -> Result<(), error::Error> {
    context_load(context)?;

    let path = context_config_dir().map(|path| path.join("current"))?;

    File::create(path)?.write_all(context.trim().as_bytes())?;

    println!("Switched to context: {}", context);

    Ok(())
}

fn context_create(
    context: &str,
    url: &str,
    username: Option<&str>,
    password: Option<&str>,
    default_tenant: Option<&str>,
    api_flavor: Option<ApiFlavor>,
) -> Result<(), error::Error> {
    if context_file_path(context)?.exists() {
        return Err(ErrorKind::ContextExistsError(context.to_string()).into());
    }

    context_validate_url(url)?;

    let ctx = Context {
        url: url.into(),
        username: username.map(|u| u.into()),
        password: password.map(|p| p.into()),
        default_tenant: default_tenant.map(|t| t.into()),
        api_flavor,
    };

    context_store(context, ctx)?;

    println!("Created new context: {}", context);
    context_switch(context)?;

    return Ok(());
}

fn context_update(
    context: &str,
    url: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
    default_tenant: Option<&str>,
    api_flavor: Option<ApiFlavor>,
) -> Result<(), error::Error> {
    let mut ctx = context_load(context)?;

    if url.is_some() {
        context_validate_url(url.unwrap())?;
        ctx.url = url.unwrap().into();
        println!("Updated context '{}' URL to: {}", context, ctx.url);
    }

    if let Some(u) = username {
        if u.is_empty() {
            ctx.username = None;
        } else {
            ctx.username = Some(u.into());
        }

        println!("Updated context '{}' set username to: {}", context, u);
    }

    if let Some(p) = password {
        if p.is_empty() {
            ctx.password = None;
        } else {
            ctx.password = Some(p.into());
        }

        println!("Updated context '{}' set password", context);
    }

    if let Some(t) = default_tenant {
        if t.is_empty() {
            ctx.default_tenant = None;
        } else {
            ctx.default_tenant = Some(t.into());
        }

        println!("Updated context '{}' set default tenant to: {}", context, t);
    }

    if let Some(a) = api_flavor {
        ctx.api_flavor = Some(a.clone());
        println!("Updated context '{}' set API flavor to: {}", context, a);
    }

    context_store(context, ctx)?;

    return Ok(());
}

fn context_delete(context: &str) -> Result<(), error::Error> {
    // delete context file

    let path = context_file_path(context)?;
    if path.exists() {
        std::fs::remove_file(path)?;

        // delete "current" marker

        let current = context_get_current()?;
        if current == Some(context.to_string()) {
            let cp = context_config_dir().map(|path| path.join("current"))?;
            std::fs::remove_file(cp)?;
        }
    } else {
        println!("Nothing to delete");
        return Ok(());
    }

    // success

    println!("Deleted context: {}", context);

    return Ok(());
}

fn context_show() -> Result<(), error::Error> {
    let context = context_get_current()?;
    let ctx = context_load_current(None)?;

    println!("Current context: {}", context.unwrap());
    println!("            URL: {}", ctx.url);
    if ctx.api_flavor.is_some() {
        println!("       API type: {}", ctx.api_flavor.unwrap());
    } else {
        println!("       API type: <none>");
    }
    println!(
        "       Username: {}",
        ctx.username.unwrap_or(String::from("<none>"))
    );
    println!(
        "       Password: {}",
        ctx.password.and(Some("***")).unwrap_or("<none>")
    );
    println!(
        " Default tenant: {}",
        ctx.default_tenant.unwrap_or(String::from("<none>"))
    );

    return Ok(());
}

fn context_list() -> Result<(), error::Error> {
    let path = context_contexts_dir()?;

    if !path.exists() {
        println!("No known contexts");
        return Ok(());
    }

    let current = context_get_current()?;

    let active = Style::new().bold().fg(Color::Green);

    for entry in path.read_dir()? {
        let name = context_decode_file_name(entry?.file_name().to_str().unwrap())?;

        if current == Some(name.clone()) && ColorMode::Auto(Output::StdOut).use_color() {
            println!("{} *", active.paint(name));
        } else {
            println!("{}", name);
        }
    }

    return Ok(());
}

fn context_current() -> Result<(), error::Error> {
    let current = context_get_current()?;
    if let Some(current) = current {
        println!("{}", current);
    }
    Ok(())
}
