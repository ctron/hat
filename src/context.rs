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

use crate::args::flag_arg;
use crate::resource::Tracer;
use crate::utils::Either;
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
    token: Option<String>,
    #[serde(default)]
    use_kubernetes: bool,
    #[serde(default)]
    insecure: bool,
    default_tenant: Option<String>,
    api_flavor: Option<ApiFlavor>,
}

impl Context {
    pub fn to_url(&self, overrides: &Overrides) -> Result<url::Url, url::ParseError> {
        let url = overrides.url().unwrap_or(&self.url);
        Url::parse(url)
    }

    pub fn username(&self) -> &Option<String> {
        &self.username
    }

    pub fn password(&self) -> &Option<String> {
        &self.password
    }

    pub fn token(&self) -> &Option<String> {
        &self.token
    }

    pub fn use_kubernetes(&self) -> bool {
        self.use_kubernetes
    }

    #[allow(dead_code)]
    pub fn insecure(&self) -> bool {
        self.insecure
    }

    #[allow(dead_code)]
    pub fn default_tenant(&self) -> &Option<String> {
        &self.default_tenant
    }

    pub fn make_tenant(&self, overrides: &Overrides) -> Result<String, error::Error> {
        overrides.tenant().clone()
            .map(|s|s.to_string())
            .or_else(|| self.default_tenant.clone())
            .ok_or_else(|| error::Error::from(ErrorKind::GenericError("No tenant specified. Either set a default tenant for the context or use the argument --tenant to provide one.".into())))
    }

    pub fn api_flavor(&self) -> &ApiFlavor {
        match self.api_flavor {
            Some(ref v) => v,
            None => &ApiFlavor::EclipseHonoV1,
        }
    }

    // Tests if the context supports the requested API versions
    pub fn api_required(&self, apis: &[ApiFlavor]) -> Result<(), error::Error> {
        let our = self.api_flavor();

        for api in apis {
            if api == our {
                // found ... OK
                return Ok(());
            }
        }

        // not found .. Err
        let msg = format!("Operation not supported by API: {}", our);
        Err(ErrorKind::GenericError(msg).into())
    }

    fn apply_common_config(
        &self,
        client_builder: reqwest::ClientBuilder,
        overrides: &Overrides,
    ) -> reqwest::ClientBuilder {
        let client_builder = if overrides.insecure().unwrap_or(self.insecure) {
            client_builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true)
        } else {
            client_builder
        };

        client_builder
    }

    #[cfg(not(windows))]
    pub fn create_client(&self, overrides: &Overrides) -> Result<reqwest::Client, error::Error> {
        let builder = if overrides.use_kubernetes().unwrap_or(self.use_kubernetes) {
            let result = kube::config::create_client_builder(Default::default())?;
            result.0
        } else {
            reqwest::ClientBuilder::new()
        };

        Ok(self
            .apply_common_config(builder, overrides)
            .build()?
            .trace())
    }

    #[cfg(windows)]
    pub fn create_client(&self, overrides: &Overrides) -> Result<reqwest::Client, error::Error> {
        if overrides.use_kubernetes().unwrap_or(self.use_kubernetes) {
            Err(ErrorKind::GenericError("Kubernetes is not supported on Windows".into()).into())
        } else {
            Ok(self
                .apply_common_config(reqwest::ClientBuilder::new(), overrides)
                .build()?)
        }
    }
}

pub fn context(app: &mut App, matches: &ArgMatches) -> Result<(), error::Error> {
    match matches.subcommand() {
        ("create", Some(cmd_matches)) => context_create(
            cmd_matches.value_of("context").unwrap(),
            cmd_matches.value_of("url").unwrap(),
            cmd_matches.value_of("username"),
            cmd_matches.value_of("password"),
            cmd_matches.value_of("token"),
            flag_arg("kubernetes", cmd_matches).unwrap_or(false),
            flag_arg("insecure", cmd_matches).unwrap_or(false),
            cmd_matches.value_of("default_tenant"),
            value_t!(cmd_matches.value_of("api_flavor"), ApiFlavor).ok(),
        ),
        ("update", Some(cmd_matches)) => context_update(
            cmd_matches.value_of("context"),
            cmd_matches.value_of("url"),
            cmd_matches.value_of("username"),
            cmd_matches.value_of("password"),
            cmd_matches.value_of("token"),
            flag_arg("kubernetes", cmd_matches),
            flag_arg("insecure", cmd_matches),
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

fn context_encode_file_name<S>(context: S) -> String
where
    S: Into<String>,
{
    utf8_percent_encode(&context.into(), DEFAULT_ENCODE_SET).collect()
}

fn context_decode_file_name(name: &str) -> Result<String, Utf8Error> {
    let iter = percent_decode(name.as_bytes());

    Ok(iter.decode_utf8()?.to_string())
}

fn context_config_dir() -> Result<PathBuf, error::Error> {
    let dir = dirs::config_dir().expect("Unable to evaluate user's configuration directory");

    Ok(dir.join("hat"))
}

fn context_contexts_dir() -> Result<PathBuf, error::Error> {
    context_config_dir().map(|path| path.join("contexts"))
}

fn context_file_path<S>(context: S) -> Result<PathBuf, error::Error>
where
    S: Into<String>,
{
    let context = context.into();
    let name = context.trim();

    if name.is_empty() {
        return Err(ErrorKind::ContextNameError(context).into());
    }

    context_contexts_dir().map(|path| path.join(context_encode_file_name(context)))
}

/// Load the provided context.
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

/// Read the current selected context.
fn context_get_current() -> Result<Option<String>, error::Error> {
    let path = context_config_dir().map(|path| path.join("current"))?;

    if !path.exists() {
        return Ok(None);
    }

    let mut current = String::new();

    File::open(path)?.read_to_string(&mut current)?;

    Ok(Some(current))
}

/// Loads the provided, or default context.
fn context_load_or_current(name: Option<String>) -> Result<Context, error::Error> {
    context_load_or_fail(name.or(context_get_current()?))
}

/// Loads the current (or overridde) context.
pub fn context_load_current(overrides: Option<&Overrides>) -> Result<Context, error::Error> {
    context_load_or_current(overrides.and_then(Overrides::context))
}

/// Tests if the name contains a valid context name.
/// [`None`] is never a valid name.
fn context_names_valid(name: Option<String>) -> Result<String, error::Error> {
    name.ok_or_else(|| {
        ErrorKind::GenericError(
            "No context selected. Create a first context or select an existing one.".to_string(),
        )
        .into()
    })
}

/// Loads a context, if the name is valid.
fn context_load_or_fail(name: Option<String>) -> Result<Context, error::Error> {
    context_names_valid(name).and_then(|current| context_load(current.as_str()))
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

    Ok(())
}

fn context_validate_url(url: &str) -> Result<(), error::Error> {
    Url::parse(&url)?;
    Ok(())
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
    token: Option<&str>,
    use_kubernetes: bool,
    insecure: bool,
    default_tenant: Option<&str>,
    api_flavor: Option<ApiFlavor>,
) -> Result<(), error::Error> {
    if context_file_path(context)?.exists() {
        return Err(ErrorKind::ContextExistsError(context.to_string()).into());
    }

    context_validate_url(url)?;

    let ctx = Context {
        url: url.into(),
        username: username.map(Into::into),
        password: password.map(Into::into),
        token: token.map(Into::into),
        use_kubernetes,
        insecure,
        default_tenant: default_tenant.map(Into::into),
        api_flavor,
    };

    context_store(context, ctx)?;

    println!("Created new context: {}", context);
    context_switch(context)?;

    Ok(())
}

fn context_update(
    context: Option<&str>,
    url: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
    token: Option<&str>,
    use_kubernetes: Option<bool>,
    insecure: Option<bool>,
    default_tenant: Option<&str>,
    api_flavor: Option<ApiFlavor>,
) -> Result<(), error::Error> {
    let context = match context {
        Some(c) => {
            println!("Updating context: '{}':", c);
            Some(c.to_string())
        }
        None => {
            let ctx = context_get_current()?;
            if let Some(ref c) = ctx {
                println!("Updating current context: '{}':", c);
            }
            ctx
        }
    };
    let context = context_names_valid(context)?;

    let mut ctx = context_load(context.as_str())?;

    if url.is_some() {
        context_validate_url(url.unwrap())?;
        ctx.url = url.unwrap().into();
        println!("\tSetting URL to: {}", ctx.url);
    }

    if let Some(k) = use_kubernetes {
        ctx.use_kubernetes = k;
        println!(
            "\t{}using local Kubernetes config",
            ctx.use_kubernetes.either("", "NOT ")
        );
    }

    if let Some(i) = insecure {
        ctx.insecure = i;
        println!(
            "\t{}validating TLS certificate and hostname",
            ctx.insecure.either("NOT ", "")
        );
    }

    if let Some(u) = username {
        if u.is_empty() {
            ctx.username = None;
        } else {
            ctx.username = Some(u.into());
        }

        println!("\tSetting username to: {}", u);
    }

    if let Some(p) = password {
        if p.is_empty() {
            ctx.password = None;
        } else {
            ctx.password = Some(p.into());
        }

        println!("\tSetting password");
    }

    if let Some(p) = token {
        if p.is_empty() {
            ctx.token = None;
        } else {
            ctx.token = Some(p.into());
        }

        println!("\tSetting token");
    }

    if let Some(t) = default_tenant {
        if t.is_empty() {
            ctx.default_tenant = None;
        } else {
            ctx.default_tenant = Some(t.into());
        }

        println!("\tSetting default tenant to: {}", t);
    }

    if let Some(a) = api_flavor {
        ctx.api_flavor = Some(a.clone());
        println!("\t Setting API flavor to: {}", a);
    }

    context_store(&context, ctx)?;

    Ok(())
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

    Ok(())
}

fn context_show() -> Result<(), error::Error> {
    let context = context_get_current()?;
    let ctx = context_load_current(None)?;

    println!("Current context: {}", context.unwrap());
    println!("            URL: {}", ctx.url);

    println!(
        "       API type: {}",
        ctx.api_flavor
            .as_ref()
            .map_or_else(|| String::from("<none>"), ApiFlavor::to_string)
    );

    println!(
        "       Username: {}",
        ctx.username.unwrap_or_else(|| String::from("<none>"))
    );
    println!(
        "       Password: {}",
        ctx.password.and(Some("***")).unwrap_or("<none>")
    );
    println!(
        "          Token: {}",
        ctx.token.unwrap_or_else(|| String::from("<none>"))
    );
    println!(
        " Use Kubernetes: {}",
        ctx.use_kubernetes.either("yes", "no")
    );
    println!("   Insecure TLS: {}", ctx.insecure.either("yes", "no"));
    println!(
        " Default tenant: {}",
        ctx.default_tenant.unwrap_or_else(|| String::from("<none>"))
    );

    Ok(())
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

    Ok(())
}

fn context_current() -> Result<(), error::Error> {
    let current = context_get_current()?;
    if let Some(current) = current {
        println!("{}", current);
    }
    Ok(())
}
