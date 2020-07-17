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

use url::Url;

use crate::help::help;
use clap::{App, ArgMatches};

use std::str::Utf8Error;

use std::io::prelude::*;
use std::path::*;

use crate::error;
use crate::error::ErrorKind;

use crate::Overrides;

use crate::args::flag_arg;
use crate::resource::Tracer;
use crate::utils::Either;
use ansi_term::Style;
use colored_json::*;
use kube::config::ConfigOptions;
use percent_encoding::{percent_decode, utf8_percent_encode, NON_ALPHANUMERIC};
use serde;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Context {
    url: String,
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
    #[serde(default)]
    use_kubernetes: bool,
    kubernetes_context: Option<String>,
    kubernetes_cluster: Option<String>,
    #[serde(default)]
    insecure: bool,
    default_tenant: Option<String>,
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

    pub fn kubernetes_cluster(&self) -> Option<&String> {
        return self.kubernetes_cluster.as_ref();
    }

    pub fn kubernetes_context(&self) -> Option<&String> {
        return self.kubernetes_context.as_ref();
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

    fn apply_common_config(
        &self,
        client_builder: reqwest::ClientBuilder,
        overrides: &Overrides,
    ) -> reqwest::ClientBuilder {
        let client_builder = if overrides.insecure().unwrap_or(self.insecure) {
            client_builder.danger_accept_invalid_certs(true)
        } else {
            client_builder
        };

        client_builder
    }

    pub async fn create_client(
        &self,
        overrides: &Overrides,
    ) -> Result<reqwest::Client, error::Error> {
        let builder = if overrides.use_kubernetes().unwrap_or(self.use_kubernetes) {
            let cluster = overrides.kubernetes_cluster().or(self.kubernetes_cluster());
            let context = overrides.kubernetes_context().or(self.kubernetes_context());
            let options = ConfigOptions {
                context: context.cloned(),
                cluster: cluster.cloned(),
                ..Default::default()
            };
            let result = kube::config::create_client_builder(options).await?;
            result.0
        } else {
            reqwest::Client::builder()
        };

        Ok(self
            .apply_common_config(builder, overrides)
            .build()?
            .trace())
    }
}

pub fn context(app: &mut App, matches: &ArgMatches) -> Result<(), error::Error> {
    match matches.subcommand() {
        ("create", Some(cmd_matches)) => context_create(
            cmd_matches.value_of("context-name").unwrap(),
            cmd_matches
                .value_of("context-url")
                .or_else(|| cmd_matches.value_of("url"))
                .unwrap(),
            cmd_matches.value_of("username"),
            cmd_matches.value_of("password"),
            cmd_matches.value_of("token"),
            flag_arg("use-kubernetes", cmd_matches).unwrap_or(false),
            cmd_matches.value_of("kubernetes-cluster"),
            cmd_matches.value_of("kubernetes-context"),
            flag_arg("insecure", cmd_matches).unwrap_or(false),
            cmd_matches.value_of("tenant"),
        ),
        ("update", Some(cmd_matches)) => context_update(
            cmd_matches.value_of("context-name"),
            cmd_matches.value_of("url"),
            cmd_matches.value_of("username"),
            cmd_matches.value_of("password"),
            cmd_matches.value_of("token"),
            flag_arg("use-kubernetes", cmd_matches),
            cmd_matches.value_of("kubernetes-cluster"),
            cmd_matches.value_of("kubernetes-context"),
            flag_arg("insecure", cmd_matches),
            cmd_matches.value_of("tenant"),
        ),
        ("switch", Some(cmd_matches)) => {
            context_switch(cmd_matches.value_of("context-name").unwrap())
        }
        ("delete", Some(cmd_matches)) => {
            context_delete(cmd_matches.value_of("context-name").unwrap())
        }
        ("list", Some(_)) => context_list(),
        ("show", Some(cmd_matches)) => context_show(
            cmd_matches
                .value_of("context-name")
                .or_else(|| cmd_matches.value_of("context")),
        ),
        ("current", Some(_)) => context_current(),
        _ => help(app),
    }
}

fn context_encode_file_name<S>(context: S) -> String
where
    S: Into<String>,
{
    utf8_percent_encode(&context.into(), NON_ALPHANUMERIC).collect()
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
    S: AsRef<str>,
{
    let context = context.as_ref().to_string();
    let name = context.trim();

    if name.is_empty() {
        return Err(ErrorKind::ContextNameError(context).into());
    }

    context_contexts_dir().map(|path| path.join(context_encode_file_name(context)))
}

/// Load the provided context.
fn context_load<S>(context: S) -> Result<Context, error::Error>
where
    S: AsRef<str>,
{
    let file = File::open(context_file_path(context.as_ref())?);

    match file {
        Ok(file) => Ok(serde_yaml::from_reader(file)?),
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound => {
                Err(ErrorKind::ContextUnknownError(context.as_ref().to_string()).into())
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
    kubernetes_cluster: Option<&str>,
    kubernetes_context: Option<&str>,
    insecure: bool,
    default_tenant: Option<&str>,
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
        kubernetes_context: kubernetes_context.map(Into::into),
        kubernetes_cluster: kubernetes_cluster.map(Into::into),

        insecure,
        default_tenant: default_tenant.map(Into::into),
    };

    context_store(context, ctx)?;

    println!("Created new context: {} for {}", context, url);
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
    kubernetes_cluster: Option<&str>,
    kubernetes_context: Option<&str>,
    insecure: Option<bool>,
    default_tenant: Option<&str>,
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

    if let Some(p) = kubernetes_cluster {
        if p.is_empty() {
            ctx.kubernetes_cluster = None;
        } else {
            ctx.kubernetes_cluster = Some(p.into());
        }

        println!("\tSetting Kubernetes cluster to: {}", p);
    }

    if let Some(p) = kubernetes_context {
        if p.is_empty() {
            ctx.kubernetes_context = None;
        } else {
            ctx.kubernetes_context = Some(p.into());
        }

        println!("\tSetting Kubernetes context to: {}", p);
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

fn context_show(context: Option<&str>) -> Result<(), error::Error> {
    let context = context
        .map(|s| Ok(s.to_string()))
        .or_else(|| context_get_current().transpose())
        .transpose()
        .and_then(|name| context_names_valid(name))?;

    let ctx = context_load(&context)?;

    println!("   Current context: {}", context);
    println!("               URL: {}", ctx.url);

    println!(
        "          Username: {}",
        ctx.username.unwrap_or_else(|| String::from("<none>"))
    );
    println!(
        "          Password: {}",
        ctx.password.and(Some("***")).unwrap_or("<none>")
    );
    println!(
        "             Token: {}",
        ctx.token.unwrap_or_else(|| String::from("<none>"))
    );
    println!(
        "    Use Kubernetes: {}",
        ctx.use_kubernetes.either("yes", "no")
    );
    if ctx.use_kubernetes {
        println!(
            "Kubernetes cluster: {}",
            ctx.kubernetes_cluster
                .unwrap_or_else(|| String::from("<none>"))
        );
        println!(
            "Kubernetes context: {}",
            ctx.kubernetes_context
                .unwrap_or_else(|| String::from("<none>"))
        );
    }
    println!("      Insecure TLS: {}", ctx.insecure.either("yes", "no"));
    println!(
        "    Default tenant: {}",
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
