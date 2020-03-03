/*******************************************************************************
 * Copyright (c) 2018, 2020 Red Hat Inc
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

#[macro_use]
extern crate clap;

#[macro_use]
extern crate log;

#[macro_use]
extern crate serde_derive;

extern crate bcrypt;

use clap::{App, AppSettings, Arg, SubCommand};
use overrides::Overrides;
use simplelog::{Config, LevelFilter, TermLogger};
use std::result::Result;

mod args;
mod client;
mod context;
mod credentials;
mod devices;
mod error;
mod hash;
mod help;
mod output;
mod overrides;
mod resource;
mod tenant;
mod utils;

fn app() -> App<'static, 'static> {
    // globals

    let args_global_verbose = Arg::with_name("verbose")
        .help("Be more verbose, repeat to increase verbosity")
        .global(true)
        .short("v")
        .long("verbose")
        .multiple(true);

    // context

    let args_ctx = Arg::with_name("context")
        .help("Name of the context")
        .number_of_values(1)
        .required(true);
    let args_ctx_url = Arg::with_name("url")
        .help("URL to the server")
        .number_of_values(1)
        .required(true);
    let args_ctx_username = Arg::with_name("username")
        .help("Username for accessing the device registry")
        .long("username")
        .short("u")
        .number_of_values(1);
    let args_ctx_password = Arg::with_name("password")
        .help("Password for accessing the device registry")
        .long("password")
        .short("p")
        .number_of_values(1);
    let args_ctx_token = Arg::with_name("token")
        .help("Bearer token for accessing the device registry")
        .long("token")
        .number_of_values(1);
    let args_ctx_kubernetes = Arg::with_name("kubernetes")
        .help("Use local Kubernetes token for accessing the device registry")
        .long("kubernetes")
        .possible_values(&["true", "false"])
        .min_values(0)
        .max_values(1);
    let args_ctx_default_tenant = Arg::with_name("default-tenant")
        .help("Set the default tenant")
        .long("default-tenant")
        .number_of_values(1);
    let args_ctx_insecure = Arg::with_name("insecure")
        .help("Ignore TLS certificate and hostname (INSECURE!)")
        .long("insecure")
        .possible_values(&["true", "false"])
        .min_values(0)
        .max_values(1);

    // tenant

    let args_tenant_name = Arg::with_name("tenant_name")
        .help("Tenant name")
        .required(true);
    let args_tenant_name_optional = Arg::with_name("tenant_name")
        .help("Tenant name")
        .required(false);
    let args_tenant_payload = Arg::with_name("payload").help("Tenant payload");

    // device

    let args_device = Arg::with_name("device")
        .help("ID of the device")
        .required(true);
    let args_device_optional = Arg::with_name("device")
        .help("ID of the device")
        .required(false);
    let args_device_payload = Arg::with_name("payload").help("Device payload");
    let args_device_via = Arg::with_name("via")
        .help("Gateways of the device")
        .empty_values(false)
        .multiple(true)
        .takes_value(true)
        .required(false);

    // credentials

    let args_credentials_auth_id = Arg::with_name("auth-id")
        .help("Device Authentication ID")
        .required(true);
    let args_credentials_type = Arg::with_name("type")
        .help("Device Authentication Type")
        .required(true);
    let args_credentials_payload =
        Arg::with_name("payload").help("Credentials payload in JSON format");
    let args_credentials_hash_function = Arg::with_name("hash-function")
        .short("h")
        .long("hash")
        .takes_value(true)
        .help("Password hash function [possible values: plain, sha-256, sha-512, bcrypt<:iterations>]")
        .default_value("plain");
    let args_credentials_password = Arg::with_name("password")
        .required(true)
        .help("The plaintext password");
    let args_credentials_psk = Arg::with_name("psk").required(true).help("The PSK value");

    // overrides

    let args_override_url = Arg::with_name("url-override")
        .help("Override the URL")
        .global(true)
        .short("U")
        .long("url")
        .group("overrides")
        .env("HAT_URL")
        .number_of_values(1);

    let args_override_tenant = Arg::with_name("tenant-override")
        .help("Override the default tenant")
        .global(true)
        .short("t")
        .long("tenant")
        .env("HAT_TENANT")
        .number_of_values(1);

    let args_override_context = Arg::with_name("context-override")
        .help("Override the default context")
        .global(true)
        .short("c")
        .long("context")
        .env("HAT_CONTEXT")
        .number_of_values(1);

    let args_override_kubernetes = Arg::with_name("kubernetes-override")
        .help("Override the use of Kubernetes credentials")
        .global(true)
        .long("use-kubernetes")
        .short("k")
        .possible_values(&["true", "false"])
        .min_values(0)
        .max_values(1);

    let args_override_insecure = Arg::with_name("insecure-override")
        .help("Ignore TLS certificate and hostname (INSECURE!)")
        .global(true)
        .long("insecure")
        .possible_values(&["true", "false"])
        .min_values(0)
        .max_values(1);

    let args_overrides = [
        args_override_context,
        args_override_kubernetes,
        args_override_tenant,
        args_override_url,
        args_override_insecure,
    ];

    // main app

    App::new("Hono Admin Tool")
        .version(crate_version!())
        .bin_name("hat")
        .author("Jens Reimann <jreimann@redhat.com>")
        .about("Work with an Eclipse Hono instance")
        .global_setting(AppSettings::VersionlessSubcommands)
        .arg(args_global_verbose)
        .subcommand(
            SubCommand::with_name("context")
                .about("Work with contexts")
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("create")
                        .about("Create a new context")
                        .arg(args_ctx.clone())
                        .arg(args_ctx_url.clone())
                        .arg(args_ctx_username.clone())
                        .arg(args_ctx_password.clone())
                        .arg(args_ctx_token.clone())
                        .arg(args_ctx_kubernetes.clone())
                        .arg(args_ctx_insecure.clone())
                        .arg(args_ctx_default_tenant.clone()),
                )
                .subcommand(
                    SubCommand::with_name("update")
                        .about("Update an existing context")
                        .arg(args_ctx.clone().required(false))
                        .arg(args_ctx_url.clone().required(false))
                        .arg(args_ctx_username.clone())
                        .arg(args_ctx_password.clone())
                        .arg(args_ctx_token.clone())
                        .arg(args_ctx_kubernetes.clone())
                        .arg(args_ctx_insecure.clone())
                        .arg(args_ctx_default_tenant.clone()),
                )
                .subcommand(
                    SubCommand::with_name("delete")
                        .about("Delete a context")
                        .arg(args_ctx.clone()),
                )
                .subcommand(SubCommand::with_name("list").about("List existing contexts"))
                .subcommand(
                    SubCommand::with_name("current").about("Print current selected context"),
                )
                .subcommand(
                    SubCommand::with_name("switch")
                        .about("Switch to existing context")
                        .arg(args_ctx.clone()),
                )
                .subcommand(
                    SubCommand::with_name("show")
                        .about("Show current context information")
                        .arg(args_ctx.clone().required(false)),
                ),
        )
        .subcommand(
            SubCommand::with_name("tenant")
                .about("Work with tenants")
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .args(&args_overrides)
                .subcommand(
                    SubCommand::with_name("create")
                        .about("Create a new tenant")
                        .arg(args_tenant_name_optional.clone())
                        .arg(args_tenant_payload.clone()),
                )
                .subcommand(
                    SubCommand::with_name("update")
                        .about("Update an existing tenant")
                        .arg(args_tenant_name.clone())
                        .arg(args_tenant_payload.clone()),
                )
                .subcommand(
                    SubCommand::with_name("get")
                        .about("Get tenant information")
                        .arg(args_tenant_name.clone()),
                )
                .subcommand(
                    SubCommand::with_name("delete")
                        .about("Delete an existing tenant")
                        .arg(args_tenant_name.clone()),
                )
                .subcommand(
                    SubCommand::with_name("enable")
                        .about("Enable an existing tenant")
                        .arg(args_tenant_name.clone()),
                )
                .subcommand(
                    SubCommand::with_name("disable")
                        .about("Disable an existing tenant")
                        .arg(args_tenant_name.clone()),
                ),
        )
        .subcommand(
            SubCommand::with_name("device")
                .about("Work with devices")
                .args(&args_overrides)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("create")
                        .about("Register a new device")
                        .arg(args_device_optional.clone())
                        .arg(args_device_payload.clone()),
                )
                .subcommand(
                    SubCommand::with_name("get")
                        .about("Get a device")
                        .arg(args_device.clone()),
                )
                .subcommand(
                    SubCommand::with_name("update")
                        .about("Update an existing device registration")
                        .arg(args_device.clone())
                        .arg(args_device_payload.clone()),
                )
                .subcommand(
                    SubCommand::with_name("set-via")
                        .about("Set the gateway configuration")
                        .arg(args_device.clone())
                        .arg(args_device_via.clone()),
                )
                .subcommand(
                    SubCommand::with_name("delete")
                        .about("Delete a device registration")
                        .arg(args_device.clone()),
                )
                .subcommand(
                    SubCommand::with_name("enable")
                        .about("Enable a device registration")
                        .arg(args_device.clone()),
                )
                .subcommand(
                    SubCommand::with_name("disable")
                        .about("Disable a device registration")
                        .arg(args_device.clone()),
                ),
        )
        .subcommand(
            SubCommand::with_name("cred")
                .aliases(&["creds", "auth", "credentials"])
                .about("Work with device credentials")
                .args(&args_overrides)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("set")
                        .about("Set all credentials for device")
                        .arg(args_device.clone())
                        .arg(args_credentials_payload.clone()),
                )
                .subcommand(
                    SubCommand::with_name("get")
                        .about("Get all credentials for an existing device")
                        .arg(args_device.clone()),
                )
                .subcommand(
                    SubCommand::with_name("add-password")
                        .about("Add password secret")
                        .arg(args_device.clone())
                        .arg(args_credentials_auth_id.clone())
                        .arg(args_credentials_hash_function.clone())
                        .arg(args_credentials_password.clone()),
                )
                .subcommand(
                    SubCommand::with_name("set-password")
                        .about("Set password as the only secret")
                        .arg(args_device.clone())
                        .arg(args_credentials_auth_id.clone())
                        .arg(args_credentials_hash_function.clone())
                        .arg(args_credentials_password.clone()),
                )
                .subcommand(
                    SubCommand::with_name("add-psk")
                        .about("Add PSK secret")
                        .arg(args_device.clone())
                        .arg(args_credentials_auth_id.clone())
                        .arg(args_credentials_hash_function.clone())
                        .arg(args_credentials_psk.clone()),
                )
                .subcommand(
                    SubCommand::with_name("set-psk")
                        .about("Set PSK as the only secret")
                        .arg(args_device.clone())
                        .arg(args_credentials_auth_id.clone())
                        .arg(args_credentials_psk.clone()),
                )
                .subcommand(
                    SubCommand::with_name("delete")
                        .about("Delete a credential set from a device")
                        .arg(args_device.clone())
                        .arg(args_credentials_type.clone())
                        .arg(args_credentials_auth_id.clone()),
                )
                .subcommand(
                    SubCommand::with_name("delete-all")
                        .about("Delete all credentials for a device")
                        .arg(args_device.clone()),
                ),
        )
}

fn run() -> Result<(), failure::Error> {
    let mut app = app();
    let matches = app.clone().get_matches();

    let level_filter = match matches.occurrences_of("verbose") {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    let cfg = Config::default();
    TermLogger::init(level_filter, cfg).unwrap();

    debug!("Args: {:#?}", matches);

    // fill overrides
    let overrides = Overrides::from(&matches);

    let (cmd_name, cmd) = matches.subcommand();

    // process non-network commands

    if cmd_name == "context" {
        context::context(&mut app, cmd.unwrap())?;
        return Ok(());
    }

    // process remote commands

    let context = context::context_load_current(Some(&overrides))?;

    match cmd_name {
        "tenant" => tenant::tenant(&mut app, cmd.unwrap(), &overrides, &context)?,
        "device" => devices::registration(&mut app, cmd.unwrap(), &overrides, &context)?,
        "cred" => credentials::credentials(&mut app, cmd.unwrap(), &overrides, &context)?,
        _ => help::help(&mut app)?,
    };

    Ok(())
}

fn main() {
    #[cfg(windows)]
    let _enabled = colored_json::enable_ansi_support();

    let rc = run();

    if let Err(err) = rc {
        eprintln!("{}", err);

        if let Some(cause) = err.as_fail().cause() {
            eprintln!("{}", cause);
        }

        let backtrace = err.backtrace().to_string();
        if !backtrace.trim().is_empty() {
            eprintln!("{}", backtrace);
        }

        std::process::exit(1);
    }
}
