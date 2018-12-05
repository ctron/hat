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

#[macro_use]
extern crate clap;

#[macro_use]
extern crate log;
extern crate simplelog;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;
extern crate serde_yaml;

extern crate failure;
#[macro_use]
extern crate failure_derive;
extern crate url;
extern crate dirs;

extern crate reqwest;
extern crate http;

extern crate hyper;

extern crate base64;
extern crate rand;

extern crate sha2;

extern crate colored;
extern crate colored_json;

use std::result::Result;
use clap::{Arg, App, SubCommand, AppSettings};
use simplelog::{LevelFilter,TermLogger,Config};
use overrides::Overrides;

mod context;
mod credentials;
mod hash;
mod help;
mod error;
mod output;
mod overrides;
mod registration;
mod resource;
mod tenant;
mod utils;

fn app() -> App<'static,'static> {

    let hash_functions = ["sha-256", "sha-512"];

    // context

    let args_ctx = Arg::with_name("context")
        .help("Name of the context")
        .required(true)
    ;
    let args_ctx_url = Arg::with_name("url")
        .help("URL to the server")
        .required(true)
    ;
    let args_ctx_username = Arg::with_name("username")
        .help("Username for accessing the device registry")
        .long("username")
        .short("u")
        .takes_value(true)
    ;
    let args_ctx_password = Arg::with_name("password")
        .help("Password for accessing the device registry")
        .long("password")
        .short("p")
        .takes_value(true)
    ;
    let args_ctx_default_tenant = Arg::with_name("default_tenant")
        .help("Set the default tenant")
        .long("default-tenant")
        .takes_value(true)
    ;
    let args_ctx_api_flavor = Arg::with_name("api_flavor")
        .help("Set the API flavor")
        .long("api-flavor")
        .alias("api-flavour")
        .possible_values(&["hono", "iothub"])
        .takes_value(true)
    ;

    // tenant

    let args_tenant_name = Arg::with_name("tenant_name")
        .help("Tenant name")
        .required(true)
    ;
    let args_tenant_payload = Arg::with_name("payload")
        .help("Tenant payload")
    ;

    // device

    let args_device = Arg::with_name("device")
        .help("ID of the device")
        .required(true)
    ;
    let args_device_payload = Arg::with_name("payload")
        .help("Device payload")
    ;

    // credentials

    let args_credentials_type = Arg::with_name("type")
        .help("Type of credentials")
        .required(true)
    ;
    let args_credentials_auth_id = Arg::with_name("auth-id")
        .help("Device Authentication ID")
        .required(true)
    ;
    let args_credentials_payload = Arg::with_name("payload")
        .help("Credentials payload in JSON format")
    ;

    // overrides

    let args_override_tenant = Arg::with_name("tenant-override")
        .help("Override the default tenant")
        .global(true)
        .short("t")
        .long("tenant")
        .takes_value(true)
    ;

    let args_override_context = Arg::with_name("context-override")
        .help("Override the default context")
        .global(true)
        .short("c")
        .long("context")
        .takes_value(true)
    ;

    // main app

    let app = App::new("Hono Admin Tool")
        .version(crate_version!())
        .bin_name("hat")
        .author("Jens Reimann <jreimann@redhat.com>")
        .about("Work with an Eclipse Hono instance")

        .setting(AppSettings::VersionlessSubcommands)

        .arg(Arg::with_name("verbose")
            .help("Be more verbose, repeat to increase verbosity")
            .global(true)
            .short("v")
            .long("verbose")
            .multiple(true)
        )

        .arg(args_override_tenant.clone())
        .arg(args_override_context.clone())

        .subcommand(SubCommand::with_name("context")

            .about("Work with contexts")
            .setting(AppSettings::SubcommandRequiredElseHelp)

            .subcommand(SubCommand::with_name("create")
                .about("Create a new context")
                .arg(args_ctx.clone())
                .arg(args_ctx_url.clone())
                .arg(args_ctx_username.clone())
                .arg(args_ctx_password.clone())
                .arg(args_ctx_default_tenant.clone())
                .arg(args_ctx_api_flavor.clone())
            )
            .subcommand(SubCommand::with_name("update")
                .about("Update an existing context")
                .arg(args_ctx.clone())
                .arg(Arg::with_name("url")
                    .long("url")
                    .help("The new url to set")
                    .takes_value(true)
                )
                .arg(args_ctx_username.clone())
                .arg(args_ctx_password.clone())
                .arg(args_ctx_default_tenant.clone())
                .arg(args_ctx_api_flavor.clone())
            )
            .subcommand(SubCommand::with_name("delete")
                .about("Delete a context")
                .arg(args_ctx.clone())
            )
            .subcommand(SubCommand::with_name("list")
                .about("List existing contexts")
            )
            .subcommand(SubCommand::with_name("switch")
                .about("Switch to existing context")
                .arg(args_ctx.clone())
            )
            .subcommand(SubCommand::with_name("show")
                .about("Show current context information")
            )
        )

        .subcommand(SubCommand::with_name("tenant")
            .about("Work with tenants")
            .setting(AppSettings::SubcommandRequiredElseHelp)

            .subcommand(SubCommand::with_name("create")
                .about("Create a new tenant")
                .arg(args_tenant_name.clone())
                .arg(args_tenant_payload.clone())
            )

            .subcommand(SubCommand::with_name("update")
                .about("Update an existing tenant")
                .arg(args_tenant_name.clone())
                .arg(args_tenant_payload.clone())
            )

            .subcommand(SubCommand::with_name("get")
                .about("Get tenant information")
                .arg(args_tenant_name.clone())
            )

            .subcommand(SubCommand::with_name("delete")
                .about("Delete an existing tenant")
                .arg(args_tenant_name.clone())
            )

            .subcommand(SubCommand::with_name("enable")
                .about("Enable an existing tenant")
                .arg(args_tenant_name.clone())
            )

            .subcommand(SubCommand::with_name("disable")
                .about("Disable an existing tenant")
                .arg(args_tenant_name.clone())
            )
        )

        .subcommand(SubCommand::with_name("reg")
            .about("Work with registrations")
            .setting(AppSettings::SubcommandRequiredElseHelp)

            // .arg(args_tenant.clone())

            .subcommand(SubCommand::with_name("create")
                .about("Register a new device")
                .arg(args_device.clone())
                .arg(args_device_payload.clone())
            )

            .subcommand(SubCommand::with_name("get")
                .about("Get a device")
                .arg(args_device.clone())
            )

            .subcommand(SubCommand::with_name("update")
                .about("Update an existing device registration")
                .arg(args_device.clone())
                .arg(args_device_payload.clone())
            )

            .subcommand(SubCommand::with_name("delete")
                .about("Delete a device registration")
                .arg(args_device.clone())
            )

            .subcommand(SubCommand::with_name("enable")
                .about("Enable a device registration")
                .arg(args_device.clone())
            )

            .subcommand(SubCommand::with_name("disable")
                .about("Disable a device registration")
                .arg(args_device.clone())
            )

        )

        .subcommand(SubCommand::with_name("cred")

            .about("Work with device credentials")
            .setting(AppSettings::SubcommandRequiredElseHelp)

            // .arg(args_tenant.clone())

            .subcommand(SubCommand::with_name("create")
                .about("Create a new credentials set for an existing device")
                .arg(args_device.clone())
                .arg(args_credentials_auth_id.clone())
                .arg(args_credentials_type.clone())
                .arg(args_credentials_payload.clone())
            )

            .subcommand(SubCommand::with_name("update")
                .about("Update an existing credentials set")
                .arg(args_credentials_auth_id.clone())
                .arg(args_credentials_type.clone())
                .arg(args_credentials_payload.clone())
            )

            .subcommand(SubCommand::with_name("get")
                .about("Get all credentials for an existing device")
                .arg(args_device.clone())
            )

            .subcommand(SubCommand::with_name("get-for")
                .about("Get all credentials by auth ID and type")
                .arg(args_credentials_auth_id.clone())
                .arg(args_credentials_type.clone())
            )

            .subcommand(SubCommand::with_name("delete")
                .about("Delete all credentials for an existing device")
                .arg(args_device.clone())
            )

            .subcommand(SubCommand::with_name("delete-for")
                .about("Delete all credentials by auth ID and type")
                .arg(args_credentials_auth_id.clone())
                .arg(args_credentials_type.clone())
            )

            .subcommand(SubCommand::with_name("enable")
                .about("Enable a set of credentials")
                .arg(args_credentials_auth_id.clone())
                .arg(args_credentials_type.clone())
            )

            .subcommand(SubCommand::with_name("disable")
                .about("Disable a set of credentials")
                .arg(args_credentials_auth_id.clone())
                .arg(args_credentials_type.clone())
            )

            .subcommand(SubCommand::with_name("add-password")
                .about("Add password secret for an existing credentials set")

                .arg(args_credentials_auth_id.clone())

                .arg(Arg::with_name("hash-function")
                    .required(true)
                    .help("Password hash function")
                    .possible_values(&hash_functions)
                )

                .arg(Arg::with_name("password")
                    .required(true)
                    .help("The plaintext password")
                )

                .arg(Arg::with_name("device")
                    .help("Create credentials set for device if necessary")
                    .long("device")
                    .takes_value(true)
                    .max_values(1)
                )

            )

            .subcommand(SubCommand::with_name("set-password")
                .about("Set password as the only secret to an existing credentials set")

                .arg(args_credentials_auth_id.clone())

                .arg(Arg::with_name("hash-function")
                    .required(true)
                    .help("Password hash function")
                    .possible_values(&hash_functions)
                )

                .arg(Arg::with_name("password")
                    .required(true)
                    .help("The plaintext password")
                )

                .arg(Arg::with_name("device")
                    .help("Create credentials set for device if necessary")
                    .long("device")
                    .takes_value(true)
                    .max_values(1)
                )

            )

        )
    ;

    return app;
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
    TermLogger::init(level_filter,cfg).unwrap();

    debug!("Args: {:#?}", matches);

    // fill overrides
    let overrides = Overrides::from(&matches);

    let (cmd_name, cmd) = matches.subcommand();

    // process non-network commands

    if cmd_name == "context" {
        context::context(& mut app, cmd.unwrap())?;
        return Ok(());
    }

    // process remote commands

    let context = context::context_load_current(Some(&overrides))?;

    match cmd_name {
        "tenant" => tenant::tenant(& mut app, cmd.unwrap(), &overrides, &context)?,
        "reg" => registration::registration(& mut app, cmd.unwrap(), &overrides, &context)?,
        "cred" => credentials::credentials(& mut app, cmd.unwrap(), &overrides, &context)?,
        _ => help::help(& mut app)?,
    };

    Ok(())
}

fn main() {

    #[cfg(windows)]
    let _enabled = colored_json::enable_ansi_support();

    let rc = run();

    if rc.is_err() {

        let err = rc.err().unwrap();

        eprintln!("Execution failed: {}", err);

        let backtrace = err.backtrace().to_string();
        if !backtrace.trim().is_empty() {
            eprintln!("{}", backtrace);
        }

        std::process::exit(1);
    }
}
