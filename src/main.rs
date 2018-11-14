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

extern crate crypto;
extern crate base64;
extern crate rand;

use std::result::Result;
use clap::{Arg, App, SubCommand};

mod context;
mod credentials;
mod hash;
mod help;
mod hono;
mod tenant;
mod registration;
mod resource;

fn app() -> App<'static,'static> {

    let hash_functions = ["sha-256", "sha-512"];

    let args_ctx = Arg::with_name("context")
        .help("Name of the context")
        .required(true)
    ;
    let args_ctx_url = Arg::with_name("url")
        .help("URL to the server")
        .required(true)
    ;

    // tenant

    let args_tenant = Arg::with_name("tenant")
        .help("Name of the tenant")
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

    let app = App::new("hat")
        .version(crate_version!())
        .author("Jens Reimann <jreimann@redhat.com")
        .about("Work with an Eclipse Hono instance")

        .subcommand(SubCommand::with_name("context")

            .about("Work with contexts")

            .subcommand(SubCommand::with_name("create")
                .about("Create a new context")
                .arg(args_ctx.clone())
                .arg(args_ctx_url.clone())
            )
            .subcommand(SubCommand::with_name("update")
                .about("Update an existing context")
                .arg(args_ctx.clone())
                .arg(args_ctx_url.clone())
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

            .subcommand(SubCommand::with_name("create")
                .about("Create a new tenant")
                .arg(args_tenant.clone())
                .arg(args_tenant_payload.clone())
            )


            .subcommand(SubCommand::with_name("update")
                .about("Update an existing tenant")
                .arg(args_tenant.clone())
                .arg(args_tenant_payload.clone())
            )

            .subcommand(SubCommand::with_name("get")
                .about("Get tenant information")
                .arg(args_tenant.clone())
            )

            .subcommand(SubCommand::with_name("delete")
                .about("Delete an existing tenant")
                .arg(args_tenant.clone())
            )

            .subcommand(SubCommand::with_name("enable")
                .about("Enable an existing tenant")
                .arg(args_tenant.clone())
            )

            .subcommand(SubCommand::with_name("disable")
                .about("Disable an existing tenant")
                .arg(args_tenant.clone())
            )
        )

        .subcommand(SubCommand::with_name("reg")
            .about("Work with registrations")

            .subcommand(SubCommand::with_name("create")
                .about("Register a new device")
                .arg(args_tenant.clone())
                .arg(args_device.clone())
                .arg(args_device_payload.clone())
            )

            .subcommand(SubCommand::with_name("get")
                .about("Get a device")
                .arg(args_tenant.clone())
                .arg(args_device.clone())
            )

            .subcommand(SubCommand::with_name("update")
                .about("Update an existing device registration")
                .arg(args_tenant.clone())
                .arg(args_device.clone())
                .arg(args_device_payload.clone())
            )

            .subcommand(SubCommand::with_name("delete")
                .about("Delete a device")
                .arg(args_tenant.clone())
                .arg(args_device.clone())
            )

        )

        .subcommand(SubCommand::with_name("cred")

            .about("Work with device credentials")

            .subcommand(SubCommand::with_name("create")
                .about("Create a new credentials set for an existing device")
                .arg(args_tenant.clone())
                .arg(args_device.clone())
                .arg(args_credentials_auth_id.clone())
                .arg(args_credentials_type.clone())
                .arg(args_credentials_payload.clone())
            )

            .subcommand(SubCommand::with_name("update")
                .about("Update an existing credentials set")
                .arg(args_tenant.clone())
                .arg(args_credentials_auth_id.clone())
                .arg(args_credentials_type.clone())
                .arg(args_credentials_payload.clone())
            )

            .subcommand(SubCommand::with_name("get")
                .about("Get all credentials for an existing device")
                .arg(args_tenant.clone())
                .arg(args_device.clone())
            )

            .subcommand(SubCommand::with_name("get-for")
                .about("Get all credentials by auth ID and type")
                .arg(args_tenant.clone())
                .arg(args_credentials_auth_id.clone())
                .arg(args_credentials_type.clone())
            )

            .subcommand(SubCommand::with_name("delete")
                .about("Delete all credentials for an existing device")
                .arg(args_tenant.clone())
                .arg(args_device.clone())
            )

            .subcommand(SubCommand::with_name("delete-for")
                .about("Delete all credentials by auth ID and type")
                .arg(args_tenant.clone())
                .arg(args_credentials_auth_id.clone())
                .arg(args_credentials_type.clone())
            )

            .subcommand(SubCommand::with_name("enable")
                .about("Enable a set of credentials")
                .arg(args_tenant.clone())
                .arg(args_credentials_auth_id.clone())
                .arg(args_credentials_type.clone())
            )

            .subcommand(SubCommand::with_name("disable")
                .about("Disable a set of credentials")
                .arg(args_tenant.clone())
                .arg(args_credentials_auth_id.clone())
                .arg(args_credentials_type.clone())
            )

            .subcommand(SubCommand::with_name("add-password")
                .about("Add password secret for an existing credentials set")

                .arg(args_tenant.clone())
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
                    .long("create")
                    .takes_value(true)
                    .max_values(1)
                )

            )

            .subcommand(SubCommand::with_name("set-password")
                .about("Set password as the only secret to an existing credentials set")

                .arg(args_tenant.clone())
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

            )

        )
    ;

    return app;
}

fn run() -> Result<(), failure::Error> {

    let mut app = app();
    let matches = app.clone().get_matches();

    let (cmd_name, cmd) = matches.subcommand();

    // process non-network commands

    if cmd_name == "context" {
        context::context(& mut app, cmd.unwrap())?;
        return Ok(());
    }

    // process remote commands

    let context = context::context_load_current()?;

    match cmd_name {
        "tenant" => tenant::tenant(& mut app, cmd.unwrap(), &context)?,
        "reg" => registration::registration(& mut app, cmd.unwrap(), &context)?,
        "cred" => credentials::credentials(& mut app, cmd.unwrap(), &context)?,
        _ => help::help(& mut app)?,
    };

    Ok(())
}

fn main() {
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
