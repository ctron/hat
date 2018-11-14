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

use std::result::Result;
use std::fs::File;

use url::{Url};
use url::percent_encoding::{utf8_percent_encode,percent_decode,DEFAULT_ENCODE_SET};

use clap::{App, ArgMatches};
use help::help;

use std::str::Utf8Error;

use std::path::*;
use std::io::prelude::*;

use hono;
use hono::ErrorKind;

#[derive(Serialize, Deserialize, Debug)]
pub struct Context {
    url: String
}

impl Context {
    pub fn to_url(&self) -> Result<url::Url,url::ParseError> {
        return Url::parse(self.url.as_str());
    }
}

pub fn context(app:& mut App, matches:&ArgMatches) -> Result<(), hono::Error> {

    match matches.subcommand() {
        ( "create", Some(cmd_matches)) => context_create(
            cmd_matches.value_of("context").unwrap(),
            cmd_matches.value_of("url").unwrap()
        ),
        ( "update", Some(cmd_matches)) => context_update(
            cmd_matches.value_of("context").unwrap(),
            cmd_matches.value_of("url").unwrap()
        ),
        ( "switch", Some(cmd_matches)) => context_switch(
            cmd_matches.value_of("context").unwrap()
        ),
        ( "delete", Some(cmd_matches)) => context_delete(
            cmd_matches.value_of("context").unwrap()
        ),
        ( "list", Some(_)) => context_list(),
        ( "show", Some(_)) => context_show(),
        _ => help(app)
    }

}

fn context_encode_file_name(context:&str) -> String {
    let iter = utf8_percent_encode(context,DEFAULT_ENCODE_SET);
    return iter.collect();
}

fn context_decode_file_name(name:&str) -> Result<String,Utf8Error> {
    let iter = percent_decode(name.as_bytes());

    Ok(iter.decode_utf8()?.to_string())
}

fn context_config_dir() -> Result<PathBuf,hono::Error> {
    let dir = dirs::config_dir().expect("Unable to evaluate user's configuration directory");

    return Ok(
        dir
            .join("hat")
    );
}

fn context_contexts_dir() -> Result<PathBuf, hono::Error> {
    context_config_dir()
        .map( | path | path.join("contexts") )
}

fn context_file_path(context:&str) -> Result<PathBuf,hono::Error> {

    let name = context.trim();

    if name.is_empty() {
        return Err(ErrorKind::ContextNameError {context: context.to_string()}.into());
    }

    return context_contexts_dir()
        .map( | path |
            path.join(context_encode_file_name(context))
        );
}

fn context_load(context:&str) -> Result<Context, hono::Error> {
    let file = File::open(context_file_path(context)?)?;

    Ok(serde_yaml::from_reader(file)?)
}


fn context_get_current() -> Result<Option<String>, hono::Error> {

    let path = context_config_dir().map(| path | path.join("current"))?;

    if !path.exists() {
        return Ok(None);
    }

    let mut current = String::new();

    File::open(path)?.read_to_string(& mut current)?;

    return Ok(Some(current));
}

pub fn context_load_current() -> Result<Context, hono::Error> {
    context_get_current()
        .and_then( | result |

            result
                .ok_or_else(|| ErrorKind::GenericError("No context selected. Create a first context or select an existing one.".to_string()).into())
                .and_then(|current| context_load(current.as_str()))

        )
}

fn context_store(context_name:&str, context:Context) -> Result<(), hono::Error> {
    let path = context_file_path(context_name)?;

    std::fs::create_dir_all(path.parent().unwrap())?;

    let mut file = File::create(path)?;

    file.write_all(serde_yaml::to_string(&context)?.as_bytes())?;

    return Ok(());
}

fn context_validate_url(url:&str) -> Result<(), hono::Error> {
    Url::parse(&url)?;
    return Ok(());
}

fn context_create(context:&str, url:&str) -> Result<(), hono::Error> {

    if context_file_path(context)?.exists() {
        return Err(ErrorKind::ContextExistsError {context: context.to_string()}.into());
    }

    context_validate_url(url)?;

    let ctx = Context {
        url: String::from(url)
    };

    context_store(context, ctx)?;
    context_switch(context)?;

    println!("Created new context: {}", context);

    return Ok(());
}

fn context_switch(context:&str) -> Result<(), hono::Error> {

    context_load(context)?;

    let path = context_config_dir().map(| path | path.join("current"))?;

    File::create(path)?.write_all(context.trim().as_bytes())?;

    Ok(())
}

fn context_update(context:&str, url:&str) -> Result<(), hono::Error> {

    if !context_file_path(context)?.exists() {
        return Err(ErrorKind::ContextUnknownError {context: context.to_string()}.into());
    }

    let mut ctx = context_load(context)?;

    context_validate_url(url)?;

    ctx.url = url.to_string();

    context_store(context, ctx)?;

    println!("Updated context '{}' to: {}", context, url);

    return Ok(());
}

fn context_delete(context:&str) -> Result<(), hono::Error> {

    // delete context file

    let path = context_file_path(context)?;
    if path.exists() {
        std::fs::remove_file(path)?;

        // delete "current" marker

        let current = context_get_current()?;
        if current == Some(context.to_string()) {
            let cp = context_config_dir()
                .map( | path | path.join("current") )?;
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

fn context_show() -> Result<(), hono::Error> {
    let context = context_get_current()?;
    let ctx = context_load_current()?;

    println!("Current context: {}", context.unwrap());
    println!("            URL: {}", ctx.url);

    return Ok(());
}

fn context_list() -> Result<(), hono::Error> {

    let path = context_contexts_dir()?;

    if !path.exists() {
        eprintln!("No known contexts");
        return Ok(());
    }

    let current = context_get_current()?;

    for entry in path.read_dir()? {
        let name = context_decode_file_name(entry?.file_name().to_str().unwrap())?;
        print!("{}", name);
        if current == Some(name) {
            print!(" *");
        }
        println!();
    }

    return Ok(());

}