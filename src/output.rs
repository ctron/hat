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

use error::Error;

use serde_json::value::Value;

pub fn display_json_value(value: &Value) -> Result<(), Error> {
    println!("{}", ::serde_json::to_string_pretty(&value)?);
    return Ok(());
}