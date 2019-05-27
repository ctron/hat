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

use colored_json::write_colored_json;

use serde_json::value::Value;

use crate::error;
use std::io::stdout;
use std::io::Write;

pub fn display_json_value(value: &Value) -> std::result::Result<(), error::Error> {
    let mut out = stdout();

    {
        let mut out = out.lock();
        write_colored_json(value, &mut out)?;
        out.write_all("\n".as_bytes())?;
    }

    out.flush()?;

    Ok(())
}
