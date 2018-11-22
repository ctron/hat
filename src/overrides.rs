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

pub struct Overrides {
    context: Option<String>,
    tenant: Option<String>,
}

impl Overrides {
    pub fn context(&self) -> Option<String> {
        self.context.clone()
    }
    pub fn tenant(&self) -> Option<String> {
        self.tenant.clone()
    }
}

impl <'a> From<&'a clap::ArgMatches<'a>> for Overrides {
    fn from(matches: &'a clap::ArgMatches) -> Self {
        Overrides{
            context: matches.value_of("context-override").map(|s|s.to_string()),
            tenant: matches.value_of("tenant-override").map(|s|s.to_string()),
        }
    }
}