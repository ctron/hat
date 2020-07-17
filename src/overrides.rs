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

use crate::args::flag_arg;

pub struct Overrides {
    context: Option<String>,
    url: Option<String>,
    tenant: Option<String>,
    use_kubernetes: Option<bool>,
    kubernetes_context: Option<String>,
    kubernetes_cluster: Option<String>,
    insecure: Option<bool>,
}

impl Overrides {
    pub fn context(&self) -> Option<String> {
        self.context.clone()
    }
    pub fn url(&self) -> Option<&String> {
        self.url.as_ref()
    }
    pub fn tenant(&self) -> Option<String> {
        self.tenant.clone()
    }
    pub fn use_kubernetes(&self) -> Option<bool> {
        self.use_kubernetes
    }
    pub fn kubernetes_cluster(&self) -> Option<&String> {
        self.kubernetes_cluster.as_ref()
    }
    pub fn kubernetes_context(&self) -> Option<&String> {
        self.kubernetes_context.as_ref()
    }
    pub fn insecure(&self) -> Option<bool> {
        self.insecure
    }
}

impl<'a> From<&'a clap::ArgMatches<'a>> for Overrides {
    fn from(matches: &'a clap::ArgMatches) -> Self {
        Overrides {
            context: matches.value_of("context").map(ToString::to_string),
            url: matches.value_of("url").map(ToString::to_string),
            tenant: matches.value_of("tenant").map(ToString::to_string),
            use_kubernetes: flag_arg("use-kubernetes", matches),
            kubernetes_cluster: matches
                .value_of("kubernetes-cluster")
                .map(ToString::to_string),
            kubernetes_context: matches
                .value_of("kubernetes-context")
                .map(ToString::to_string),
            insecure: flag_arg("insecure", matches),
        }
    }
}
