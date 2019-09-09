/*******************************************************************************
 * Copyright (c) 2019 Red Hat Inc
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

use crate::utils::Either;

pub fn use_kubernetes(name: &str, matches: &clap::ArgMatches) -> Option<bool> {
    matches.is_present(name).either(
        Some(matches.value_of(name).map_or(true, map_switch_value)),
        None,
    )
}

pub fn map_switch_value(value: &str) -> bool {
    match value {
        "true" | "yes" | "on" => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_use_kubernetes() {
        let app = clap::App::new("test").arg(
            clap::Arg::with_name("k")
                .short("k")
                .min_values(0)
                .max_values(1)
                .takes_value(true),
        );

        let m = app.clone().get_matches_from(vec!["test"]);
        assert_eq!(use_kubernetes("k", &m), None);

        let m = app.clone().get_matches_from(vec!["test", "-k"]);
        assert_eq!(use_kubernetes("k", &m), Some(true));

        let m = app.clone().get_matches_from(vec!["test", "-k=false"]);
        assert_eq!(use_kubernetes("k", &m), Some(false));

        let m = app.clone().get_matches_from(vec!["test", "-k=true"]);
        assert_eq!(use_kubernetes("k", &m), Some(true));
    }

}
