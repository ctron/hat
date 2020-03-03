/*******************************************************************************
 * Copyright (c) 2019, 2020 Red Hat Inc
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

pub fn flag_arg(name: &str, matches: &clap::ArgMatches) -> Option<bool> {
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

    fn setup<'a, 'b>() -> clap::App<'a, 'b> {
        clap::App::new("test").arg(
            clap::Arg::with_name("k")
                .short("k")
                .min_values(0)
                .max_values(1)
                .takes_value(true),
        )
    }

    #[test]
    fn test_flag_arg_1() {
        let app = setup();
        let m = app.get_matches_from(vec!["test"]);
        assert_eq!(flag_arg("k", &m), None);
    }

    #[test]
    fn test_flag_arg_2() {
        let app = setup();
        let m = app.get_matches_from(vec!["test", "-k"]);
        assert_eq!(flag_arg("k", &m), Some(true));
    }

    #[test]
    fn test_flag_arg_3() {
        let app = setup();
        let m = app.get_matches_from(vec!["test", "-k=false"]);
        assert_eq!(flag_arg("k", &m), Some(false));
    }

    #[test]
    fn test_flag_arg_4() {
        let app = setup();

        let m = app.get_matches_from(vec!["test", "-k=true"]);
        assert_eq!(flag_arg("k", &m), Some(true));
    }
}
