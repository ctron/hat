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

use failure::{Backtrace, Context, Fail};
use std::fmt::{self,Display};

#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

#[derive(Clone, Debug, Fail)]
pub enum ErrorKind {

    #[fail(display="{}", _0)]
    GenericError(String),

    #[fail(display="I/O error: {:?}", _0)]
    Io(::std::io::ErrorKind),

    #[fail(display="Command Line Error: {:?}", _0)]
    CommandLine(::clap::ErrorKind),

    #[fail(display="Request error: {}", _0)]
    Request(String),

    #[fail(display="URL format error")]
    UrlError,

    #[fail(display="JSON format error: {:?}", _0)]
    JsonError(::serde_json::error::Category),

    #[fail(display="YAML format error")]
    YamlError,

    #[fail(display="Invalid UTF-8 string")]
    Utf8Error,

    // context errors

    #[fail(display="Context '{}' already exists", _0)]
    ContextExistsError(String),
    #[fail(display="Unknown context '{}'", _0)]
    ContextUnknownError(String),
    #[fail(display="Invalid context name: {}", _0)]
    ContextNameError(String),

    // API errors
    #[fail(display="Unsupported operation: Wrong API flavor")]
    WrongApiFlavor,

    // remote errors

    #[fail(display="Resource not found: {}", _0)]
    NotFound(String),

    #[fail(display="Resource already exists: {}", _0)]
    AlreadyExists(String),

    #[fail(display="Malformed request")]
    MalformedRequest,

    #[fail(display="Unexpected return code: {}", _0)]
    UnexpectedResult(http::StatusCode)

}

impl Fail for Error {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

#[allow(dead_code)]
impl Error {
    pub fn kind(&self) -> ErrorKind {
        self.inner.get_context().clone()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error { inner: Context::new(kind) }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Error {
        Error { inner }
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        let msg = format!("{}", err);
        err.context(ErrorKind::Request(msg)).into()
    }
}

impl From<url::ParseError> for Error {
    fn from(_err: url::ParseError) -> Error {
        ErrorKind::UrlError.into()
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Error {
        let cat = err.classify();
        err.context(ErrorKind::JsonError(cat)).into()
    }
}

impl From<serde_yaml::Error> for Error {
    fn from(err: serde_yaml::Error) -> Error {
        err.context(ErrorKind::YamlError).into()
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        let kind = err.kind();
        err.context(ErrorKind::Io(kind)).into()
    }
}

impl From<clap::Error> for Error {
    fn from(err: clap::Error) -> Error {
        let kind = err.kind.clone();
        err.context(ErrorKind::CommandLine(kind)).into()
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Error {
        err.context(ErrorKind::Utf8Error).into()
    }
}