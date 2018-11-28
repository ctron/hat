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

use serde_json::value::Value;
use serde_json::ser::{Formatter, PrettyFormatter};
use serde::{Serialize};

use colored::*;

use std::io;

use error;

pub struct ColoredFormatter<'a, F: 'a>
    where F: Formatter
{
    formatter: &'a mut F,
    colorizer: Vec<&'a Fn(ColoredString) -> ColoredString>,
}

impl <'a, F> ColoredFormatter<'a, F>
    where
        F: Formatter
{
    pub fn new(formatter: &'a mut F) -> Self {
        return ColoredFormatter{
            formatter,
            colorizer: Vec::new(),
        };
    }
}

fn color_object_key (c: ColoredString) -> ColoredString {
    c.bright_blue().bold()
}

fn colored<W: ?Sized, C: ?Sized, H> ( writer: &mut W, colorizer: Option<&C>, mut handler: H ) -> io::Result<()>
    where
        W: io::Write,
        C: Fn(ColoredString) -> ColoredString,
        H: FnMut(& mut Vec<u8>) -> io::Result<()>,
{
    let mut w : Vec<u8> = Vec::with_capacity(128);
    handler(& mut w)?;
    let s = String::from_utf8_lossy(&w);

    let out = match colorizer {
        Some(c) => format!("{}", c(ColoredString::from(s.as_ref()))),
        None => s.to_string(),
    };
    Ok(writer.write_all(out.as_bytes())?)
}

impl <'a, F> Formatter for ColoredFormatter<'a, F>
    where
        F: Formatter
{
    fn write_null<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.write_null(writer)
    }

    fn write_bool<W: ?Sized>(&mut self, writer: &mut W, value: bool) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.write_bool(writer, value)
    }

    fn write_i8<W: ?Sized>(&mut self, writer: &mut W, value: i8) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.write_i8(writer, value)
    }

    fn write_i16<W: ?Sized>(&mut self, writer: &mut W, value: i16) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.write_i16(writer, value)
    }

    fn write_i32<W: ?Sized>(&mut self, writer: &mut W, value: i32) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.write_i32(writer, value)
    }

    fn write_i64<W: ?Sized>(&mut self, writer: &mut W, value: i64) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.write_i64(writer, value)
    }

    fn write_u8<W: ?Sized>(&mut self, writer: &mut W, value: u8) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.write_u8(writer, value)
    }

    fn write_u16<W: ?Sized>(&mut self, writer: &mut W, value: u16) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.write_u16(writer, value)
    }

    fn write_u32<W: ?Sized>(&mut self, writer: &mut W, value: u32) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.write_u32(writer, value)
    }

    fn write_u64<W: ?Sized>(&mut self, writer: &mut W, value: u64) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.write_u64(writer, value)
    }

    fn write_f32<W: ?Sized>(&mut self, writer: &mut W, value: f32) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.write_f32(writer, value)
    }

    fn write_f64<W: ?Sized>(&mut self, writer: &mut W, value: f64) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.write_f64(writer, value)
    }

    fn write_number_str<W: ?Sized>(&mut self, writer: &mut W, value: &str) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.write_number_str(writer, value)
    }

    fn begin_string<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
        where
            W: io::Write,
    {
        colored(writer, self.colorizer.last().map(Clone::clone), |w| self.formatter.begin_string(w))
    }

    fn end_string<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
        where
            W: io::Write,
    {
        colored(writer, self.colorizer.last().map(Clone::clone), |w| self.formatter.end_string(w))
    }

    fn write_string_fragment<W: ?Sized>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()>
        where
            W: io::Write,
    {
        colored(writer, self.colorizer.last().map(Clone::clone), |w| self.formatter.write_string_fragment(w, fragment))
    }

    fn begin_array<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.begin_array(writer)
    }

    fn end_array<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.end_array(writer)
    }

    fn begin_array_value<W: ?Sized>(&mut self, writer: &mut W, first: bool) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.begin_array_value(writer, first)
    }

    fn end_array_value<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.end_array_value(writer)
    }

    fn begin_object<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
        where
            W: io::Write,
    {
        colored(writer, Some(&Colorize::bold), |w| self.formatter.begin_object(w))
    }

    fn end_object<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
        where
            W: io::Write,
    {
        colored(writer, Some(&Colorize::bold), |w| self.formatter.end_object(w))
    }

    fn begin_object_key<W: ?Sized>(&mut self, writer: &mut W, first: bool) -> io::Result<()>
        where
            W: io::Write,
    {
        self.colorizer.push(&color_object_key);
        self.formatter.begin_object_key(writer, first)
    }

    fn end_object_key<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.end_object_key(writer)?;
        self.colorizer.pop();
        Ok(())
    }

    fn begin_object_value<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
        where
            W: io::Write,
    {
        self.colorizer.push(&Colorize::green);
        self.formatter.begin_object_value(writer)
    }

    fn end_object_value<W: ?Sized>(&mut self, writer: &mut W) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.end_object_value(writer)?;
        self.colorizer.pop();
        Ok(())
    }

    fn write_raw_fragment<W: ?Sized>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()>
        where
            W: io::Write,
    {
        self.formatter.write_raw_fragment(writer, fragment)
    }

}

pub fn display_json_value(value: &Value) -> std::result::Result<(), error::Error> {
    let mut formatter = PrettyFormatter::new();
    let formatter = ColoredFormatter::new(& mut formatter);

    let mut writer : Vec<u8> = Vec::with_capacity(128);
    {
        let mut serializer = serde_json::Serializer::with_formatter(&mut writer, formatter);
        value.serialize(& mut serializer)?;
    }

    println!("{}", String::from_utf8(writer)?);

    return Ok(());
}