// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::env;
use std::fmt;
use std::result;

pub type Result<T> = result::Result<T, Error>;

const ARG_PREFIX: &str = "--";
const ARG_SEPARATOR: &str = "--";
const FLAG_PROVIDED: &str = "true";
const HELP_ARG: &str = "--help";

/// Errors associated with parsing and validating arguments.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// The required argument was not provided.
    MissingArgument(String),
    /// A value for the argument was not provided.
    MissingValue(String),
    /// The provided argument was not expected.
    UnexpectedArgument(String),
    /// The argument was provided more than once.
    DuplicateArgument(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            MissingArgument(ref arg) => write!(f, "Argument '{}' required, but not found.", arg),
            MissingValue(ref arg) => write!(
                f,
                "The argument '{}' requires a value, but none was supplied.",
                arg
            ),
            UnexpectedArgument(ref arg) => write!(
                f,
                "Found argument '{}' which wasn't expected, or isn't valid in this context.",
                arg
            ),
            DuplicateArgument(ref arg) => {
                write!(f, "The argument '{}' was provided more than once.", arg)
            }
        }
    }
}

/// Used for setting the characteristics of the `name` command line argument.
#[derive(Clone, Debug, PartialEq)]
pub struct ArgInfo<'a> {
    name: &'a str,
    required: bool,
    requires: Option<&'a str>,
    takes_value: bool,
    default_value: Option<&'a str>,
    help: Option<&'a str>,
    user_value: Option<String>,
}

impl<'a> ArgInfo<'a> {
    /// Create a new `ArgInfo` that keeps the necessary information for an argument.
    pub fn new(name: &'a str) -> ArgInfo<'a> {
        ArgInfo {
            name,
            required: false,
            requires: None,
            takes_value: false,
            default_value: None,
            help: None,
            user_value: None,
        }
    }

    /// Set if the argument *must* be provided by user.
    pub fn required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }

    /// Set that `requires` argument *must* be also provided if the current argument was.
    pub fn requires(mut self, requires: &'a str) -> Self {
        self.requires = Some(requires);
        self
    }

    /// If `takes_value` is true, then the user *must* provide a value for the
    /// argument, otherwise that argument is a flag.
    pub fn takes_value(mut self, takes_value: bool) -> Self {
        self.takes_value = takes_value;
        self
    }

    /// Keep a default value which will be used if the user didn't provide a value for
    /// the argument.
    pub fn default_value(mut self, default_value: &'a str) -> Self {
        self.default_value = Some(default_value);
        self
    }

    /// Return the value of the argument, which will be the user's one if it was provided,
    /// the default value if not or `None` if there isn't a value for that argument at all.
    pub fn get_value(&self) -> Option<String> {
        if let Some(user_value) = &self.user_value {
            return Some(user_value.clone());
        } else if let Some(default_value) = self.default_value {
            return Some(default_value.to_string());
        }
        None
    }

    /// Set the information that will be displayed for the argument when user passes
    /// `--help` flag.
    pub fn help(mut self, help: &'a str) -> Self {
        self.help = Some(help);
        self
    }

    fn format_help(&self) -> String {
        let mut help_builder = vec![];

        help_builder.push(format!("--{}", self.name));

        if self.takes_value {
            help_builder.push(format!(" <{}>", self.name));
        }

        if let Some(help) = self.help {
            help_builder.push(format!(": {}", help));
        }
        help_builder.concat()
    }
}

/// Used for setting that `--help` flag was provided by user.
pub enum Help {
    Provided,
    NotProvided,
}

/// Keep information about the command line argument parser.
///
/// * `args` - A Hash Map in which the key is an argument and the value is its associated `ArgInfo`.
/// * `extra_args` - The arguments specified after `--` (i.e. end of command options).
/// * `header` - This is used for storing general information about the process.
#[derive(Debug, Default, PartialEq)]
pub struct ArgParser<'a> {
    args: HashMap<&'a str, ArgInfo<'a>>,
    extra_args: Vec<String>,
    header: String,
}

impl<'a> ArgParser<'a> {
    /// Add an argument with its associated `ArgInfo` in `args` map.
    pub fn arg(mut self, arg_info: ArgInfo<'a>) -> Self {
        self.args.insert(arg_info.name, arg_info);
        self
    }

    /// Set general information about the running application.
    pub fn header(mut self, header: String) -> Self {
        self.header = header;
        self
    }

    /// Concatenate the `help` information of every possible argument
    /// in a message that represents the correct command line usage
    /// for the application.
    pub fn format_help(&self) -> String {
        let mut help_builder = vec![];

        help_builder.push(format!("{}\n", self.header));

        for arg in self.args.values() {
            help_builder.push(format!("{}\n", arg.format_help()));
        }

        help_builder.concat()
    }

    /// Used for getting the value for an optional argument (i.e. that is
    /// neither required nor has a default value).
    pub fn value(&self, arg_name: &'static str) -> Option<String> {
        // Safe to unwrap because we are searching in the map only
        // for valid args.
        self.args.get(arg_name).unwrap().user_value.clone()
    }

    /// Set the extra arguments for the argument parser.
    pub fn extra_args(self) -> Vec<String> {
        self.extra_args
    }

    // Splits `args` in two slices: one with the actual arguments of the process and the other with
    // the extra arguments, meaning all parameters specified after `--`.
    fn split_args(args: &[String]) -> (&[String], &[String]) {
        if let Some(index) = args.iter().position(|arg| arg == ARG_SEPARATOR) {
            return (&args[..index], &args[index + 1..]);
        }

        (&args, &[])
    }

    /// Collect the command line arguments and the values provided for them.
    pub fn parse(&mut self) -> Result<Help> {
        let args: Vec<String> = env::args().collect();

        // Skipping the first element of `args` as it is the name of the binary, not an actual argument.
        let (args, extra_args) = ArgParser::split_args(&args[1..]);
        self.extra_args = extra_args.to_vec();

        if args.contains(&HELP_ARG.to_string()) {
            return Ok(Help::Provided);
        }

        self.populate_args(args);

        Ok(Help::NotProvided)
    }

    // Check if `required` and `requires` field rules are indeed followed by every argument.
    fn validate_requirements(&self, args: &[String]) -> Result<()> {
        for arg_info in self.args.values() {
            // The arguments that are marked `required` must be provided by user.
            if arg_info.required && arg_info.user_value.is_none() {
                return Err(Error::MissingArgument(arg_info.name.to_string()));
            }
            // For the arguments that require a specific argument to be also present in the list
            // of arguments provided by user, search for that argument.
            if arg_info.user_value.is_some() {
                if let Some(arg_name) = arg_info.requires {
                    if !args.contains(&(format!("--{}", arg_name))) {
                        return Err(Error::MissingArgument(arg_name.to_string()));
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_arg(&self, arg: &str) -> Result<()> {
        if !arg.starts_with(ARG_PREFIX) {
            return Err(Error::UnexpectedArgument(arg.to_string()));
        }
        let arg_name = &arg[ARG_PREFIX.len()..];

        // Check if the argument is an expected one.
        if !self.args.contains_key(arg_name) {
            return Err(Error::UnexpectedArgument(arg_name.to_string()));
        }

        // Check if the argument was not provided more than once.
        if self.args.get(arg_name).unwrap().user_value.is_some() {
            return Err(Error::DuplicateArgument(arg_name.to_string()));
        }
        Ok(())
    }

    /// Validate the arguments provided by user and their values. Insert those
    /// values in the `ArgInfo` instances of the corresponding arguments.
    pub fn populate_args(&mut self, args: &[String]) -> Result<()> {
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            self.validate_arg(arg)?;

            let arg_info = self
                .args
                .get_mut(&arg[ARG_PREFIX.len()..])
                .ok_or_else(|| Error::UnexpectedArgument(arg[ARG_PREFIX.len()..].to_string()))?;

            let val = if arg_info.takes_value {
                iter.next()
                    .filter(|v| !v.starts_with(ARG_PREFIX))
                    .ok_or_else(|| Error::MissingValue(arg_info.name.to_string()))?
            } else {
                FLAG_PROVIDED
            };

            arg_info.user_value = Some(val.to_string());
        }

        self.validate_requirements(&args)?;

        Ok(())
    }

    /// Extracts an argument's value or returns a specific error if the argument is missing.
    pub fn arg_value(&self, arg_name: &'static str) -> Result<String> {
        self.args
            .get(arg_name)
            .ok_or_else(|| Error::UnexpectedArgument(arg_name.to_string()))?
            .get_value()
            .ok_or_else(|| Error::MissingValue(arg_name.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_parser() -> ArgParser<'static> {
        ArgParser::default()
            .header("App info".to_string())
            .arg(
                ArgInfo::new("exec-file")
                    .required(true)
                    .takes_value(true)
                    .help("'exec-file' info."),
            )
            .arg(
                ArgInfo::new("no-api")
                    .requires("config-file")
                    .takes_value(false)
                    .help("'no-api' info."),
            )
            .arg(
                ArgInfo::new("api-sock")
                    .takes_value(true)
                    .default_value("socket")
                    .help("'api-sock' info."),
            )
            .arg(
                ArgInfo::new("id")
                    .takes_value(true)
                    .default_value("instance")
                    .help("'id' info."),
            )
            .arg(
                ArgInfo::new("seccomp-level")
                    .takes_value(true)
                    .default_value("2")
                    .help("'seccomp-level' info."),
            )
            .arg(
                ArgInfo::new("config-file")
                    .takes_value(true)
                    .help("'config-file' info."),
            )
    }

    #[test]
    fn test_arg_help() {
        // Checks help format for an argument.
        let mut arg_info = ArgInfo::new("exec-file").required(true).takes_value(true);

        assert_eq!(arg_info.format_help(), "--exec-file <exec-file>");

        arg_info = ArgInfo::new("exec-file")
            .required(true)
            .takes_value(true)
            .help("'exec-file' info.");

        assert_eq!(
            arg_info.format_help(),
            "--exec-file <exec-file>: 'exec-file' info."
        );

        arg_info = ArgInfo::new("no-api")
            .requires("config-file")
            .takes_value(false);

        assert_eq!(arg_info.format_help(), "--no-api");

        arg_info = ArgInfo::new("no-api")
            .requires("config-file")
            .takes_value(false)
            .help("'no-api' info.");

        assert_eq!(arg_info.format_help(), "--no-api: 'no-api' info.");
    }

    #[test]
    fn test_parser_help() {
        // Checks help information when user passes `--help` flag.
        let arg_parser = ArgParser::default().header("App info".to_string()).arg(
            ArgInfo::new("exec-file")
                .required(true)
                .takes_value(true)
                .help("'exec-file' info."),
        );
        assert_eq!(
            arg_parser.format_help(),
            "App info\n--exec-file <exec-file>: \'exec-file\' info.\n"
        );
    }

    #[test]
    fn test_populate_args() {
        let mut arg_parser = build_parser();

        // Test different scenarios for the command line arguments provided by user.
        let args = vec!["--exec-file", "foo", "--api-sock", "--id", "bar"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<String>>();

        assert_eq!(
            arg_parser.populate_args(&args),
            Err(Error::MissingValue("api-sock".to_string()))
        );

        arg_parser = build_parser();

        let args = vec![
            "--exec-file",
            "foo",
            "--api-sock",
            "bar",
            "--api-sock",
            "foobar",
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<String>>();

        assert_eq!(
            arg_parser.populate_args(&args),
            Err(Error::DuplicateArgument("api-sock".to_string()))
        );

        arg_parser = build_parser();

        let args = vec!["--api-sock", "foo"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<String>>();

        assert_eq!(
            arg_parser.populate_args(&args),
            Err(Error::MissingArgument("exec-file".to_string()))
        );

        arg_parser = build_parser();

        let args = vec!["--exec-file", "foo", "--api-sock", "bar", "--invalid-arg"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<String>>();

        assert_eq!(
            arg_parser.populate_args(&args),
            Err(Error::UnexpectedArgument("invalid-arg".to_string()))
        );

        arg_parser = build_parser();

        let args = vec![
            "--exec-file",
            "foo",
            "--api-sock",
            "bar",
            "--id",
            "foobar",
            "--no-api",
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<String>>();

        assert_eq!(
            arg_parser.populate_args(&args),
            Err(Error::MissingArgument("config-file".to_string()))
        );

        arg_parser = build_parser();

        let args = vec!["--exec-file", "foo", "--api-sock", "bar", "--id"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<String>>();

        assert_eq!(
            arg_parser.populate_args(&args),
            Err(Error::MissingValue("id".to_string()))
        );

        arg_parser = build_parser();

        let args = vec![
            "--exec-file",
            "foo",
            "--config-file",
            "bar",
            "--no-api",
            "foobar",
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<String>>();

        assert_eq!(
            arg_parser.populate_args(&args),
            Err(Error::UnexpectedArgument("foobar".to_string()))
        );

        arg_parser = build_parser();

        let args = vec!["--exec-file", "foo", "--api-sock", "bar", "foobar"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<String>>();

        assert_eq!(
            arg_parser.populate_args(&args),
            Err(Error::UnexpectedArgument("foobar".to_string()))
        );

        arg_parser = build_parser();

        let args = vec!["foo"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<String>>();

        assert_eq!(
            arg_parser.populate_args(&args),
            Err(Error::UnexpectedArgument("foo".to_string()))
        );

        arg_parser = build_parser();

        let args = vec![
            "--exec-file",
            "foo",
            "--api-sock",
            "bar",
            "--id",
            "foobar",
            "--seccomp-level",
            "0",
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<String>>();

        assert!(arg_parser.populate_args(&args).is_ok());
    }

    #[test]
    fn test_split() {
        let mut args = vec!["--exec-file", "foo", "--", "--extra-arg-1", "--extra-arg-2"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<String>>();
        let (left, right) = ArgParser::split_args(&args);
        assert_eq!(left.to_vec(), vec!["--exec-file", "foo"]);
        assert_eq!(right.to_vec(), vec!["--extra-arg-1", "--extra-arg-2"]);

        args = vec!["--exec-file", "foo", "--"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<String>>();
        let (left, right) = ArgParser::split_args(&args);
        assert_eq!(left.to_vec(), vec!["--exec-file", "foo"]);
        assert!(right.is_empty());

        args = vec!["--exec-file", "foo"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<String>>();
        let (left, right) = ArgParser::split_args(&args);
        assert_eq!(left.to_vec(), vec!["--exec-file", "foo"]);
        assert!(right.is_empty());
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", Error::MissingArgument("foo".to_string())),
            "Argument 'foo' required, but not found."
        );
        assert_eq!(
            format!("{}", Error::MissingValue("foo".to_string())),
            "The argument 'foo' requires a value, but none was supplied."
        );
        assert_eq!(
            format!("{}", Error::UnexpectedArgument("foo".to_string())),
            "Found argument 'foo' which wasn't expected, or isn't valid in this context."
        );
        assert_eq!(
            format!("{}", Error::DuplicateArgument("foo".to_string())),
            "The argument 'foo' was provided more than once."
        );
    }
}
