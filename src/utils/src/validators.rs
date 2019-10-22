// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Misc data format validations, shared by multiple Firecracker components.
use std::fmt;

const MAX_INSTANCE_ID_LEN: usize = 64;
const MIN_INSTANCE_ID_LEN: usize = 1;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidChar(char, usize),        // (char, position)
    InvalidLen(usize, usize, usize), // (length, min, max)
    InvalidSeccompValue(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidChar(ch, pos) => write!(f, "invalid char ({}) at position {}", ch, pos),
            Error::InvalidLen(len, min_len, max_len) => write!(
                f,
                "invalid len ({});  the length must be between {} and {}",
                len, min_len, max_len
            ),
            Error::InvalidSeccompValue(ref arg) => write!(
                f,
                "'{}' isn't a valid value for 'seccomp-level'. Must  be 0, 1 or 2.",
                arg
            ),
        }
    }
}

/// Checks that the instance id only contains alphanumeric chars and hyphens
/// and that the size is between 1 and 64 characters.
pub fn validate_instance_id(input: &str) -> Result<(), Error> {
    if input.len() > MAX_INSTANCE_ID_LEN || input.len() < MIN_INSTANCE_ID_LEN {
        return Err(Error::InvalidLen(
            input.len(),
            MIN_INSTANCE_ID_LEN,
            MAX_INSTANCE_ID_LEN,
        ));
    }
    for (i, c) in input.chars().enumerate() {
        if !(c == '-' || c.is_alphanumeric()) {
            return Err(Error::InvalidChar(c, i));
        }
    }
    Ok(())
}

/// Checks that the seccomp level value is 0, 1 or 2.
pub fn validate_seccomp_level(seccomp_level: &str) -> Result<(), Error> {
    let seccomp_values = ["0", "1", "2"];
    if !seccomp_values.contains(&seccomp_level) {
        return Err(Error::InvalidSeccompValue(seccomp_level.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_instance_id() {
        assert_eq!(
            format!("{}", validate_instance_id("").unwrap_err()),
            "invalid len (0);  the length must be between 1 and 64"
        );
        assert!(validate_instance_id("12-3aa").is_ok());
        assert_eq!(
            format!("{}", validate_instance_id("12_3aa").unwrap_err()),
            "invalid char (_) at position 2"
        );
        assert_eq!(
            validate_instance_id("12:3aa").unwrap_err(),
            Error::InvalidChar(':', 2)
        );
        assert_eq!(
            validate_instance_id(str::repeat("a", MAX_INSTANCE_ID_LEN + 1).as_str()).unwrap_err(),
            Error::InvalidLen(
                MAX_INSTANCE_ID_LEN + 1,
                MIN_INSTANCE_ID_LEN,
                MAX_INSTANCE_ID_LEN
            )
        );
    }

    #[test]
    fn test_validate_seccomp_level() {
        assert_eq!(
            format!("{}", validate_seccomp_level("3").unwrap_err()),
            "'3' isn't a valid value for 'seccomp-level'. Must  be 0, 1 or 2."
        );
        assert!(validate_seccomp_level("0").is_ok());
        assert_eq!(
            format!("{}", validate_seccomp_level("foo").unwrap_err()),
            "'foo' isn't a valid value for 'seccomp-level'. Must  be 0, 1 or 2."
        );
        assert_eq!(
            validate_seccomp_level("foo").unwrap_err(),
            Error::InvalidSeccompValue("foo".to_string())
        );
    }
}
