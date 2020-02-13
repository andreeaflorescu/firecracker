// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use logger::{Metric, METRICS};
use request::{Error, ParsedRequest};

pub fn parse_get_instance_info() -> Result<ParsedRequest, Error> {
    METRICS.app_metrics.get_api_requests.instance_info_count.inc();
    Ok(ParsedRequest::GetInstanceInfo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_get_instance_info_request() {
        match parse_get_instance_info() {
            Ok(ParsedRequest::GetInstanceInfo) => {}
            _ => panic!("Test failed."),
        }
    }
}
