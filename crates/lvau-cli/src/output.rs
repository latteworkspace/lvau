use serde::Serialize;
use std::io::{self, Write};

pub const JSON_SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct JsonEnvelope<'a, T: Serialize> {
    schema_version: u32,
    command: &'a str,
    status: &'static str,
    data: &'a T,
}

#[derive(Serialize)]
struct JsonErrorEnvelope<'a> {
    schema_version: u32,
    command: &'a str,
    status: &'static str,
    error: JsonError<'a>,
}

#[derive(Serialize)]
struct JsonError<'a> {
    code: &'a str,
    message: &'a str,
}

/// Print one stable, versioned success document to stdout.
pub fn print_success<T: Serialize>(command: &str, data: &T) -> Result<(), serde_json::Error> {
    let envelope = JsonEnvelope {
        schema_version: JSON_SCHEMA_VERSION,
        command,
        status: "ok",
        data,
    };
    println!("{}", serde_json::to_string_pretty(&envelope)?);
    Ok(())
}

/// Print one stable, versioned error document to stderr.
///
/// Command handlers may adopt this while preserving their existing exit codes.
#[allow(dead_code)]
pub fn print_error(command: &str, code: &str, message: &str) -> Result<(), serde_json::Error> {
    let envelope = JsonErrorEnvelope {
        schema_version: JSON_SCHEMA_VERSION,
        command,
        status: "error",
        error: JsonError { code, message },
    };
    let encoded = serde_json::to_string_pretty(&envelope)?;
    let _ = writeln!(io::stderr(), "{encoded}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Data {
        value: u32,
    }

    #[test]
    fn success_contract_has_stable_top_level_fields() {
        let value = JsonEnvelope {
            schema_version: JSON_SCHEMA_VERSION,
            command: "inspect",
            status: "ok",
            data: &Data { value: 7 },
        };
        let json = serde_json::to_value(value).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["command"], "inspect");
        assert_eq!(json["status"], "ok");
        assert_eq!(json["data"]["value"], 7);
    }
}
