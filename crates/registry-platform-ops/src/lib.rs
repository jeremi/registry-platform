//! Public operations contract assets shared by Registry runtimes.
//!
//! Relay and Notary own route wiring, authorization, and local posture
//! collection. This crate owns the shared public contract and the emit-only
//! sensitivity-tier filter used before posture leaves a runtime.

use serde_json::Value;

pub const POSTURE_SCHEMA_V1: &str = include_str!("../schemas/registry.ops.posture.v1.schema.json");

pub const RELAY_POSTURE_EXAMPLE_V1: &str =
    include_str!("../examples/registry-relay.posture.valid.json");

pub const NOTARY_POSTURE_EXAMPLE_V1: &str =
    include_str!("../examples/registry-notary.posture.valid.json");

pub const DEFAULT_POSTURE_ALLOWLIST_FIXTURE_V1: &str =
    include_str!("../fixtures/posture/default-allowlist.json");

pub const REDACTION_INPUT_SENSITIVE_FIXTURE_V1: &str =
    include_str!("../fixtures/posture/redaction-input-sensitive.json");

pub const DEFAULT_REDACTED_POSTURE_FIXTURE_V1: &str =
    include_str!("../fixtures/posture/default-redacted.posture.valid.json");

pub const RESTRICTED_POSTURE_FIXTURE_V1: &str =
    include_str!("../fixtures/posture/restricted-posture.valid.json");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostureTier {
    Default,
    Restricted,
}

impl PostureTier {
    fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Restricted => "restricted",
        }
    }
}

#[derive(Debug)]
pub enum PostureFilterError {
    InvalidAllowlist(serde_json::Error),
    MissingAllowedPointers,
    InvalidAllowedPointer,
    FilteredToEmptyDocument,
}

impl std::fmt::Display for PostureFilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAllowlist(error) => write!(f, "invalid posture allowlist: {error}"),
            Self::MissingAllowedPointers => write!(f, "posture allowlist is missing pointers"),
            Self::InvalidAllowedPointer => {
                write!(f, "posture allowlist contains a non-string pointer")
            }
            Self::FilteredToEmptyDocument => {
                write!(f, "posture filter removed the entire document")
            }
        }
    }
}

impl std::error::Error for PostureFilterError {}

pub fn filter_posture_for_tier(
    mut posture: Value,
    tier: PostureTier,
) -> Result<Value, PostureFilterError> {
    posture["tier"] = Value::String(tier.as_str().to_string());
    match tier {
        PostureTier::Default => filter_default_posture(posture),
        PostureTier::Restricted => Ok(posture),
    }
}

fn filter_default_posture(posture: Value) -> Result<Value, PostureFilterError> {
    let allowlist: Value = serde_json::from_str(DEFAULT_POSTURE_ALLOWLIST_FIXTURE_V1)
        .map_err(PostureFilterError::InvalidAllowlist)?;
    let allowed = allowlist["allowed_json_pointers"]
        .as_array()
        .ok_or(PostureFilterError::MissingAllowedPointers)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(PointerPattern::parse)
                .ok_or(PostureFilterError::InvalidAllowedPointer)
        })
        .collect::<Result<Vec<_>, _>>()?;

    filter_value(&posture, "", &allowed).ok_or(PostureFilterError::FilteredToEmptyDocument)
}

fn filter_value(value: &Value, pointer: &str, allowed: &[PointerPattern]) -> Option<Value> {
    if allowed.iter().any(|pattern| pattern.matches(pointer)) {
        return Some(value.clone());
    }

    match value {
        Value::Object(map) => {
            let filtered = map
                .iter()
                .filter_map(|(key, child)| {
                    let child_pointer = append_pointer(pointer, key);
                    filter_value(child, &child_pointer, allowed).map(|child| (key.clone(), child))
                })
                .collect::<serde_json::Map<_, _>>();
            (!filtered.is_empty()
                || allowed
                    .iter()
                    .any(|pattern| pattern.has_descendant_of(pointer)))
            .then_some(Value::Object(filtered))
        }
        Value::Array(items) => {
            let filtered = items
                .iter()
                .filter_map(|child| {
                    let child_pointer = append_pointer(pointer, "*");
                    filter_value(child, &child_pointer, allowed)
                })
                .collect::<Vec<_>>();
            (!filtered.is_empty()
                || allowed
                    .iter()
                    .any(|pattern| pattern.has_descendant_of(pointer)))
            .then_some(Value::Array(filtered))
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => None,
    }
}

fn append_pointer(base: &str, segment: &str) -> String {
    if base.is_empty() {
        format!("/{}", escape_pointer(segment))
    } else {
        format!("{base}/{}", escape_pointer(segment))
    }
}

fn escape_pointer(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

#[derive(Debug)]
struct PointerPattern {
    segments: Vec<String>,
}

impl PointerPattern {
    fn parse(pointer: &str) -> Self {
        Self {
            segments: pointer_segments(pointer),
        }
    }

    fn matches(&self, pointer: &str) -> bool {
        let pointer_segments = pointer_segments(pointer);
        self.segments.len() == pointer_segments.len()
            && self
                .segments
                .iter()
                .zip(pointer_segments)
                .all(|(pattern, segment)| pattern == "*" || pattern == &segment)
    }

    fn has_descendant_of(&self, pointer: &str) -> bool {
        let pointer_segments = pointer_segments(pointer);
        self.segments.len() > pointer_segments.len()
            && self
                .segments
                .iter()
                .zip(pointer_segments)
                .all(|(pattern, segment)| pattern == "*" || pattern == &segment)
    }
}

fn pointer_segments(pointer: &str) -> Vec<String> {
    pointer
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(ToString::to_string)
        .collect()
}
