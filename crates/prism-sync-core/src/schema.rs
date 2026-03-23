use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};

use crate::error::{CoreError, Result};

/// The type of a syncable field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncType {
    String,
    Int,
    Bool,
    DateTime,
    Blob,
}

/// A typed value for sync operations.
///
/// Matches the SyncType variants plus Null for nullable fields.
#[derive(Debug, Clone, PartialEq)]
pub enum SyncValue {
    Null,
    String(String),
    Int(i64),
    Bool(bool),
    DateTime(DateTime<Utc>),
    Blob(Vec<u8>),
}

impl SyncValue {
    /// Returns the SyncType of this value, or None for Null.
    pub fn sync_type(&self) -> Option<SyncType> {
        match self {
            SyncValue::Null => None,
            SyncValue::String(_) => Some(SyncType::String),
            SyncValue::Int(_) => Some(SyncType::Int),
            SyncValue::Bool(_) => Some(SyncType::Bool),
            SyncValue::DateTime(_) => Some(SyncType::DateTime),
            SyncValue::Blob(_) => Some(SyncType::Blob),
        }
    }

    /// Returns true if this is Null.
    pub fn is_null(&self) -> bool {
        matches!(self, SyncValue::Null)
    }
}

/// Definition of a single syncable field within an entity table.
#[derive(Debug, Clone)]
pub struct SyncFieldDef {
    pub name: String,
    pub sync_type: SyncType,
}

/// An entity table definition within the sync schema.
#[derive(Debug, Clone)]
pub struct SyncEntityDef {
    pub table_name: String,
    pub fields: Vec<SyncFieldDef>,
}

impl SyncEntityDef {
    /// Find a field definition by name.
    pub fn field_by_name(&self, name: &str) -> Option<&SyncFieldDef> {
        self.fields.iter().find(|f| f.name == name)
    }
}

/// Schema declaration for the sync engine.
///
/// Registered entity tables and their field types. The sync engine uses this
/// to validate operations and encode/decode values.
///
/// # Example
/// ```
/// use prism_sync_core::schema::{SyncSchema, SyncType};
///
/// let schema = SyncSchema::builder()
///     .entity("tasks", |e| {
///         e.field("title", SyncType::String)
///          .field("done", SyncType::Bool)
///          .field("due_date", SyncType::DateTime)
///          .field("priority", SyncType::Int)
///     })
///     .entity("members", |e| {
///         e.field("name", SyncType::String)
///          .field("avatar", SyncType::Blob)
///     })
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct SyncSchema {
    entities: HashMap<String, SyncEntityDef>,
}

impl SyncSchema {
    pub fn builder() -> SyncSchemaBuilder {
        SyncSchemaBuilder {
            entities: Vec::new(),
        }
    }

    /// Parse a JSON schema definition into a `SyncSchema`.
    ///
    /// Expected format:
    /// ```json
    /// {
    ///   "entities": {
    ///     "members": {
    ///       "fields": {
    ///         "name": "String",
    ///         "age": "Int"
    ///       }
    ///     }
    ///   }
    /// }
    /// ```
    pub fn from_json(json: &str) -> Result<Self> {
        let val: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| CoreError::Schema(format!("Invalid schema JSON: {e}")))?;

        let entities = val
            .get("entities")
            .and_then(|v| v.as_object())
            .ok_or_else(|| {
                CoreError::Schema("Schema JSON must have an 'entities' object".into())
            })?;

        let mut builder = SyncSchema::builder();
        for (table_name, entity_val) in entities {
            let fields = entity_val
                .get("fields")
                .and_then(|v| v.as_object())
                .ok_or_else(|| {
                    CoreError::Schema(format!("Entity '{table_name}' must have a 'fields' object"))
                })?;

            let field_defs: Vec<(String, SyncType)> = fields
                .iter()
                .map(|(name, type_val)| {
                    let type_str = type_val.as_str().ok_or_else(|| {
                        CoreError::Schema(format!("Field type for '{name}' must be a string"))
                    })?;
                    let sync_type = match type_str {
                        "String" => SyncType::String,
                        "Int" => SyncType::Int,
                        "Bool" => SyncType::Bool,
                        "DateTime" => SyncType::DateTime,
                        "Blob" => SyncType::Blob,
                        other => {
                            return Err(CoreError::Schema(format!(
                                "Unknown SyncType '{other}' for field '{name}'"
                            )))
                        }
                    };
                    Ok((name.clone(), sync_type))
                })
                .collect::<Result<Vec<_>>>()?;

            let table = table_name.clone();
            builder = builder.entity(&table, |e| {
                for (name, sync_type) in &field_defs {
                    e.field(name, *sync_type);
                }
                e
            });
        }

        Ok(builder.build())
    }

    /// Get an entity definition by table name.
    pub fn entity(&self, table_name: &str) -> Option<&SyncEntityDef> {
        self.entities.get(table_name)
    }

    /// Get all registered entity table names.
    pub fn table_names(&self) -> Vec<&str> {
        self.entities.keys().map(|s| s.as_str()).collect()
    }

    /// Returns true if the given table is registered.
    pub fn has_table(&self, table_name: &str) -> bool {
        self.entities.contains_key(table_name)
    }
}

/// Builder for constructing SyncSchema via a fluent API.
pub struct SyncSchemaBuilder {
    entities: Vec<SyncEntityDef>,
}

impl SyncSchemaBuilder {
    /// Register an entity table with fields.
    pub fn entity<F>(mut self, table_name: &str, configure: F) -> Self
    where
        F: FnOnce(&mut EntityBuilder) -> &mut EntityBuilder,
    {
        let mut builder = EntityBuilder { fields: Vec::new() };
        configure(&mut builder);

        self.entities.push(SyncEntityDef {
            table_name: table_name.to_string(),
            fields: builder.fields,
        });
        self
    }

    /// Build the schema.
    pub fn build(self) -> SyncSchema {
        let entities = self
            .entities
            .into_iter()
            .map(|e| (e.table_name.clone(), e))
            .collect();
        SyncSchema { entities }
    }
}

/// Builder for entity field definitions.
pub struct EntityBuilder {
    fields: Vec<SyncFieldDef>,
}

impl EntityBuilder {
    /// Add a field to the entity.
    pub fn field(&mut self, name: &str, sync_type: SyncType) -> &mut Self {
        self.fields.push(SyncFieldDef {
            name: name.to_string(),
            sync_type,
        });
        self
    }
}

// -- Value encoding/decoding --
// These must match the Dart implementation's encoding rules exactly.

/// Encode a SyncValue to its JSON string representation for the wire format.
///
/// Encoding rules (matching Dart's OpEmitter.encodeValue):
/// - Null: literal string `"null"`
/// - String: JSON-encoded string (with quotes): `"\"hello\""`
/// - Int: JSON number: `"42"`
/// - Bool: `"true"` / `"false"`
/// - DateTime: JSON-encoded ISO-8601: `"\"2026-03-15T12:00:00.000Z\""`
/// - Blob: JSON-encoded base64: `"\"base64data...\""`
pub fn encode_value(value: &SyncValue) -> String {
    match value {
        SyncValue::Null => "null".to_string(),
        SyncValue::String(s) => serde_json::to_string(s).unwrap_or_else(|_| "null".to_string()),
        SyncValue::Int(i) => serde_json::to_string(i).unwrap_or_else(|_| "null".to_string()),
        SyncValue::Bool(b) => serde_json::to_string(b).unwrap_or_else(|_| "null".to_string()),
        SyncValue::DateTime(dt) => {
            // Dart format: ISO-8601 with millisecond precision
            let iso = dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
            serde_json::to_string(&iso).unwrap_or_else(|_| "null".to_string())
        }
        SyncValue::Blob(bytes) => {
            let b64 = BASE64.encode(bytes);
            serde_json::to_string(&b64).unwrap_or_else(|_| "null".to_string())
        }
    }
}

/// Decode a JSON-encoded string back to a SyncValue of the given type.
///
/// The `encoded` string comes from the `encoded_value` field of CrdtChange.
pub fn decode_value(encoded: &str, sync_type: SyncType) -> Result<SyncValue> {
    // Handle the literal "null" case
    if encoded == "null" {
        return Ok(SyncValue::Null);
    }

    // Parse the JSON value first
    let json_val: serde_json::Value = serde_json::from_str(encoded).map_err(|e| {
        CoreError::Serialization(format!("Failed to parse encoded value '{encoded}': {e}"))
    })?;

    if json_val.is_null() {
        return Ok(SyncValue::Null);
    }

    match sync_type {
        SyncType::String => {
            let s = json_val.as_str().ok_or_else(|| {
                CoreError::Serialization(format!("Expected string, got: {json_val}"))
            })?;
            Ok(SyncValue::String(s.to_string()))
        }
        SyncType::Int => {
            let i = json_val.as_i64().ok_or_else(|| {
                CoreError::Serialization(format!("Expected int, got: {json_val}"))
            })?;
            Ok(SyncValue::Int(i))
        }
        SyncType::Bool => {
            let b = json_val.as_bool().ok_or_else(|| {
                CoreError::Serialization(format!("Expected bool, got: {json_val}"))
            })?;
            Ok(SyncValue::Bool(b))
        }
        SyncType::DateTime => {
            let s = json_val.as_str().ok_or_else(|| {
                CoreError::Serialization(format!("Expected date string, got: {json_val}"))
            })?;
            let dt = s.parse::<DateTime<Utc>>().map_err(|e| {
                CoreError::Serialization(format!("Invalid ISO-8601 date '{s}': {e}"))
            })?;
            Ok(SyncValue::DateTime(dt))
        }
        SyncType::Blob => {
            let s = json_val.as_str().ok_or_else(|| {
                CoreError::Serialization(format!("Expected base64 string, got: {json_val}"))
            })?;
            let bytes = BASE64
                .decode(s)
                .map_err(|e| CoreError::Serialization(format!("Invalid base64 '{s}': {e}")))?;
            Ok(SyncValue::Blob(bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_builder() {
        let schema = SyncSchema::builder()
            .entity("tasks", |e| {
                e.field("title", SyncType::String)
                    .field("done", SyncType::Bool)
            })
            .entity("members", |e| e.field("name", SyncType::String))
            .build();

        assert!(schema.has_table("tasks"));
        assert!(schema.has_table("members"));
        assert!(!schema.has_table("unknown"));
        assert_eq!(schema.entity("tasks").unwrap().fields.len(), 2);
    }

    #[test]
    fn entity_field_lookup() {
        let schema = SyncSchema::builder()
            .entity("tasks", |e| {
                e.field("title", SyncType::String)
                    .field("done", SyncType::Bool)
            })
            .build();

        let entity = schema.entity("tasks").unwrap();
        assert_eq!(
            entity.field_by_name("title").unwrap().sync_type,
            SyncType::String
        );
        assert_eq!(
            entity.field_by_name("done").unwrap().sync_type,
            SyncType::Bool
        );
        assert!(entity.field_by_name("nonexistent").is_none());
    }

    #[test]
    fn encode_decode_null() {
        let encoded = encode_value(&SyncValue::Null);
        assert_eq!(encoded, "null");
        let decoded = decode_value(&encoded, SyncType::String).unwrap();
        assert_eq!(decoded, SyncValue::Null);
    }

    #[test]
    fn encode_decode_string() {
        let val = SyncValue::String("hello world".to_string());
        let encoded = encode_value(&val);
        assert_eq!(encoded, "\"hello world\"");
        let decoded = decode_value(&encoded, SyncType::String).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn encode_decode_string_with_quotes() {
        let val = SyncValue::String("he said \"hi\"".to_string());
        let encoded = encode_value(&val);
        let decoded = decode_value(&encoded, SyncType::String).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn encode_decode_int() {
        let val = SyncValue::Int(42);
        let encoded = encode_value(&val);
        assert_eq!(encoded, "42");
        let decoded = decode_value(&encoded, SyncType::Int).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn encode_decode_negative_int() {
        let val = SyncValue::Int(-100);
        let encoded = encode_value(&val);
        assert_eq!(encoded, "-100");
        let decoded = decode_value(&encoded, SyncType::Int).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn encode_decode_bool_true() {
        let val = SyncValue::Bool(true);
        let encoded = encode_value(&val);
        assert_eq!(encoded, "true");
        let decoded = decode_value(&encoded, SyncType::Bool).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn encode_decode_bool_false() {
        let val = SyncValue::Bool(false);
        let encoded = encode_value(&val);
        assert_eq!(encoded, "false");
        let decoded = decode_value(&encoded, SyncType::Bool).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn encode_decode_datetime() {
        let dt = "2026-03-15T12:00:00.000Z".parse::<DateTime<Utc>>().unwrap();
        let val = SyncValue::DateTime(dt);
        let encoded = encode_value(&val);
        assert_eq!(encoded, "\"2026-03-15T12:00:00.000Z\"");
        let decoded = decode_value(&encoded, SyncType::DateTime).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn encode_decode_blob() {
        let val = SyncValue::Blob(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let encoded = encode_value(&val);
        // base64 of [0xDE, 0xAD, 0xBE, 0xEF] = "3q2+7w=="
        assert_eq!(encoded, "\"3q2+7w==\"");
        let decoded = decode_value(&encoded, SyncType::Blob).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn decode_invalid_json() {
        assert!(decode_value("not{json", SyncType::String).is_err());
    }

    #[test]
    fn decode_type_mismatch() {
        assert!(decode_value("42", SyncType::String).is_err());
    }

    #[test]
    fn sync_value_type_checking() {
        assert_eq!(
            SyncValue::String("x".into()).sync_type(),
            Some(SyncType::String)
        );
        assert_eq!(SyncValue::Int(1).sync_type(), Some(SyncType::Int));
        assert_eq!(SyncValue::Bool(true).sync_type(), Some(SyncType::Bool));
        assert_eq!(SyncValue::Null.sync_type(), None);
        assert!(SyncValue::Null.is_null());
        assert!(!SyncValue::Int(0).is_null());
    }
}
