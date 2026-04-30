/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! Parser for the NIBArchive binary format used in iOS 3.2+ nib files.
//!
//! Converts NIBArchive data into a plist [Dictionary] compatible with
//! the NSKeyedArchiver format so the existing [super::ns_keyed_unarchiver]
//! code can consume it.

use plist::{Dictionary, Integer, Uid, Value};
use std::collections::HashMap;

const MAGIC: &[u8; 10] = b"NIBArchive";

pub fn is_nib_archive(data: &[u8]) -> bool {
    data.len() > 10 && &data[..10] == MAGIC
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn read_i16_le(data: &[u8], offset: usize) -> i16 {
    i16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

fn read_i32_le(data: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn read_i64_le(data: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

fn read_f32_le(data: &[u8], offset: usize) -> f32 {
    f32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn read_f64_le(data: &[u8], offset: usize) -> f64 {
    f64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

fn read_varint(data: &[u8], pos: &mut usize) -> u32 {
    let mut result: u32 = 0;
    let mut shift = 0;
    loop {
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 != 0 {
            break;
        }
        shift += 7;
    }
    result
}

struct NibHeader {
    object_count: u32,
    object_offset: u32,
    key_count: u32,
    key_offset: u32,
    value_count: u32,
    value_offset: u32,
    class_count: u32,
    class_offset: u32,
}

struct NibObject {
    class_index: u32,
    values_index: u32,
    values_count: u32,
}

struct NibValue {
    key_index: u32,
    value_type: u8,
    payload: NibPayload,
}

enum NibPayload {
    Int8(i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    True,
    False,
    Float(f32),
    Double(f64),
    Data(Vec<u8>),
    Nil,
    ObjectRef(u32),
}

fn parse_header(data: &[u8]) -> NibHeader {
    NibHeader {
        object_count: read_u32_le(data, 18),
        object_offset: read_u32_le(data, 22),
        key_count: read_u32_le(data, 26),
        key_offset: read_u32_le(data, 30),
        value_count: read_u32_le(data, 34),
        value_offset: read_u32_le(data, 38),
        class_count: read_u32_le(data, 42),
        class_offset: read_u32_le(data, 46),
    }
}

fn parse_keys(data: &[u8], header: &NibHeader) -> Vec<String> {
    let mut pos = header.key_offset as usize;
    let mut keys = Vec::with_capacity(header.key_count as usize);
    for _ in 0..header.key_count {
        let length = read_varint(data, &mut pos) as usize;
        let raw = &data[pos..pos + length];
        let trimmed = raw.strip_suffix(&[0]).unwrap_or(raw);
        let s = String::from_utf8_lossy(trimmed).into_owned();
        pos += length;
        keys.push(s);
    }
    keys
}

fn parse_class_names(data: &[u8], header: &NibHeader) -> Vec<String> {
    let mut pos = header.class_offset as usize;
    let mut classes = Vec::with_capacity(header.class_count as usize);
    for _ in 0..header.class_count {
        let name_length = read_varint(data, &mut pos) as usize;
        let fallback_count = read_varint(data, &mut pos) as usize;
        pos += fallback_count * 4;
        let raw = &data[pos..pos + name_length];
        let trimmed = raw.strip_suffix(&[0]).unwrap_or(raw);
        let name = String::from_utf8_lossy(trimmed).into_owned();
        pos += name_length;
        classes.push(name);
    }
    classes
}

fn parse_objects(data: &[u8], header: &NibHeader) -> Vec<NibObject> {
    let mut pos = header.object_offset as usize;
    let mut objects = Vec::with_capacity(header.object_count as usize);
    for _ in 0..header.object_count {
        let class_index = read_varint(data, &mut pos);
        let values_index = read_varint(data, &mut pos);
        let values_count = read_varint(data, &mut pos);
        objects.push(NibObject {
            class_index,
            values_index,
            values_count,
        });
    }
    objects
}

fn parse_values(data: &[u8], header: &NibHeader) -> Vec<NibValue> {
    let mut pos = header.value_offset as usize;
    let mut values = Vec::with_capacity(header.value_count as usize);
    for _ in 0..header.value_count {
        let key_index = read_varint(data, &mut pos);
        let value_type = data[pos];
        pos += 1;
        let payload = match value_type {
            0x00 => {
                let v = data[pos] as i8;
                pos += 1;
                NibPayload::Int8(v)
            }
            0x01 => {
                let v = read_i16_le(data, pos);
                pos += 2;
                NibPayload::Int16(v)
            }
            0x02 => {
                let v = read_i32_le(data, pos);
                pos += 4;
                NibPayload::Int32(v)
            }
            0x03 => {
                let v = read_i64_le(data, pos);
                pos += 8;
                NibPayload::Int64(v)
            }
            0x04 => NibPayload::True,
            0x05 => NibPayload::False,
            0x06 => {
                let v = read_f32_le(data, pos);
                pos += 4;
                NibPayload::Float(v)
            }
            0x07 => {
                let v = read_f64_le(data, pos);
                pos += 8;
                NibPayload::Double(v)
            }
            0x08 => {
                let length = read_varint(data, &mut pos) as usize;
                let d = data[pos..pos + length].to_vec();
                pos += length;
                NibPayload::Data(d)
            }
            0x09 => NibPayload::Nil,
            0x0A => {
                let idx = read_u32_le(data, pos);
                pos += 4;
                NibPayload::ObjectRef(idx)
            }
            _ => {
                log!(
                    "NIBArchive: unknown value type 0x{:02x} at pos {}",
                    value_type,
                    pos - 1
                );
                NibPayload::Nil
            }
        };
        values.push(NibValue {
            key_index,
            value_type,
            payload,
        });
    }
    values
}

fn payload_to_plist(payload: &NibPayload) -> Value {
    match payload {
        NibPayload::Int8(v) => Value::Integer(Integer::from(*v as i64)),
        NibPayload::Int16(v) => Value::Integer(Integer::from(*v as i64)),
        NibPayload::Int32(v) => Value::Integer(Integer::from(*v as i64)),
        NibPayload::Int64(v) => Value::Integer(Integer::from(*v)),
        NibPayload::True => Value::Boolean(true),
        NibPayload::False => Value::Boolean(false),
        NibPayload::Float(v) => Value::Real((*v).into()),
        NibPayload::Double(v) => Value::Real(*v),
        NibPayload::Data(d) => Value::Data(d.clone()),
        NibPayload::Nil => Value::Uid(Uid::new(0)),
        NibPayload::ObjectRef(idx) => Value::Uid(Uid::new(*idx as u64)),
    }
}

/// Parse a NIBArchive binary and convert it into an NSKeyedArchiver-
/// compatible plist [Dictionary].
pub fn parse_nib_archive(data: &[u8]) -> Dictionary {
    assert!(is_nib_archive(data));

    let header = parse_header(data);
    let keys = parse_keys(data, &header);
    let class_names = parse_class_names(data, &header);
    let objects = parse_objects(data, &header);
    let all_values = parse_values(data, &header);

    log!(
        "NIBArchive: {} objects, {} keys, {} values, {} classes",
        objects.len(),
        keys.len(),
        all_values.len(),
        class_names.len()
    );

    // Build the $objects array matching NSKeyedArchiver format.
    // Index 0 is always "$null".
    let mut plist_objects: Vec<Value> = Vec::new();
    plist_objects.push(Value::String("$null".to_string()));

    // Map from NIBArchive object index -> plist $objects index
    let mut obj_index_map: HashMap<u32, u64> = HashMap::new();

    // First pass: assign plist indices
    for (i, _) in objects.iter().enumerate() {
        let plist_idx = plist_objects.len() as u64;
        obj_index_map.insert(i as u32, plist_idx);

        // Placeholder; will be filled in second pass
        plist_objects.push(Value::Dictionary(Dictionary::new()));
    }

    // Second pass: build each object's dictionary
    for (i, obj) in objects.iter().enumerate() {
        let class_name = &class_names[obj.class_index as usize];
        let plist_idx = obj_index_map[&(i as u32)] as usize;

        let val_start = obj.values_index as usize;
        let val_end = val_start + obj.values_count as usize;

        // NSString/NSMutableString: store as plain Value::String
        // instead of a dictionary, since NSKeyedUnarchiver handles
        // strings directly without initWithCoder:.
        if class_name == "NSString" || class_name == "NSMutableString" {
            let mut string_val = String::new();
            for val in &all_values[val_start..val_end] {
                let key_name = &keys[val.key_index as usize];
                if key_name == "NS.bytes" || key_name == "UINibEncoderEmptyKey"
                {
                    if let NibPayload::Data(d) = &val.payload {
                        string_val =
                            String::from_utf8_lossy(d).into_owned();
                        // Strip trailing null
                        string_val =
                            string_val.trim_end_matches('\0').to_string();
                    }
                }
            }
            plist_objects[plist_idx] = Value::String(string_val);
            continue;
        }

        // NSData/NSMutableData: store as plain Value::Data
        if class_name == "NSData" || class_name == "NSMutableData" {
            let mut data_val = Vec::new();
            for val in &all_values[val_start..val_end] {
                let key_name = &keys[val.key_index as usize];
                if key_name == "NS.bytes" || key_name == "UINibEncoderEmptyKey"
                {
                    if let NibPayload::Data(d) = &val.payload {
                        data_val = d.clone();
                    }
                }
            }
            plist_objects[plist_idx] = Value::Data(data_val);
            continue;
        }

        // Build the $class entry (append at end of $objects)
        let class_plist_idx = plist_objects.len() as u64;
        let mut class_dict = Dictionary::new();
        class_dict.insert(
            "$classname".to_string(),
            Value::String(class_name.clone()),
        );
        class_dict.insert(
            "$classes".to_string(),
            Value::Array(vec![
                Value::String(class_name.clone()),
                Value::String("NSObject".to_string()),
            ]),
        );
        plist_objects.push(Value::Dictionary(class_dict));

        // Build the object's own dictionary
        let mut obj_dict = Dictionary::new();
        obj_dict.insert(
            "$class".to_string(),
            Value::Uid(Uid::new(class_plist_idx)),
        );

        // Track repeated keys for NSArray inlining
        let mut key_counts: HashMap<u32, usize> = HashMap::new();
        for val in &all_values[val_start..val_end] {
            *key_counts.entry(val.key_index).or_insert(0) += 1;
        }

        // Collect repeated-key values into arrays
        let mut array_values: HashMap<u32, Vec<Value>> = HashMap::new();

        for val in &all_values[val_start..val_end] {
            let key_name = &keys[val.key_index as usize];

            let plist_val = match &val.payload {
                NibPayload::ObjectRef(idx) => {
                    if let Some(&mapped) = obj_index_map.get(idx) {
                        Value::Uid(Uid::new(mapped))
                    } else {
                        Value::Uid(Uid::new(0))
                    }
                }
                // Convert inline geometry data to string format
                // stored in $objects and referenced by UID, matching
                // what decodeCGRectForKey / decodeCGPointForKey expect.
                NibPayload::Data(d) if d.len() == 16 && matches!(
                    key_name.as_str(),
                    "UIBounds" | "UIFrame" | "UIFrameX"
                    | "UIAutoresizeToFitContentFrame"
                ) => {
                    let x = read_f32_le(d, 0);
                    let y = read_f32_le(d, 4);
                    let w = read_f32_le(d, 8);
                    let h = read_f32_le(d, 12);
                    let s = format!("{{{{{x}, {y}}}, {{{w}, {h}}}}}");
                    let idx = plist_objects.len() as u64;
                    plist_objects.push(Value::String(s));
                    Value::Uid(Uid::new(idx))
                }
                NibPayload::Data(d) if d.len() == 8 && matches!(
                    key_name.as_str(),
                    "UICenter" | "UIContentOffset"
                ) => {
                    let x = read_f32_le(d, 0);
                    let y = read_f32_le(d, 4);
                    let s = format!("{{{x}, {y}}}");
                    let idx = plist_objects.len() as u64;
                    plist_objects.push(Value::String(s));
                    Value::Uid(Uid::new(idx))
                }
                NibPayload::Data(d) if d.len() == 8 && matches!(
                    key_name.as_str(),
                    "UIContentSize" | "UIScrollViewContentSize"
                    | "UIMinimumSize" | "UIMaximumSize"
                ) => {
                    let w = read_f32_le(d, 0);
                    let h = read_f32_le(d, 4);
                    let s = format!("{{{w}, {h}}}");
                    let idx = plist_objects.len() as u64;
                    plist_objects.push(Value::String(s));
                    Value::Uid(Uid::new(idx))
                }
                other => payload_to_plist(other),
            };

            let count = key_counts[&val.key_index];
            if count > 1 {
                array_values
                    .entry(val.key_index)
                    .or_insert_with(Vec::new)
                    .push(plist_val);
            } else {
                obj_dict.insert(key_name.clone(), plist_val);
            }
        }

        // Insert collected arrays.
        // For NSArray/NSMutableArray/NSDictionary/NSMutableDictionary,
        // NIBArchive uses "UINibEncoderEmptyKey" for elements, but
        // NSKeyedArchiver uses "NS.objects" (and "NS.keys" for dicts).
        let is_array = class_name == "NSArray"
            || class_name == "NSMutableArray";
        let is_dict = class_name == "NSDictionary"
            || class_name == "NSMutableDictionary";

        for (key_idx, arr) in array_values {
            let key_name = &keys[key_idx as usize];
            if (is_array || is_dict) && key_name == "UINibEncoderEmptyKey" {
                obj_dict.insert("NS.objects".to_string(), Value::Array(arr));
            } else {
                obj_dict.insert(key_name.clone(), Value::Array(arr));
            }
        }

        plist_objects[plist_idx] = Value::Dictionary(obj_dict);
    }

    // Build the $top dictionary from the root object (object 0).
    // In NSKeyedArchiver nibs, the top-level keys (UINibObjectsKey,
    // UINibConnectionsKey, etc.) live directly in $top. The root
    // NIBArchive object's values become $top entries.
    let mut top = Dictionary::new();
    let root_obj = &objects[0];
    let root_start = root_obj.values_index as usize;
    let root_end = root_start + root_obj.values_count as usize;
    for val in &all_values[root_start..root_end] {
        let key_name = &keys[val.key_index as usize];
        let plist_val = match &val.payload {
            NibPayload::ObjectRef(idx) => {
                if let Some(&mapped) = obj_index_map.get(idx) {
                    Value::Uid(Uid::new(mapped))
                } else {
                    Value::Uid(Uid::new(0))
                }
            }
            other => payload_to_plist(other),
        };
        top.insert(key_name.clone(), plist_val);
    }

    // Build the wrapper
    let mut root = Dictionary::new();
    root.insert(
        "$archiver".to_string(),
        Value::String("NSKeyedArchiver".to_string()),
    );
    root.insert(
        "$version".to_string(),
        Value::Integer(Integer::from(100000)),
    );
    root.insert("$top".to_string(), Value::Dictionary(top));
    root.insert("$objects".to_string(), Value::Array(plist_objects));

    root
}
