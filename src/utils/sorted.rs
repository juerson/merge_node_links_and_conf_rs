use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;
use std::collections::HashSet;

// 排序vec<String>中的json字符串
#[allow(dead_code)]
pub fn sort_json_vec_of_string(mut vec_of_string: Vec<String>) -> Vec<String> {
    vec_of_string.sort_by(|a, b| {
        let parsed_a: JsonValue = serde_json::from_str::<JsonValue>(a).unwrap();
        let parsed_b: JsonValue = serde_json::from_str::<JsonValue>(b).unwrap();
        compare_json(&parsed_a, &parsed_b)
    });
    vec_of_string.into_iter().map(|s| s.to_string()).collect()
}

// 【该函数没有使用到】先按照长度排序，然后在长度相同时按照字母顺序排序
#[allow(dead_code)]
fn sort_json_fields_by_order(json_value: &mut JsonValue) {
    if let Some(obj) = json_value.as_object_mut() {
        let mut sorted_map: BTreeMap<String, JsonValue> = BTreeMap::new();
        // 按照字母顺序和单词长度对键进行排序
        let mut keys: Vec<_> = obj.keys().cloned().collect();
        keys.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
        // 将键移动到已排序的映射中
        for key in keys {
            if let Some(value) = obj.remove(&key) {
                sorted_map.insert(key, value);
            }
        }
        obj.extend(sorted_map);
    }
    // 递归地对嵌套对象进行排序
    if let Some(obj) = json_value.as_object_mut() {
        for (_, value) in obj.iter_mut() {
            sort_json_fields_by_order(value);
        }
    }
}

// 比较json字符串：首先按照JSON对象的键进行排序，然后递归比较JSON对象的值或数组的元素
fn compare_json(a: &JsonValue, b: &JsonValue) -> std::cmp::Ordering {
    match (a, b) {
        (JsonValue::Object(obj_a), JsonValue::Object(obj_b)) => {
            // 只比较"type"和"name"字段
            let fields = ["protocol", "type", "server", "port"];
            for field in &fields {
                let value_a = obj_a.get(*field);
                let value_b = obj_b.get(*field);
                match (value_a, value_b) {
                    (Some(val_a), Some(val_b)) => {
                        let ordering = val_a.to_string().cmp(&val_b.to_string());
                        if ordering != std::cmp::Ordering::Equal {
                            return ordering;
                        }
                    }
                    // 如果任一对象缺少字段，则认为缺少字段的对象更小
                    (None, Some(_)) => return std::cmp::Ordering::Less,
                    (Some(_), None) => return std::cmp::Ordering::Greater,
                    (None, None) => continue,
                }
            }
            std::cmp::Ordering::Equal
        }
        _ => a.to_string().cmp(&b.to_string()),
    }
}

// 另一种写法（比较json数据）
#[allow(dead_code)]
fn compare_json1(a: &JsonValue, b: &JsonValue) -> std::cmp::Ordering {
    match (a, b) {
        (JsonValue::Object(obj_a), JsonValue::Object(obj_b)) => {
            let keys_a: Vec<&String> = obj_a.keys().collect();
            let keys_b: Vec<&String> = obj_b.keys().collect();

            // 对键一致的进行排序
            let mut sorted_keys_a = keys_a.clone();
            let mut sorted_keys_b = keys_b.clone();
            sorted_keys_a.sort();
            sorted_keys_b.sort();
            // 首先比较键
            let key_ordering = sorted_keys_a.cmp(&sorted_keys_b);
            if key_ordering != std::cmp::Ordering::Equal {
                return key_ordering;
            }
            // 如果两个键相等，递归地比较两个值
            for key in keys_a {
                let value_ordering = compare_json(&obj_a[key], &obj_b[key]);
                if value_ordering != std::cmp::Ordering::Equal {
                    return value_ordering;
                }
            }
            std::cmp::Ordering::Equal
        }
        (JsonValue::Array(arr_a), JsonValue::Array(arr_b)) => {
            let len_ordering = arr_a.len().cmp(&arr_b.len());
            if len_ordering != std::cmp::Ordering::Equal {
                return len_ordering;
            }
            for (elem_a, elem_b) in arr_a.iter().zip(arr_b.iter()) {
                let elem_ordering = compare_json(elem_a, elem_b);
                if elem_ordering != std::cmp::Ordering::Equal {
                    return elem_ordering;
                }
            }
            std::cmp::Ordering::Equal
        }
        _ => a.to_string().cmp(&b.to_string()),
    }
}

// 对每个元素以yaml字符串形式存在的HashSet排序
#[allow(dead_code)]
pub fn sort_yaml_strings(values: &HashSet<String>, keys: &[&str]) -> HashSet<String> {
    let mut sorted_yaml_strings = HashSet::new();
    for yaml_string in values {
        // 解析 YAML 字符串
        let yaml_value: YamlValue = serde_yaml::from_str(&yaml_string).unwrap();
        // 将 YAML 转换为 JSON
        let json_value: JsonValue = serde_json::to_value(yaml_value).unwrap();
        // 提取需要的字段并按照给定键名排序
        if let JsonValue::Object(mut json_object) = json_value {
            let mut sorted_map = serde_json::Map::new();
            for key in keys {
                if let Some(value) = json_object.remove(*key) {
                    sorted_map.insert(key.to_string(), value);
                }
            }
            // 添加剩余的字段
            for (key, value) in json_object {
                sorted_map.insert(key, value);
            }
            // 构造排序后的 JSON 对象
            let sorted_json = JsonValue::Object(sorted_map);
            // 将 JSON 对象转换为 YAML 字符串
            let sorted_yaml_string = serde_yaml::to_string(&sorted_json).unwrap();
            sorted_yaml_strings.insert(sorted_yaml_string);
        }
    }
    sorted_yaml_strings
}
