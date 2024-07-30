use crate::utils::date::{
    replace_url_date_with_today,     // 今天
    replace_url_date_with_yesterday, // 昨天
};

use serde_yaml::Value as YamlValue;
use std::collections::HashSet;

// 定义一个枚举类型，用于判断数据格式
#[derive(Debug)]
pub enum DataFormat {
    Json,
    Yaml,
    Base64,
    Other,
}

// 提取urls.yaml配置文件中的所有url
pub fn extract_urls_of_yaml(data: &YamlValue) -> Vec<String> {
    let mut values = HashSet::new();
    if let YamlValue::Mapping(mapping) = data {
        for (_key, value) in mapping {
            if let YamlValue::Sequence(seq) = value {
                for v in seq {
                    if let YamlValue::String(s) = v {
                        // 假如地址url链接中有日期，就将url链接中的日期（包括路径中的年、月），替换成昨天的，url链接中没有日期就使用原始的url链接
                        let url_date_with_yesterday =
                            replace_url_date_with_yesterday(s.clone().as_str());
                        values.insert(url_date_with_yesterday.clone());
                        /*
                        如果s.clone()跟昨天的链接一样（可能就是昨天日期的链接，也可能没有日期，前面哪个替换函数返回了原始链接），可以插入原始链接；
                        如果这两个值不相等，说明成功更新url链接日期到昨天，那么原始链接（日期太旧了）就不要插入HashSet了，昨天的日期都早于原始
                        的，使用最新的日期的节点不香吗？况且后面还有今天日期的链接插入。
                        */
                        if url_date_with_yesterday == s.clone() {
                            values.insert(s.clone()); // 将配置文件中的原始值插入到HashSet去重
                        }

                        // 假如地址url链接中有日期，就将url链接中的日期（包括路径中的年、月），替换成今天的，url链接中没有日期就使用原始的url链接
                        let url_date_with_today = replace_url_date_with_today(s.clone().as_str());
                        values.insert(url_date_with_today.clone());
                    }
                }
            }
        }
    }
    values.into_iter().collect() // 转换为Vec<String>
}

// 查找url在urls.yaml配置文件中，对应的key键名作为文件名（原始文件名，后面可以添加编号）
pub fn find_key_as_filename(url_of_string: String, data: &YamlValue) -> Option<String> {
    if let YamlValue::Mapping(mapping) = data {
        for (key, value) in mapping {
            if let YamlValue::Sequence(seq) = value {
                if seq
                    .iter()
                    .any(|v| v == &YamlValue::String(url_of_string.to_string()))
                {
                    if let YamlValue::String(key_str) = key {
                        return Some(key_str.clone());
                    }
                }
            }
        }
    }
    None
}

// 能转换为json、yaml、base64，还是其它格式的数据。
pub fn can_convert_to_json_or_yaml(input: &str) -> DataFormat {
    // 1、初步判断是否为 Base64 编码
    let is_base64_bool = base64::decode(input).is_ok();
    // 2、进一步检查是否为有效的 Base64 编码
    fn is_base64(input: &str, is_base64_bool: bool) -> bool {
        // 检查长度是否为 4 的倍数
        if input.len() % 4 != 0 && !is_base64_bool {
            return false;
        }
        // 检查是否只包含有效的 Base64 字符
        if !input
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
            && !is_base64_bool
        {
            return false;
        }

        is_base64_bool
    }
    // 检查是否为有效的 YAML
    fn is_yaml(input: &str) -> bool {
        // 尝试解析为 serde_yaml::Value
        match serde_yaml::from_str::<serde_yaml::Value>(input) {
            Ok(value) => {
                // 进一步检查解析后的值是否是复杂结构；例如，确保它不是单个标量值
                match value {
                    serde_yaml::Value::Mapping(_) | serde_yaml::Value::Sequence(_) => true,
                    _ => false,
                }
            }
            Err(_) => false,
        }
    }
    if is_base64(input, is_base64_bool) {
        DataFormat::Base64
    } else if !is_base64_bool && serde_json::from_str::<serde_json::Value>(input).is_ok() {
        DataFormat::Json
    } else if !is_base64_bool
        && serde_yaml::from_str::<serde_yaml::Value>(input).is_ok()
        && is_yaml(input)
    {
        DataFormat::Yaml
    } else {
        DataFormat::Other // 可能是v2ray链接，也可能是其他格式的数据
    }
}

// 递归查找field_vec中的字段的值，只要找到值，就立刻返回
pub fn find_field_value<'a>(json: &'a YamlValue, field_vec: &'a [&str]) -> Option<&'a str> {
    for field in field_vec {
        match json {
            YamlValue::Mapping(map) => {
                if let Some(v) = map.get(&YamlValue::String(field.to_string())) {
                    if let YamlValue::String(s) = v {
                        return Some(s);
                    } else {
                        // If the field is not a string, continue searching recursively
                        if let Some(val) = find_field_value(v, field_vec) {
                            return Some(val);
                        }
                    }
                }
            }
            YamlValue::Sequence(seq) => {
                for v in seq {
                    if let Some(val) = find_field_value(v, field_vec) {
                        return Some(val);
                    }
                }
            }
            _ => {}
        }
    }
    None
}
