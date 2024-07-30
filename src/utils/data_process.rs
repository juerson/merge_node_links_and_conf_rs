use rand::{distributions::Alphanumeric, Rng};
use regex::Regex;
use serde_json::Value as JsonValue;
use serde_yaml::{Mapping, Value as YamlValue};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
};

use crate::utils::{
    custom_struct::{CustomString, UrlJsonPair},
    yaml::find_field_value,
};

// 是v2ray链接的，就将链接插入到links_set中
pub fn is_liks_data_insert_links_set(
    protocol_url: String,
    links_set: &Rc<RefCell<HashSet<CustomString>>>,
    links_prefix_set: &Rc<RefCell<HashSet<String>>>,
    protocols: Vec<&str>,
) {
    let custom_str = CustomString::new(protocol_url.as_str());
    if protocols
        .iter()
        .take(protocols.len() - 1)
        .any(|&s| protocol_url.starts_with(&(s.to_owned() + "://")))
    {
        // 以每行字符串的开头到#字符结尾为参考去重
        let prefix: String = custom_str.inner.chars().take_while(|&c| c != '#').collect();
        if links_prefix_set.borrow_mut().insert(prefix.clone()) {
            links_set.borrow_mut().insert(custom_str);
        }
    }
}

// 是json的数据，就将节点插入json对应的集合中
pub fn is_json_data_insert_json_set(
    body: String,
    url: String,
    json_set: &Rc<RefCell<HashSet<UrlJsonPair>>>,
    singbox_json_set: &Rc<RefCell<HashSet<String>>>,
    xray_json_set: &Rc<RefCell<HashSet<String>>>,
) {
    // 是json的数据
    if let Ok(json_value) = serde_json::from_str::<JsonValue>(&body) {
        // 检查字段是否存在且是一个数组
        if let Some(items) = json_value
            .get("outbounds")
            .and_then(|array| array.as_array())
        {
            for item in items {
                let item_string = item.to_string();
                if item.get("type").is_some() {
                    // 有type字段的通常是sing-box的配置文件
                    singbox_json_set.borrow_mut().insert(item_string.clone());
                }
                if item.get("protocol").is_some() {
                    // 有protocol字段的通常是xray的配置文件
                    xray_json_set.borrow_mut().insert(item_string.clone());
                }
            }
        } else {
            // Json数据中，字段outbounds不存在或不是数组
            let json_string = json_value.to_string();
            // 将url和字符串化的json数据放到自定义的数据结构体中
            let url_json_pair: UrlJsonPair = UrlJsonPair {
                url,
                json_data: json_string,
            };
            // 插入到HashSet中，去重（使用 json_data 字段的哈希值和相等性来进行去重）
            json_set.borrow_mut().insert(url_json_pair);
        }
    } else {
        // 无法解析为JSON数据
    }
}

// 是clash的节点就将节点插入clash对应的集合中
pub fn is_clash_data_insert_clash_set(
    body: String,
    clash_name_field_set: &Rc<RefCell<HashMap<String, String>>>,
    clash_set: &Rc<RefCell<HashSet<String>>>,
) {
    if let Ok(yaml_value) = serde_yaml::from_str::<YamlValue>(&body) {
        if let Some(YamlValue::Sequence(items)) = yaml_value.get("proxies") {
            // 定义要忽略的键
            let ignored_keys = ["name", "client-fingerprint", "skip-cert-verify", "tfo"];
            for item in items {
                if let YamlValue::Mapping(mut map) = item.clone() {
                    /* 从field_names中找字段对应的值，找到的值就作为节点名称（选择性，不完全使用这个名称） */
                    let field_names = ["servername", "Host", "host", "sni"];
                    let mut servername_or_host: &str = "";
                    if let Some(value) = find_field_value(&item, &field_names) {
                        if !value.is_empty() {
                            servername_or_host = value;
                        }
                    }
                    let server = item.get("server").and_then(|v| v.as_str()).unwrap_or("");
                    /* 替换原来的port字段的值(字符串转换数字)，防止导入clash使用报错 */
                    let port_as_u16: Option<u16> = parse_port_value(item.get("port"));
                    // 修改端口
                    if let Some(port) = port_as_u16 {
                        map.insert(
                            YamlValue::String("port".to_string()),
                            YamlValue::Number(serde_yaml::Number::from(port)),
                        );
                    }
                    modify_clash_cipher_value(item, &mut map);
                    /* 下面代码的作用：
                    1.替换节点json数据中，不合法的name字段值，防止导入clash报错；
                    2.将最后修改过的节点的json数据插入到clash_set集合中
                    */
                    if let Some(YamlValue::String(original_name)) =
                        map.get(&YamlValue::String("name".to_string()))
                    {
                        // 替换掉name字段中不需要的字符或特殊字符，防止clash报错
                        let new_name = modify_clash_name_value(
                            original_name,
                            servername_or_host,
                            server,
                            port_as_u16,
                            clash_name_field_set,
                        );

                        // 更新map中的name
                        map.insert(
                            YamlValue::String("name".to_string()),
                            YamlValue::String(new_name),
                        );
                        let new_item = YamlValue::Mapping(map);
                        // 将修改后的new_item值，选择性插入clash_set集合中（忽略name键判断是否插入）
                        insert_unique_item_to_clash_set(clash_set, &new_item, &ignored_keys);
                    }
                }
            }
        } else {
            // YAML数据中，字段proxies不存在或不是数组
        }
    } else {
        // 不是yaml数据
    }
}

// 修改clash中的cipher字段值
fn modify_clash_cipher_value(item: &YamlValue, map: &mut serde_yaml::Mapping) {
    /* 替换原来的cipher字段的值，防止导致clash使用报错 */
    if let Some(type_value) = item.get("type") {
        if let Some(type_str) = type_value.as_str() {
            if let Some(cipher_value) = item.get("cipher") {
                if let Some(cipher_str) = cipher_value.as_str() {
                    match type_str {
                        "vmess" => {
                            // 如果vmess节点的cipher字段为空，则自动设置为"auto"
                            if cipher_str.is_empty() {
                                map.insert(
                                    YamlValue::String("cipher".to_string()),
                                    YamlValue::String("auto".to_string()),
                                );
                            }
                        }
                        "ss" => {
                            // 替换错误的chacha20-poly1305为chacha20-ietf-poly1305
                            if cipher_str == "chacha20-poly1305" {
                                map.insert(
                                    YamlValue::String("cipher".to_string()),
                                    YamlValue::String("chacha20-ietf-poly1305".to_string()),
                                );
                            }
                            // 替换错误的cipher值
                            if cipher_str == "ss" {
                                map.insert(
                                    YamlValue::String("cipher".to_string()),
                                    YamlValue::String("none".to_string()),
                                );
                            }
                        }
                        _ => {
                            // 如果"type"字段的值是其他值，你可以选择忽略它
                        }
                    }
                }
            } else {
                // 防止vmess节点中，没有字段cipher，导致报错
                match type_str {
                    "vmess" => {
                        map.insert(
                            YamlValue::String("cipher".to_string()),
                            YamlValue::String("auto".to_string()),
                        );
                    }
                    _ => {}
                }
            }
        }
    }
}

// 修改clash中的name字段值
fn modify_clash_name_value(
    original_name: &String,   // 原name字段值
    servername_or_host: &str, // 这个用于替换原name字段的值，如果为空则使用{server}:{port}格式的
    server: &str,
    port_as_u16: Option<u16>,
    clash_name_field_set: &Rc<RefCell<HashMap<String, String>>>,
) -> String {
    let re = Regex::new(r"[https?://|__| _|_ |_-_| - |\|\|]").unwrap();
    let mut new_original_name = re
        .replace_all(&original_name, "")
        .to_string()
        .replace("->", "→");
    if new_original_name.is_empty() {
        if !servername_or_host.is_empty() {
            // 使用servername_or_host的值为节点名称
            new_original_name = format!("{}", servername_or_host);
        } else {
            // 使用{server}:{port}格式的为节点名称
            new_original_name = format!("{}:{}", server, port_as_u16.unwrap());
        }
    }
    let mut base_name: String = new_original_name
        .chars()
        .take(32)
        .map(|c| match c {
            // 替换字符
            '@' | '%' | ',' => ' ',
            ' ' | '[' | ']' | '{' | '}' => '|',
            _ => c,
        })
        .collect();
    // 去掉前面替换为空格的空格字符
    base_name = base_name.replace(" ", "");
    // 去掉节点名称中开头和结尾为这些特殊字符的字符
    let special_chars = ['.', ':', '：', '_', '|', '-', '/'];
    while base_name.starts_with(&special_chars) || base_name.ends_with(&special_chars) {
        if base_name.starts_with(&special_chars) {
            base_name = base_name.trim_start_matches(&special_chars).to_string();
        }
        if base_name.ends_with(&special_chars) {
            base_name = base_name.trim_end_matches(&special_chars).to_string();
        }
    }
    let regex = Regex::new(r"^[A-Za-z0-9]{20,32}").unwrap();
    if let Some(_matched) = regex.find(&base_name) {
        // println!("匹配的部分: {}", matched.as_str());
        if !servername_or_host.is_empty() {
            // 使用找到的servername_or_host值为节点名称
            base_name = format!("{}", servername_or_host);
        } else {
            // 使用{server}:{port}格式的为节点名称
            base_name = format!("{}:{}", server, port_as_u16.unwrap());
        }
    }
    let new_name = if clash_name_field_set.borrow_mut().contains_key(&base_name) {
        let rng = rand::thread_rng();
        let rand_string: String = rng
            .clone()
            .sample_iter(&Alphanumeric)
            .take(4) // 你可以根据需要调整随机字符串的长度
            .map(char::from)
            .collect();
        // 如果名称已经存在，则使用server、port值创建一个新的唯一名称
        format!("{}#{}", base_name, rand_string)
    } else {
        // 原名称
        base_name.clone()
    };

    // 记录new_name，以避免将来重复使用
    clash_name_field_set
        .borrow_mut()
        .insert(base_name, new_name.clone());
    new_name
}

/* 查找端口的值，并将其转换为u16类型 */
fn parse_port_value(port_value: Option<&YamlValue>) -> Option<u16> {
    if let Some(value) = port_value {
        match value {
            YamlValue::String(port_str) => {
                if let Ok(port) = port_str.parse::<u16>() {
                    return Some(port);
                }
            }
            YamlValue::Number(port_num) => {
                if let Some(port) = port_num.as_u64() {
                    return Some(port as u16);
                }
            }
            _ => {}
        }
    }
    None
}

// 忽略除了ignored_keys中的其它键是否重复,不重复就插入集合中
fn insert_unique_item_to_clash_set(
    existing_items: &std::rc::Rc<std::cell::RefCell<HashSet<String>>>,
    new_item: &YamlValue,
    ignored_keys: &[&str],
) -> bool {
    if let Some(mapping) = new_item.as_mapping() {
        // 创建一个新的映射，排除 ignored_keys 中的所有键
        let mut filtered_mapping = Mapping::new();
        for (key, value) in mapping {
            if let Some(key_str) = key.as_str() {
                if !ignored_keys.contains(&key_str) {
                    filtered_mapping.insert(key.clone(), value.clone());
                }
            }
        }
        // 将过滤后的映射序列化为字符串
        if let Ok(filtered_str) = serde_yaml::to_string(&YamlValue::Mapping(filtered_mapping)) {
            // 检查临时HashSet是否已包含这个字符串，如果不包含，则添加完整的new_item
            if !existing_items.borrow().contains(&filtered_str) {
                if let Ok(full_item_str) = serde_yaml::to_string(new_item) {
                    // 将完整的new_item序列化后添加到existing_items中
                    return existing_items.borrow_mut().insert(full_item_str);
                }
            }
        }
    }
    // 如果new_item不是映射或无法序列化，则不添加
    false
}
