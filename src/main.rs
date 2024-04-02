mod utils;

use utils::files::create_folder_or_clear_file; // 创建文件夹或清空文件夹中的所有内容
use utils::files::generate_unique_filename; // 生成唯一的文件名（防止覆盖之前写的文件）
use utils::files::truncate_url_as_filename; // 从url链接后面截取后面的字符串作为文件名
use utils::files::write_json_to_file; // 写入json文件中
use utils::files::write_outbounds_field_value_to_file; // 写入xray或sing-bos的配置文件中
use utils::files::write_proxies_field_value_to_file; // 写入clash的配置文件中
use utils::links::extract_links; // 从字符串中(网页中)提取是各大代理协议的链接，比如：ss://、ssr://、vless://等等
use utils::network::fetch; // 抓取网页的内容
use utils::yaml::can_convert_to_json_or_yaml; // 检查是否可以转为json或yaml
use utils::yaml::extract_urls_of_yaml; // 提取urls.yaml中的所有链接
use utils::yaml::find_field_value; // 递归查找field_vec中的字段的值，只要找到值，就立刻返回
use utils::yaml::find_key_as_filename; // 从urls.yaml中找改url对应的key是什么，找到就作为文件名

use base64::decode;
use rand::{distributions::Alphanumeric, Rng};
use regex::Regex;
use serde_json::{from_str, Value as JsonValue};
use serde_yaml::{Mapping, Value as YamlValue};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    fs::File,
    hash::Hash,
    hash::Hasher,
    io::{self, BufReader, Write},
    path::Path,
    rc::Rc,
};

/*
下面的struct和impl的作用，只有(明文)节点链接中开头到#之间的字符串相同，
就进行hashset去重，不是按照整行节点链接相同才去重的
*/
#[derive(Debug, Eq, PartialEq, Hash)]
struct CustomString {
    inner: Rc<str>,
}

impl CustomString {
    fn new(inner: &str) -> Self {
        CustomString {
            inner: Rc::from(inner),
        }
    }
}

impl Clone for CustomString {
    fn clone(&self) -> Self {
        CustomString {
            inner: self.inner.clone(),
        }
    }
}

impl fmt::Display for CustomString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

/*
下面的struct和impl的作用，只按照结构体的json_data的去重，
不是按照整个UrlJsonPair的url和json_data都相同的hashset去重
*/
#[derive(Debug, Eq)]
struct UrlJsonPair {
    url: String,
    json_data: String,
}

impl Hash for UrlJsonPair {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.json_data.hash(state);
    }
}

impl PartialEq for UrlJsonPair {
    fn eq(&self, other: &Self) -> bool {
        self.json_data == other.json_data
    }
}

#[tokio::main]
async fn main() {
    let urls_config_file = "urls.yaml";

    // 读取 YAML 文件
    let file = File::open(urls_config_file).expect("Failed to open file");
    let reader = BufReader::new(file);
    // 解析 YAML 文件为 serde_yaml::Value
    let config_data: YamlValue = serde_yaml::from_reader(reader).expect("Failed to parse YAML");

    // 提取所有的值url
    let urls = extract_urls_of_yaml(&config_data);
    let save_folder = "output";

    /* 创建output文件夹，如果output文件夹已经存在，就删除里面存在的所有文件夹和文件 */
    create_folder_or_clear_file(Path::new(save_folder))
        .expect("创建文件夹失败或删除文件夹中的所有内容失败！");

    let tasks = urls
        .into_iter()
        .map(|url| tokio::spawn(fetch(url)))
        .collect::<Vec<_>>();

    let mut links_prefix_set = HashSet::new(); // 记录每行字符串开头到#的内容（节点链接去重）

    let mut results_links_set = HashSet::new(); // 节点链接
    let mut results_clash_set = HashSet::new(); // yaml中，字段proxies的值(粗略去重)，clash配置
    let mut outbounds_xray_json_set = HashSet::new(); // json中，字段outbounds的值(粗略去重)，xray配置
    let mut outbounds_sing_box_json_set = HashSet::new(); // json中，字段outbounds的值(粗略去重)，sing-box配置
    let mut json_content_set = HashSet::new();
    let mut yaml_existing_names: HashMap<String, String> = HashMap::new(); // 记录yaml中节点中的name名称，当名称重复时，就改为其它的名称
    let mut failed = Vec::new();
    for task in tasks {
        match task.await {
            Ok((url, body)) => {
                // 获取失败的URL
                if body == "Error" {
                    failed.push(url.clone());
                }
                /* 能转换为json或yaml的 */
                if can_convert_to_json_or_yaml(&body) {
                    // 是yaml的数据
                    if let Ok(yaml_value) = serde_yaml::from_str::<YamlValue>(&body) {
                        if let Some(YamlValue::Sequence(items)) = yaml_value.get("proxies") {
                            // 定义要忽略的键
                            let ignored_keys =
                                ["name", "client-fingerprint", "skip-cert-verify", "tfo"];
                            for item in items {
                                if let YamlValue::Mapping(mut map) = item.clone() {
                                    /* 从field_names中找字段对应的值，找到的值就作为节点名称（选择性，不完全使用这个名称） */
                                    let field_names = ["servername", "Host"];
                                    let mut found_value: &str = "";
                                    if let Some(value) = find_field_value(&item, &field_names) {
                                        if !value.is_empty() {
                                            found_value = value;
                                        }
                                    }
                                    let server =
                                        item.get("server").and_then(|v| v.as_str()).unwrap_or("");
                                    /* 替换原来的port字段的值(字符串转换数字)，防止导入clash使用报错 */
                                    let port_as_u16: Option<u16> =
                                        parse_port_value(item.get("port"));
                                    // 修改端口
                                    if let Some(port) = port_as_u16 {
                                        map.insert(
                                            YamlValue::String("port".to_string()),
                                            YamlValue::Number(serde_yaml::Number::from(port)),
                                        );
                                    }
                                    /* 替换原来的cipher字段的值，防止导致clash使用报错 */
                                    if let Some(type_value) = item.get("type") {
                                        if let Some(type_str) = type_value.as_str() {
                                            if let Some(cipher_value) = item.get("cipher") {
                                                if let Some(cipher_str) = cipher_value.as_str() {
                                                    match type_str {
                                                        "vmess" => {
                                                            // 如果vmess节点的cipher字段为空，则自动设置为"auto"，防止导入clash客户端中使用报错
                                                            if cipher_str.is_empty() {
                                                                map.insert(
                                                                    YamlValue::String(
                                                                        "cipher".to_string(),
                                                                    ),
                                                                    YamlValue::String(
                                                                        "auto".to_string(),
                                                                    ),
                                                                );
                                                            }
                                                        }
                                                        "ss" => {
                                                            // 替换错误的chacha20-poly1305为chacha20-ietf-poly1305
                                                            if cipher_str == "chacha20-poly1305" {
                                                                map.insert(
                                                                    YamlValue::String(
                                                                        "cipher".to_string(),
                                                                    ),
                                                                    YamlValue::String(
                                                                        "chacha20-ietf-poly1305"
                                                                            .to_string(),
                                                                    ),
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
                                    /* 下面代码的作用，
                                    1.替换节点json数据中，不合法的name字段值，防止导入clash报错；
                                    2.将最后修改过的节点的json数据插入到results_clash_set集合中
                                    */
                                    if let Some(YamlValue::String(original_name)) =
                                        map.get(&YamlValue::String("name".to_string()))
                                    {
                                        // 替换掉name字段中不需要的字符或特殊字符，防止clash报错
                                        let re = Regex::new(r"[https?://|__| _|_ |_-_| - |\|\|]")
                                            .unwrap();
                                        let mut new_original_name = re
                                            .replace_all(&original_name, "")
                                            .to_string()
                                            .replace("->", "→");
                                        if new_original_name.is_empty() {
                                            if !found_value.is_empty() {
                                                // 使用找到的found_value值为节点名称
                                                new_original_name = format!("{}", found_value);
                                            } else {
                                                // 使用{server}:{port}格式的为节点名称
                                                new_original_name =
                                                    format!("{}:{}", server, port_as_u16.unwrap());
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
                                        while base_name.starts_with(&special_chars)
                                            || base_name.ends_with(&special_chars)
                                        {
                                            if base_name.starts_with(&special_chars) {
                                                base_name = base_name
                                                    .trim_start_matches(&special_chars)
                                                    .to_string();
                                            }
                                            if base_name.ends_with(&special_chars) {
                                                base_name = base_name
                                                    .trim_end_matches(&special_chars)
                                                    .to_string();
                                            }
                                        }
                                        let regex = Regex::new(r"^[A-Za-z0-9]{20,32}").unwrap();
                                        if let Some(_matched) = regex.find(&base_name) {
                                            // println!("匹配的部分: {}", matched.as_str());
                                            if !found_value.is_empty() {
                                                // 使用找到的found_value值为节点名称
                                                base_name = format!("{}", found_value);
                                            } else {
                                                // 使用{server}:{port}格式的为节点名称
                                                base_name =
                                                    format!("{}:{}", server, port_as_u16.unwrap());
                                            }
                                        }
                                        let new_name =
                                            if yaml_existing_names.contains_key(&base_name) {
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
                                        yaml_existing_names.insert(base_name, new_name.clone());

                                        // 更新map中的name
                                        map.insert(
                                            YamlValue::String("name".to_string()),
                                            YamlValue::String(new_name),
                                        );
                                        let new_item = YamlValue::Mapping(map);
                                        // 将修改后的new_item值，选择性插入results_clash_set集合中（忽略name键判断是否插入）
                                        insert_unique_item_to_clash_set(
                                            &mut results_clash_set,
                                            &new_item,
                                            &ignored_keys,
                                        );
                                    }
                                }
                            }
                        } else {
                            // YAML数据中，字段proxies不存在或不是数组
                        }
                    } else {
                        // 无法解析为YAML数据
                    }
                    // 是json的数据
                    if let Ok(json_value) = from_str::<JsonValue>(&body) {
                        // 检查字段是否存在且是一个数组
                        if let Some(items) = json_value
                            .get("outbounds")
                            .and_then(|array| array.as_array())
                        {
                            for item in items {
                                let item_string = item.to_string();
                                if item.get("type").is_some() {
                                    // 有type字段的通常是sing-box的配置文件
                                    outbounds_sing_box_json_set.insert(item_string.clone());
                                }
                                if item.get("protocol").is_some() {
                                    // 有protocol字段的通常是xray的配置文件
                                    outbounds_xray_json_set.insert(item_string.clone());
                                }
                            }
                        } else {
                            // Json数据中，字段outbounds不存在或不是数组
                            let json_string = json_value.to_string();
                            // 将url和字符串化的json数据放到自定义的数据结构体中
                            let url_json_pair = UrlJsonPair {
                                url,
                                json_data: json_string,
                            };
                            // 插入到HashSet中，去重（使用 json_data 字段的哈希值和相等性来进行去重）
                            json_content_set.insert(url_json_pair);
                        }
                    } else {
                        // 无法解析为JSON数据
                    }
                } else {
                    println!("程序运行中，稍等一下...");
                    let protocols: Vec<&str> = vec![
                        "socks",
                        "socks4",
                        "socks5",
                        "ss",
                        "ssr",
                        "vless",
                        "vmess",
                        "trojan",
                        "hysteria",
                        "hysteria2",
                        "hy2",
                        "tuic",
                        "naive+https",
                        "wireguard",
                        "warp",
                        "juicity",
                        "nekoray",
                    ];
                    // 是节点的链接（包含明文链接和base64加密的字符串）
                    for line in body.split('\n') {
                        if !line.trim().is_empty() {
                            // 尝试对字符串进行base64解码
                            if let Ok(decoded) = decode(line) {
                                let decoded_str = String::from_utf8_lossy(&decoded);
                                // base64解密后，存放到一个向量中（含多个代理链接）
                                let base64_str_li: Vec<&str> = decoded_str.lines().collect();
                                for base64_str in base64_str_li {
                                    if !base64_str.trim().is_empty()
                                        && is_protocol(base64_str.trim())
                                    {
                                        let protocol_urls = extract_links(base64_str, &protocols);
                                        for protocol_url in protocol_urls {
                                            let custom_str =
                                                CustomString::new(protocol_url.as_str());
                                            if protocol_url.starts_with("nekoray://") {
                                                results_links_set.insert(custom_str);
                                            } else if protocols
                                                .iter()
                                                .take(protocols.len() - 1)
                                                .any(|&s| {
                                                    protocol_url
                                                        .starts_with(&(s.to_owned() + "://"))
                                                })
                                            {
                                                // 以每行字符串的开头到#字符结尾为参考去重
                                                let prefix: String = custom_str
                                                    .inner
                                                    .chars()
                                                    .take_while(|&c| c != '#')
                                                    .collect();
                                                if links_prefix_set.insert(prefix.clone()) {
                                                    results_links_set.insert(custom_str);
                                                }
                                            }
                                        }
                                    }
                                }
                                // 不是base64加密的字符串
                            } else {
                                let protocol_urls = extract_links(line, &protocols);
                                for protocol_url in protocol_urls {
                                    let custom_str = CustomString::new(protocol_url.as_str());
                                    if protocol_url.starts_with("nekoray://") {
                                        results_links_set.insert(custom_str);
                                    } else if protocols
                                        .iter()
                                        .take(protocols.len() - 1)
                                        .any(|&s| protocol_url.starts_with(&(s.to_owned() + "://")))
                                    {
                                        // 以每行字符串的开头到#字符结尾为参考去重
                                        let prefix: String = custom_str
                                            .inner
                                            .chars()
                                            .take_while(|&c| c != '#')
                                            .collect();
                                        if links_prefix_set.insert(prefix.clone()) {
                                            results_links_set.insert(custom_str);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(error) => eprintln!("Task failed: {:?}", error), // tokio::spawn失败
        }
    }
    if !outbounds_sing_box_json_set.is_empty() {
        let singbox_template = r#"{"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"::","listen_port":1080,"sniff":true,"set_system_proxy":false}],"outbounds":[[]]}"#;
        write_outbounds_field_value_to_file(
            "output",
            "sing-box",
            singbox_template,
            outbounds_sing_box_json_set,
        )
        .expect("sing-box的配置文件写入失败！");
    }
    if !outbounds_xray_json_set.is_empty() {
        let xray_template = r#"{"log":{"loglevel":"warning"},"routing":{"rules":[{"type":"field","ip":["geoip:private"],"outboundTag":"direct"}]},"inbounds":[{"listen":"127.0.0.1","port":10808,"protocol":"socks"},{"listen":"127.0.0.1","port":10809,"protocol":"http"}],"outbounds":[[],{"protocol":"freedom","settings":{},"tag":"direct"}]}"#;
        write_outbounds_field_value_to_file(
            "output",
            "xray",
            xray_template,
            outbounds_xray_json_set,
        )
        .expect("xray的配置文件写入失败！");
    }
    if !results_clash_set.is_empty() {
        let clash_node_count = 500; // 每个clash配置文件最多写入多少个节点？避免在同一个文件中，生成过多的节点。
        write_proxies_field_value_to_file(
            save_folder,
            "clash",
            &results_clash_set,
            clash_node_count,
        )
        .expect("clash的配置文件失败！");
    }
    if !json_content_set.is_empty() {
        for item in json_content_set {
            // 将 JSON 字符串反序列化为 JsonValue
            if let Ok(parsed_data) = from_str::<JsonValue>(&item.json_data) {
                // 查找url对应urls.yaml的哪个key键名，后面以这个key为文件名
                if let Some(key_str) = find_key_as_filename(item.url.clone(), &config_data) {
                    // 以urls.yaml文件中的key名，作为文件名，生成唯一的文件名（不会因文件名相同覆盖原文件的数据）
                    let file_name = generate_unique_filename("output", key_str.clone(), "json");
                    write_json_to_file(file_name, &parsed_data).expect("写入失败！");
                } else {
                    // 从urls.yaml文件中，没有找到与url对应的key键名，就从url链接中截取后面的字符串作为文件名
                    let file_name = truncate_url_as_filename(item.url.clone().as_str(), "output");
                    write_json_to_file(file_name, &parsed_data).expect("写入失败！");
                }
            } else {
                println!("解析JSON数据失败");
            }
        }
    }
    if !results_links_set.is_empty() {
        // 将 results_links_set 转换为 Vec<String>
        let mut result_str_vec: Vec<String> = results_links_set
            .iter()
            .map(|custom_str| custom_str.to_string())
            .collect();
        result_str_vec.sort();
        // 打开或创建一个文件，如果文件已存在则会被覆盖
        let mut file = File::create("output/links.txt").expect("无法创建文件");

        let output: Vec<String> = result_str_vec
            .iter()
            .map(|item| item.replace(" ", "")) // 替换空格
            .collect();

        let output_str = output.join("\n"); // 拼接所有的字符串，每个字符串之间使用换行符分隔

        file.write_all(output_str.as_bytes())
            .expect("无法将数据写入文件");
    }
    let mut file = File::create("这里是请求失败的链接.txt").expect("创建文件失败");
    writeln!(
        file,
        "这些链接是上次抓取网页内容时无法获取到的。除了链接本身失效外，还有可能是误判的情况。\n"
    )
    .expect("写入文件失败");

    for url in &failed {
        writeln!(file, "{}", url).expect("请求失败的链接，写入文件失败");
    }
    print!("\n程序运行结束，最终结果输出到{}文件夹中！", save_folder);
    io::stdout().flush().unwrap(); // 强制刷新标准输出缓冲区
    wait_for_enter(); // 等待用户按Enter键退出程序
}

// 忽略除了ignored_keys中的其它键是否重复,不重复就插入集合中
fn insert_unique_item_to_clash_set(
    existing_items: &mut HashSet<String>,
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
            if !existing_items.contains(&filtered_str) {
                if let Ok(full_item_str) = serde_yaml::to_string(new_item) {
                    // 将完整的new_item序列化后添加到existing_items中
                    return existing_items.insert(full_item_str);
                }
            }
        }
    }
    // 如果new_item不是映射或无法序列化，则不添加
    false
}

// 初步判断是否为代理链接
fn is_protocol(s: &str) -> bool {
    let re = Regex::new(r"^[a-zA-Z]+://").unwrap();
    re.is_match(s)
}

/* 辅助函数：等待用户按Enter键退出程序 */
fn wait_for_enter() {
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("无法读取行");
    // 移除输入中的换行符
    let _ = input.trim();
    io::stdout().flush().expect("无法刷新缓冲区");
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
