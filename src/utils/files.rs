use crate::utils::{
    common::split_links_vec,
    config::{
        CLASH_HEADERS,    // clash配置文件的基本信息
        RULES,            // clash中的规则信息
    },
    custom_struct::{CustomString, UrlJsonPair},
    yaml::find_key_as_filename, // 查找urls.yaml中，对应的key键名
};
use serde_json::{from_str, to_writer_pretty, Value as JsonValue};
use serde_yaml::Value as YamlValue;
use std::{
    collections::{HashMap, HashSet}, fs::{self, File}, io::{self, Write}, path::Path
};

// 创建文件夹，创建失败意味存在该文件夹，就清空当前文件夹里面的所有内容
pub fn create_folder_or_clear_file(dir: &Path) -> io::Result<()> {
    // 尝试创建目录，如果不存在则会成功，如果已存在则清空内容
    match fs::create_dir(dir) {
        Ok(_) => Ok(()), // 目录创建成功，无需进一步操作
        Err(ref e) if e.kind() == io::ErrorKind::AlreadyExists => {
            // 清空目录里面的所有内容
            clear_directory_contents(dir)?;
            Ok(())
        }
        Err(e) => Err(e), // 发生了其他类型的错误
    }
}

pub fn write_to_file(
    singbox_json_set: std::cell::Ref<HashSet<String>>,
    xray_json_set: std::cell::Ref<HashSet<String>>,
    json_set: std::cell::Ref<HashSet<UrlJsonPair>>,
    clash_set: std::cell::Ref<HashSet<String>>,
    links_set: std::cell::Ref<HashSet<CustomString>>,
    urls_config_yamlvalue: &YamlValue,
    output_folder: &str,
) {
    if !singbox_json_set.is_empty() {
        let singbox_template = r#"{"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"::","listen_port":1080,"sniff":true,"set_system_proxy":false}],"outbounds":[[]]}"#;
        write_outbounds_field_value_to_file(
            "output",
            "sing-box",
            singbox_template,
            singbox_json_set,
        )
        .expect("sing-box的配置文件写入失败！");
    }
    if !xray_json_set.is_empty() {
        let xray_template = r#"{"log":{"loglevel":"warning"},"routing":{"rules":[{"type":"field","ip":["geoip:private"],"outboundTag":"direct"}]},"inbounds":[{"listen":"127.0.0.1","port":10808,"protocol":"socks"},{"listen":"127.0.0.1","port":10809,"protocol":"http"}],"outbounds":[[],{"protocol":"freedom","settings":{},"tag":"direct"}]}"#;
        write_outbounds_field_value_to_file("output", "xray", xray_template, xray_json_set)
            .expect("xray的配置文件写入失败！");
    }
    if !clash_set.is_empty() {
        let clash_node_count = 500; // 每个clash配置文件最多写入多少个节点？避免在同一个文件中，生成过多的节点。
        write_proxies_field_value_to_file(output_folder, "clash", &clash_set, clash_node_count)
            .expect("clash的配置文件失败！");
    }
    if !json_set.is_empty() {
        for item in json_set.iter() {
            // 将 JSON 字符串反序列化为 JsonValue
            if let Ok(parsed_data) = from_str::<JsonValue>(&item.json_data) {
                // 查找url对应urls.yaml的哪个key键名，后面以这个key为文件名
                if let Some(key_str) =
                    find_key_as_filename(item.url.clone(), &urls_config_yamlvalue)
                {
                    // 以urls.yaml文件中的key名，作为文件名，生成唯一的文件名（不会因文件名相同覆盖原文件的数据）
                    let file_name = generate_unique_filename("output", key_str.clone(), "json");
                    write_json_to_file(file_name, &parsed_data).expect("写入失败！");
                } else {
                    // 从urls.yaml文件中，没有找到与url对应的key键名，就从url链接中截取后面的字符串作为文件名
                    let file_name = truncate_url_as_filename(item.url.clone().as_str(), output_folder);
                    write_json_to_file(file_name, &parsed_data).expect("写入失败！");
                }
            } else {
                println!("解析JSON数据失败");
            }
        }
    }
    if !links_set.is_empty() {
        // 将 links_set 转换为 Vec<String>
        let mut result_str_vec: Vec<String> = links_set
            .iter()
            .map(|custom_str| custom_str.to_string())
            .collect();
        result_str_vec.sort();

        let chunks = split_links_vec(result_str_vec, 1000);

        for (i, chunk) in chunks.iter().enumerate() {
            let file_name = format!("output/links_{}.txt", i + 1);
            let mut file = File::create(file_name).expect("无法创建文件");

            let output: Vec<String> = chunk
                .iter()
                .map(|item| item.replace(" ", "")) // 替换空格
                .collect();

            let output_str = output.join("\n"); // 拼接所有的字符串，每个字符串之间使用换行符分隔

            file.write_all(output_str.as_bytes())
                .expect("无法将数据写入文件");
        }
    }
}

pub fn write_failed_urls_to_file(failed: Vec<String>) {
    let mut file = File::create("这里是请求失败的链接.txt").expect("创建文件失败");
    writeln!(
        file,
        "这些链接是上次抓取网页内容时无法获取到的。除了链接本身失效外，还有可能是误判的情况。\n"
    )
    .expect("写入文件失败");

    for url in &failed {
        writeln!(file, "{}", url).expect("请求失败的链接，写入文件失败");
    }
}

// 将yaml中的proxies中的节点写入指定的yaml文件中
fn write_proxies_field_value_to_file(
    output_folder: &str,
    filename: &str,
    values: &HashSet<String>,
    chunk_size: usize, // 按照chunk_size个元素为一组进行拆分
) -> io::Result<()> {
    // let keys = vec!["type", "server", "port", "password"];
    // let sorted_values = sort_yaml_strings(values, &keys);

    let yaml_strings: Vec<String> = values.iter().cloned().collect();
    let json_strings: Result<Vec<String>, serde_json::Error> = yaml_strings
        .iter()
        .map(|s| {
            // 解析YAML字符串为YAML值
            let yaml_value: Result<serde_yaml::Value, _> = serde_yaml::from_str(s);
            // 将YAML值转换为JSON值
            let json_value: serde_json::Value = match yaml_value {
                Ok(value) => serde_json::from_value(serde_json::to_value(value)?).unwrap(),
                Err(e) => {
                    // 打印出错误消息（如果需要的话）
                    eprintln!("Error converting YAML to JSON: {}", e);
                    return Ok("".to_string()); // 返回一个空字符串或根据需要进行处理
                }
            };
            // 将JSON值序列化为字符串
            serde_json::to_string(&json_value)
        })
        .collect();

    match json_strings {
        Ok(strings) => {
            let mut iter = strings.iter();
            // 按照chunk_size个元素为一组进行拆分，并在每个组上进行操作
            while let Some(chunk) = iter
                .by_ref()
                .take(chunk_size)
                .collect::<Vec<_>>()
                .chunks(chunk_size)
                .next()
            {
                // 初始化一个HashMap来存储type作为键和name的向量作为值
                let mut type_name_map: HashMap<String, Vec<String>> = HashMap::new();

                // 将HashSet元素转换为JSON字符串并打印出来
                let json_strings: Result<Vec<String>, serde_json::Error> = chunk
                    .iter()
                    .map(|s| {
                        // 解析JSON字符串为JSON值
                        let json_value: Result<JsonValue, serde_json::Error> =
                            serde_json::from_str(s);
                        let mut json_value = match json_value {
                            Ok(value) => value,
                            Err(e) => {
                                // 打印出错误消息（如果需要的话）
                                eprintln!("Error parsing JSON: {}", e);
                                return Ok("".to_string()); // 返回一个空字符串或根据需要进行处理
                            }
                        };
                        // 现在处理一个JSON对象而非数组
                        if let JsonValue::Object(ref mut obj) = json_value {
                            // 从对象中提取type和name的值
                            if let (Some(type_value), Some(name_value)) =
                                (obj.get("type"), obj.get("name"))
                            {
                                if let (JsonValue::String(type_str), JsonValue::String(name_str)) =
                                    (type_value, name_value)
                                {
                                    // 将name添加到对应type的向量中
                                    type_name_map
                                        .entry(type_str.clone())
                                        .or_insert_with(Vec::new)
                                        .push(name_str.clone());
                                }
                            }
                        }

                        /* 将JSON值序列化为字符串（二选一） */
                        // 压缩成一行，单行显示（使用json数据结构，有花括号）
                        let json_string = serde_json::to_string(&json_value)?;

                        // 内容展开，多行显示
                        // let json_string = serde_json::to_string_pretty(&json_value).unwrap();
                        Ok(json_string)
                    })
                    .collect();
                // 根据 "type" 字段的顺序重新排序
                let sorted_json_strings = match json_strings {
                    Ok(strings) => {
                        let mut sorted_strings = strings.clone();
                        sorted_strings.sort_by_key(|s| {
                            let json_value: JsonValue = serde_json::from_str(s).unwrap();
                            json_value
                                .get("type")
                                .and_then(|t| t.as_str())
                                .unwrap()
                                .to_string()
                        });
                        sorted_strings
                    }
                    Err(e) => return Err(e.into()),
                };

                // 对每个 Vec<String> 进行排序，确保在yaml文件中，分组名称中的节点名是按照names字符串的顺序排序
                for (_, names) in &mut type_name_map {
                    names.sort();
                }

                let mut all_node_names = String::new();
                let mut group_names = String::new();
                let mut group_name_with_node_name_map = HashMap::new();
                // 遍历HashMap中的每个键值对
                for (key, names) in &type_name_map {
                    // 格式化key
                    let key_string = format!(
                        "  - name: 🚀 选择{}节点\n    type: select\n    proxies:",
                        key
                    );
                    group_names.push_str(&format!("      - 🚀 选择{}节点\n", key));

                    // 使用迭代器和map对names向量中的每个元素进行处理，然后用join把它们用换行符拼接起来
                    let names_string = names
                        .iter()
                        .map(|name| format!("      - {}", name))
                        .collect::<Vec<String>>()
                        .join("\n");
                    // 每个分组的名称和节点名称，成对地添加到HashMap中
                    group_name_with_node_name_map.insert(key_string.clone(), names_string.clone());
                    // 所有的节点名称，准备添加到“自动选择”的代理分组中
                    all_node_names.push_str(&format!("{}\n", names_string.clone()));
                }
                // 将HashMap中的键值对转换为一个可排序的Vec
                let mut protocol_select_groups: Vec<_> =
                    group_name_with_node_name_map.into_iter().collect();

                // 对Vec按键进行排序
                protocol_select_groups.sort_by(|&(ref key1, _), &(ref key2, _)| key1.cmp(key2));

                // ———————————————————————————————— 代理分组 ————————————————————————————————

                let select_nodes = 
                    format!("    type: select\n    proxies:\n      - 🎯 全球直连\n      - ♻️ 自动选择\n{}", group_names);
                
                // 构建拼接后的字符串（由多个"🚀 选择{}节点"代理分组组合）
                let protocol_groups: String = protocol_select_groups
                    .iter()
                    .flat_map(|(key, value)| vec![key.clone(), value.clone()])
                    .collect::<Vec<String>>()
                    .join("\n");

                let auto_select = 
                    format!("    type: url-test\n    url: http://www.gstatic.com/generate_204\n    interval: 500\n    proxies:\n{}", all_node_names);

                let direct = "    type: select\n    proxies:\n      - DIRECT\n      - ♻️ 自动选择\n";
                let global_interception = "    type: select\n    proxies:\n      - REJECT\n      - DIRECT\n";

                let homeless_exile = format!("    type: select\n    proxies:\n      - 🚀 节点选择\n      - 🎯 全球直连\n      - ♻️ 自动选择\n{}", all_node_names);

                // ——————————————————————————————————————————————————————————————————————————

                let proxy_group = format!(
                    "\nproxy-groups:\n  - name: 🚀 节点选择\n{}{}\n  - name: ♻️ 自动选择\n{}  - name: 🎯 全球直连\n{}  - name: 🛑 全球拦截\n{}  - name: 🐟 漏网之鱼\n{}",
                    select_nodes,
                    protocol_groups, // 其它分组，包含了多个分组已经对应的节点名称
                    auto_select,
                    direct,
                    global_interception,
                    homeless_exile,
                );
                
                // 【YAML排序】转为JSON数据后按照JSON中字段相同的排序在一起
                // let sorted_json_strings = sort_json_vec_of_string(json_strings.clone());
                
                let proxyies_message = sorted_json_strings
                    .iter()
                    .map(|value| format!("  - {}", value))
                    .collect::<Vec<_>>()
                    .join("\n");

                // clash的头部信息(端口、代理模式、dns等)+代理节点+代理分组+规则
                let result = CLASH_HEADERS.to_owned() + &proxyies_message + &proxy_group + RULES; // 添加"proxies:"作为精简版clash配置文件

                // 生成唯一的文件名（已经添加文件夹output_folder=output），存在该文件就添加编号
                let file_path =
                    generate_unique_filename(output_folder, filename.to_owned(), "yaml");
                fs::write(file_path, result)?;
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }

    Ok(())
}

// 将json中的outbounds中的节点写入指定的json文件中
fn write_outbounds_field_value_to_file(
    output_folder: &str,
    filename: &str,
    template: &str,
    values: std::cell::Ref<HashSet<String>>,
) -> io::Result<()> {
    // 将 HashSet 转换为 Vec<String>
    // let values_vec_of_string: Vec<String> = values.into_iter().collect::<Vec<_>>();
    // 首先按照JSON对象的键进行排序，然后递归比较JSON对象的值或数组的元素
    // let sorted_json_vec_of_string = sort_json_vec_of_string(values_vec_of_string.clone());
    // 按照JSON中字段相同的排序在一起
    // let result_string: String = sorted_json_vec_of_string.join(",\n  ");
    let mut i = 0;
    for value in values.clone() {
        let value_json: serde_json::Value = serde_json::from_str(&value)?;
        if let Some(protocol) = value_json.get("protocol") {
            if protocol == "blackhole" || protocol == "freedom" {
                continue;
            }
        }
        let output_str = format!("{}", template.replace(r"[]", &value));
        let json_value: JsonValue = serde_json::from_str(&output_str)?;
        let pretty_str = serde_json::to_string_pretty(&json_value).unwrap();
        i += 1;
        let file_path = format!("{}/{}_{}.json", output_folder, filename, i);
        let _ = fs::write(file_path, pretty_str);
    }
    Ok(())
}

// 将抓取到的整个json数据写入output/*.json文件中，（json数据中有字段outbounds的使用另外一个函数跟其它配置信息合并在一起，不使用这个函数）
fn write_json_to_file(filename: String, json_value: &JsonValue) -> io::Result<()> {
    let file = File::create(filename)?;
    to_writer_pretty(file, json_value)?;
    Ok(())
}

// 生成唯一的文件名，存在该文件就添加编号
fn generate_unique_filename(
    output_folder: &str,
    original_filename: String,
    suffix: &str,
) -> String {
    let mut count: i32 = 1;
    let mut unique_file_name = format!(
        "{}/{}_{}.{}",
        output_folder, original_filename, count, suffix
    );
    // 检查现有文件名，必要时添加编号
    while Path::new(&unique_file_name).exists() {
        count += 1;
        unique_file_name = format!(
            "{}/{}_{}.{}",
            output_folder, original_filename, count, suffix
        );
    }

    unique_file_name
}

// 截取url后面的字符当成文件名使用，如果本地存在这个文件就添加编号
fn truncate_url_as_filename(url: &str, output_folder: &str) -> String {
    // 从 URL 提取文件名
    let original_filename = url.rsplit('/').next().unwrap_or("unknown");
    let mut count = 1;
    // 分割文件名和扩展名
    if let Some((filename, suffix)) = original_filename.split_once('.') {
        let mut unique_file_name = format!("{}/{}_{}.{}", output_folder, filename, count, suffix);
        // 检查现有文件名，必要时添加编号
        while Path::new(&unique_file_name).exists() {
            count += 1;
            unique_file_name = format!("{}/{}_{}.{}", output_folder, filename, count, suffix);
        }
        return unique_file_name;
    }
    // 如果找不到扩展名，则在文件名后添加一个数字
    let mut unique_file_name = format!("{}/{}_{}", output_folder, original_filename, count);
    // 检查现有文件名，必要时添加编号
    while Path::new(&unique_file_name).exists() {
        count += 1;
        unique_file_name = format!("{}/{}_{}", output_folder, original_filename, count);
    }

    unique_file_name
}

// 删除目录里面的所有内容（包括里面的文件夹、文件）
fn clear_directory_contents(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        // 获取目录里所有的条目
        let entries = fs::read_dir(dir)?;
        // 遍历条目并删除每一个
        for entry in entries {
            let entry_path = entry?.path();
            // 判断是文件还是目录
            if entry_path.is_dir() {
                // 递归删除子目录
                fs::remove_dir_all(&entry_path)?;
            } else {
                // 删除文件
                fs::remove_file(entry_path)?;
            }
        }
    }
    Ok(())
}
