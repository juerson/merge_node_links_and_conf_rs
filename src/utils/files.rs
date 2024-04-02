// use crate::utils::sorted::sort_yaml_strings;
use crate::utils::config::CLASH_BASIC_INFO;
use crate::utils::config::RULES;
// use crate::utils::sorted::sort_json_vec_of_string;
use serde_json::{to_writer_pretty, Value as JsonValue};
use std::collections::HashMap;
use std::collections::HashSet;
// use std::fmt::format;
use std::fs;
use std::fs::File;
use std::io;
use std::path::Path;

// 将yaml中的proxies中的节点写入指定的yaml文件中
pub fn write_proxies_field_value_to_file(
    save_folder: &str,
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

                // let mut other_proxy_groups = String::new();
                let mut all_node_names = String::new();
                let mut group_names = String::new();
                let mut group_name_with_node_name_map = HashMap::new();
                // 遍历HashMap中的每个键值对
                for (key, names) in &type_name_map {
                    // 格式化key
                    let key_string = format!(
                        "  - name: 🚀 选择{}节点\n    type: select\n    proxies:\n      - 🎯 全球直连",
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
                let mut other_groups_vec: Vec<_> =
                    group_name_with_node_name_map.into_iter().collect();

                // 对Vec按键进行排序
                other_groups_vec.sort_by(|&(ref key1, _), &(ref key2, _)| key1.cmp(key2));

                // 构建拼接后的字符串（由多个代理分组组合在其它的）
                let other_groups: String = other_groups_vec
                    .iter()
                    .flat_map(|(key, value)| vec![key.clone(), value.clone()])
                    .collect::<Vec<String>>()
                    .join("\n");

                let select_nodes_type_group = format!("  - name: 🔰 选择代理类型\n    type: select\n    proxies:\n      - 🎯 全球直连\n      - ♻️ 自动选择\n{}", group_names);
                let auto_select_nodes_group = format!("  - name: ♻️ 自动选择\n    type: url-test\n    url: http://www.gstatic.com/generate_204\n    interval: 500\n    proxies:\n{}", all_node_names);
                let global_interception = format!("  - name: 🛑 全球拦截\n    type: select\n    proxies:\n      - REJECT\n      - DIRECT\n");
                let direct = format!(
                    "  - name: 🎯 全球直连\n    type: select\n    proxies:\n      - DIRECT\n"
                );
                let proxy_group = format!(
                    "\nproxy-groups:\n{}{}\n{}{}{}",
                    select_nodes_type_group,
                    other_groups, // 其它分组，包含了多个分组已经对应的节点名称
                    auto_select_nodes_group,
                    global_interception,
                    direct,
                );

                let rutles = format!("{}\n  - MATCH,🔰 选择代理类型", RULES);

                // 【YAML排序】转为JSON数据后按照JSON中字段相同的排序在一起
                // let sorted_json_strings = sort_json_vec_of_string(json_strings.clone());
                let yaml_content: String = sorted_json_strings
                    .iter()
                    .map(|value| format!("  - {}", value))
                    .collect::<Vec<_>>()
                    .join("\n");
                let clash_proxy_prefix = format!("{}\n", CLASH_BASIC_INFO); // clash配置文件开头port、dns这些信息
                let result = clash_proxy_prefix.to_owned() + &yaml_content + &proxy_group + &rutles; // 添加"proxies:"作为精简版clash配置文件

                // 生成唯一的文件名（已经添加文件夹save_folder=output），存在该文件就添加编号
                let file_path = generate_unique_filename(save_folder, filename.to_owned(), "yaml");
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
pub fn write_outbounds_field_value_to_file(
    save_folder: &str,
    filename: &str,
    template: &str,
    values: HashSet<String>,
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
        let file_path = format!("{}/{}_{}.json", save_folder, filename, i);
        let _ = fs::write(file_path, pretty_str);
    }
    Ok(())
}

// 将抓取到的整个json数据写入output/*.json文件中，（json数据中有字段outbounds的使用另外一个函数跟其它配置信息合并在一起，不使用这个函数）
pub fn write_json_to_file(filename: String, json_value: &JsonValue) -> io::Result<()> {
    // 打开文件进行写入
    let file = File::create(filename)?;
    // 将JSON值写入文件，并进行美化格式化
    to_writer_pretty(file, json_value)?;

    Ok(())
}

// 生成唯一的文件名，存在该文件就添加编号
pub fn generate_unique_filename(
    save_folder: &str,
    original_file_name: String,
    suffix: &str,
) -> String {
    let mut count: i32 = 1;
    let mut unique_file_name = format!(
        "{}/{}_{}.{}",
        save_folder, original_file_name, count, suffix
    );
    // 检查现有文件名，必要时添加编号
    while Path::new(&unique_file_name).exists() {
        count += 1;
        unique_file_name = format!(
            "{}/{}_{}.{}",
            save_folder, original_file_name, count, suffix
        );
    }

    unique_file_name
}

// 截取url后面的字符当成文件名使用，如果本地存在这个文件就添加编号
pub fn truncate_url_as_filename(url: &str, save_folder: &str) -> String {
    // 从 URL 提取文件名
    let original_file_name = url.rsplit('/').next().unwrap_or("unknown");
    let mut count = 1;
    // 分割文件名和扩展名
    if let Some((filename, suffix)) = original_file_name.split_once('.') {
        let mut unique_file_name = format!("{}/{}_{}.{}", save_folder, filename, count, suffix);
        // 检查现有文件名，必要时添加编号
        while Path::new(&unique_file_name).exists() {
            count += 1;
            unique_file_name = format!("{}/{}_{}.{}", save_folder, filename, count, suffix);
        }
        return unique_file_name;
    }
    // 如果找不到扩展名，则在文件名后添加一个数字
    let mut unique_file_name = format!("{}/{}_{}", save_folder, original_file_name, count);
    // 检查现有文件名，必要时添加编号
    while Path::new(&unique_file_name).exists() {
        count += 1;
        unique_file_name = format!("{}/{}_{}", save_folder, original_file_name, count);
    }

    unique_file_name
}

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
