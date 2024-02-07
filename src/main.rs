use reqwest::Client;
use std::{
    fs::{self, File},
    io::{self, Write, BufReader},
    collections::{HashSet, BTreeMap},
    hash::Hash,
    fmt,
    rc::Rc,
    path::Path,
    hash::Hasher,
};
use base64::decode;
use serde_json::{Value as JsonValue, from_str, to_writer_pretty};
use serde_yaml::{Value as YamlValue, to_string};
use std::time::Duration;
use tokio::time;
use regex::Regex;
use chrono::prelude::*;

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
        CustomString { inner: Rc::from(inner) }
    }
}

impl Clone for CustomString {
    fn clone(&self) -> Self {
        CustomString { inner: self.inner.clone() }
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
    create_folder_or_clear_file(Path::new(save_folder)).expect("创建文件夹失败或删除文件夹中的所有内容失败！");

    let tasks = urls.into_iter().map(|url| {
        tokio::spawn(fetch_url(url))
    }).collect::<Vec<_>>();

    let mut seen_prefixes = HashSet::new();  // 记录每行字符串开头到#的内容（节点链接去重）

    let mut links_result_set = HashSet::new(); // 节点链接
    let mut proxies_clash_yaml_set = HashSet::new(); // yaml中，字段proxies的值(粗略去重)，clash配置
    let mut outbounds_xray_json_set = HashSet::new(); // json中，字段outbounds的值(粗略去重)，xray配置
    let mut outbounds_sing_box_json_set = HashSet::new(); // json中，字段outbounds的值(粗略去重)，sing-box配置
    let mut json_content_set = HashSet::new();

    for task in tasks {
        let result = task.await;
        if let Err(error) = result {
            eprintln!("Task failed: {:?}", error);
            continue;
        }
        let (url, body) = result.unwrap();
        /* 能转换为json或yaml的 */
        if can_convert_to_json_or_yaml(&body) { // 是json或yaml的数据
            if let Ok(yaml_value) = serde_yaml::from_str::<YamlValue>(&body) {
                if let Some(YamlValue::Sequence(items)) = yaml_value.get("proxies") {
                    for item in items {
                        let item_string = to_string(item).unwrap();
                        proxies_clash_yaml_set.insert(item_string);
                    }
                } else {
                    // YAML数据中，字段proxies不存在或不是数组
                }
            } else {
                // 无法解析为YAML数据
            }
            if let Ok(json_value) = from_str::<JsonValue>(&body) {
                // 检查字段是否存在且是一个数组
                if let Some(items) = json_value.get("outbounds").and_then(|array| array.as_array()) {
                    for item in items {
                        let item_string = item.to_string();
                        if item.get("type").is_some() { // 有type字段的通常是sing-box的配置文件
                            outbounds_sing_box_json_set.insert(item_string.clone());
                        }
                        if item.get("protocol").is_some() { // 有protocol字段的通常是xray的配置文件
                            outbounds_xray_json_set.insert(item_string.clone());
                        }
                    }
                } else {// Json数据中，字段outbounds不存在或不是数组
                    let json_string = json_value.to_string();
                    // 将url和字符串化的json数据放到自定义的数据结构体中
                    let url_json_pair = UrlJsonPair { url, json_data: json_string };
                    // 插入到HashSet中，去重（使用 json_data 字段的哈希值和相等性来进行去重）
                    json_content_set.insert(url_json_pair);
                }
            } else {
                // 无法解析为JSON数据
            }
        } else { // 不是json或yaml的数据
            for line in body.split('\n') {
                if !line.trim().is_empty() {
                    // 尝试对字符串进行base64解码
                    if let Ok(decoded) = decode(line) {
                        let decoded_str = String::from_utf8_lossy(&decoded);
                        // base64解密后，存放到一个向量中（含多个代理链接）
                        let base64_str_li: Vec<&str> = decoded_str.lines().collect();
                        for base64_str in base64_str_li {
                            if !base64_str.trim().is_empty() {
                                let custom_str = CustomString::new(base64_str);
                                // 以每行字符串的开头到#字符结尾为参考去重
                                let prefix: String = custom_str.inner.chars().take_while(|&c| c != '#').collect();
                                if seen_prefixes.insert(prefix.clone()) {
                                    links_result_set.insert(custom_str);
                                }
                            }
                        }
                        // 不是base64加密的字符串
                    } else {
                        let custom_str = CustomString::new(line);
                        // 以每行字符串的开头到#字符结尾为参考去重
                        let prefix: String = custom_str.inner.chars().take_while(|&c| c != '#').collect();
                        if seen_prefixes.insert(prefix.clone()) {
                            links_result_set.insert(custom_str);
                        }
                    }
                }
            }
        }
    }
    if !outbounds_sing_box_json_set.is_empty() {
        write_outbounds_field_value_to_file("output/sing-box_outbounds.json", outbounds_sing_box_json_set).expect("写入sing-box_outbounds.json文件失败！");
    }
    if !outbounds_xray_json_set.is_empty() {
        write_outbounds_field_value_to_file("output/xray_outbounds.json", outbounds_xray_json_set).expect("写入xray_outbounds.json文件失败！");
    }
    if !proxies_clash_yaml_set.is_empty() {
        write_proxies_field_value_to_file("output/clash_proxies.yaml", &proxies_clash_yaml_set).expect("写入clash_proxies.yaml文件失败！");
    }
    if !json_content_set.is_empty() {
        for item in json_content_set {
            // 将 JSON 字符串反序列化为 JsonValue
            if let Ok(parsed_data) = from_str::<JsonValue>(&item.json_data) {
                // 查找url对应urls.yaml的哪个key键名，后面以这个key为文件名
                if let Some(key_str) = find_key_as_filename(item.url.clone(), &config_data) {
                    // 以urls.yaml文件中的key名，作为文件名，生成唯一的文件名（不会因文件名相同覆盖原文件的数据）
                    let file_name = generate_unique_filename_with_key(key_str.clone(), "output");
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
    if !links_result_set.is_empty() {
        // 将 links_result_set 转换为 Vec<String>
        let mut result_str_vec: Vec<String> = links_result_set.iter().map(|custom_str| custom_str.to_string()).collect();
        result_str_vec.sort();
        // 打开或创建一个文件，如果文件已存在则会被覆盖
        let mut file = File::create("output/links.txt").expect("无法创建文件");
        // 将 Vec 中的数据写入文件
        for item in result_str_vec {
            file.write_all(item.as_bytes()).expect("无法将数据写入文件");
            file.write_all(b"\n").expect("无法向文件写入换行符");
        }
    }
    println!("\n结果输出到{}文件夹了！", save_folder);
    // 等待用户按Enter键退出程序
    wait_for_enter();
}

async fn fetch_url(url: String) -> (String, String) {
    let client = Client::new();
    // 设置超时时间为10秒
    let timeout_duration = Duration::from_secs(10);
    // 发起异步 HTTP 请求
    let response = match time::timeout(timeout_duration, client.get(url.clone()).send()).await {
        Ok(result) => match result {
            Ok(response) => response,
            Err(_err) => {
                println!("URL: {} -> GET请求失败！", url);
                return (url.to_string(), "Error".to_string());
            }
        },
        Err(_timeout_err) => {
            println!("URL: {} -> 请求超时！", url);
            return (url.to_string(), "Timeout".to_string());
        }
    };

    // 检查响应是否成功
    if response.status().is_success() {
        // 获取响应体的字节内容
        let body_bytes = match response.bytes().await {
            Ok(bytes) => bytes,
            Err(_err) => {
                println!("URL: {} -> 获取response的字节内容失败！", url);
                return (url.to_string(), "Error".to_string());
            }
        };
        // 将字节内容转换为字符串
        let mut body = String::from_utf8_lossy(&body_bytes).to_string().replace(r"\n\n", r"\n");
        println!("URL: {} -> 获取response内容成功！", url);
        // 下面提取Github中readme.md文件中的节点（方法一、方法二）

        /* 方法一：正则表达式，匹配第一个反引号中的内容 */
        /* let re = Regex::new(r"```([^`]+)```").unwrap();
        if let Some(captures) = re.captures(&body) {
            if let Some(second_match) = captures.get(1) {
                let matched_content = second_match.as_str();
                body = matched_content.to_string();
            }
        } */

        /* 方法二：find查找字符下标的方法，获取节点内容 */

        // 1、匹配第一个反引号中的内容
        if let Some(start) = body.find("```") {
            if let Some(end) = body[start + 3..].find("```") {
                let content = &body[start + 3..start + 3 + end];
                body = content.to_string();
            }
        }
        // 2、匹配所有的反引号中的内容
        /* let mut start = 0; // 初始化位置变量
        let mut end;
        let mut loop_content = String::new();
        // 循环查找每个"```"
        while let Some(start_index) = body[start..].find("```") {
            start += start_index + 3; // 移动到"```"后面的位置
            // 查找下一个"```"
            if let Some(end_index) = body[start..].find("```") {
                end = start + end_index;
                let content = &body[start..end];
                loop_content.push_str(&*format!("{}\n", content.trim()));
                start = end + 3; // 移动到下一个"```"之后的位置
            } else {
                break; // 如果找不到匹配的"```"，结束循环
            }
        }
        if !loop_content.is_empty() {
            body = loop_content;
        } else {
            body = (&body.trim()).parse().unwrap()
        } */

        // 返回url和body
        (url.to_string(), body)
    } else {
        println!("URL: {} -> response的状态码不是'200'", url);
        (url.to_string(), "Error".to_string())
    }
}

// 能转换为json或yaml的，就为true
fn can_convert_to_json_or_yaml(input: &str) -> bool {
    !base64::decode(input).is_ok() && (
        serde_json::from_str::<serde_json::Value>(input).is_ok() || // 能转换为json吗？
            serde_yaml::from_str::<serde_yaml::Value>(input).is_ok() // 能转换为yaml吗？
    )
}

// 以urls.yaml中的key作为文件名（必要时添加编号）
fn generate_unique_filename_with_key(original_file_name: String, save_folder: &str) -> String {
    let mut count = 1;
    let mut unique_file_name = format!("{}/{}_{}.json", save_folder, original_file_name, count);
    // 检查现有文件名，必要时添加编号
    while Path::new(&unique_file_name).exists() {
        count += 1;
        unique_file_name = format!("{}/{}_{}.json", save_folder, original_file_name, count);
    }

    unique_file_name
}

// 截取url后面的字符当成文件名使用，如果本地存在这个文件就添加编号
fn truncate_url_as_filename(url: &str, save_folder: &str) -> String {
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

// 创建文件夹，创建失败意味存在该文件夹，就清空当前文件夹里面的所有内容
fn create_folder_or_clear_file(dir: &Path) -> io::Result<()> {
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

// 将json中的outbounds中的节点写入指定的json文件中
fn write_outbounds_field_value_to_file(filename: &str, values: HashSet<String>) -> io::Result<()> {
    // 将 HashSet 转换为 Vec<String>
    let values_vec_of_string: Vec<String> = values.into_iter().collect::<Vec<_>>();
    // 首先按照JSON对象的键进行排序，然后递归比较JSON对象的值或数组的元素
    let sorted_json_vec_of_string = sort_json_vec_of_string(values_vec_of_string.clone());
    // 按照JSON中字段相同的排序在一起
    let result_string: String = sorted_json_vec_of_string.join(",\n  ");
    let result = format!("\"outbounds\": [\n  {}\n]", result_string);
    fs::write(filename, result)
}

// 将yaml中的proxies中的节点写入指定的yaml文件中
fn write_proxies_field_value_to_file(filename: &str, values: &HashSet<String>) -> io::Result<()> {
    // 将HashSet元素转换为JSON字符串并打印出来
    let json_strings: Result<Vec<String>, serde_json::Error> = values
        .iter()
        .map(|s| {
            // 解析YAML字符串为YAML值
            let yaml_value: Result<YamlValue, serde_yaml::Error> = serde_yaml::from_str(s);
            let yaml_value = match yaml_value {
                Ok(value) => value,
                Err(e) => {
                    // 打印出错误消息（如果需要的话）
                    eprintln!("Error converting YAML to JSON: {}", e);
                    return Ok("".to_string()); // 返回一个空字符串或根据需要进行处理
                }
            };
            // 将YAML值转换为JSON值
            let json_value: JsonValue = serde_json::to_value(&yaml_value)?;
            // 将JSON值序列化为字符串
            let json_string = serde_json::to_string(&json_value)?; // 压缩成一行，单行显示（使用json数据结构，有花括号）
            // let json_string = serde_json::to_string_pretty(&json_value).unwrap(); // 内容展开，多行显示
            Ok(json_string)
        })
        .collect();
    // 处理JSON序列化错误
    let json_strings = match json_strings {
        Ok(strings) => strings,
        Err(serde_error) => {
            return Err(io::Error::new(io::ErrorKind::Other, serde_error));
        }
    };
    // 【YAML排序】转为JSON数据后按照JSON中字段相同的排序在一起
    let sorted_json_strings = sort_json_vec_of_string(json_strings.clone());
    let yaml_content: String = sorted_json_strings
        .iter()
        .map(|value| format!("  - {}", value))
        .collect::<Vec<_>>()
        .join("\n");
    let result = "proxies:\n".to_owned() + &yaml_content; // 添加"proxies:"作为精简版clash配置文件
    fs::write(filename, result)?;

    Ok(())
}

// 将抓取到的整个json数据写入output/*.json文件中，（json数据中有字段outbounds的使用另外一个函数跟其它配置信息合并在一起，不使用这个函数）
fn write_json_to_file(filename: String, json_value: &JsonValue) -> io::Result<()> {
    // 打开文件进行写入
    let file = File::create(filename)?;
    // 将JSON值写入文件，并进行美化格式化
    to_writer_pretty(file, json_value)?;

    Ok(())
}

// 提取urls.yaml配置文件中的所有url
fn extract_urls_of_yaml(data: &YamlValue) -> Vec<String> {
    let mut values = HashSet::new();
    if let YamlValue::Mapping(mapping) = data {
        for (_key, value) in mapping {
            if let YamlValue::Sequence(seq) = value {
                for v in seq {
                    if let YamlValue::String(s) = v {
                        // 假如地址url链接中有日期，就将url链接中的日期（包括路径中的年、月），替换成昨天的，url链接中没有日期就使用原始的url链接
                        let url_date_with_yesterday = replace_url_date_with_yesterday(s.clone().as_str());
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
fn find_key_as_filename(url_of_string: String, data: &YamlValue) -> Option<String> {
    if let YamlValue::Mapping(mapping) = data {
        for (key, value) in mapping {
            if let YamlValue::Sequence(seq) = value {
                if seq.iter().any(|v| v == &YamlValue::String(url_of_string.to_string())) {
                    if let YamlValue::String(key_str) = key {
                        return Some(key_str.clone());
                    }
                }
            }
        }
    }
    None
}

// 排序vec<String>中的json字符串
fn sort_json_vec_of_string(mut vec_of_string: Vec<String>) -> Vec<String> {
    vec_of_string.sort_by(|a, b| {
        let parsed_a = serde_json::from_str::<JsonValue>(a).unwrap();
        let parsed_b = serde_json::from_str::<JsonValue>(b).unwrap();
        compare_json(&parsed_a, &parsed_b)
    });
    vec_of_string.into_iter().map(|s| s.to_string()).collect()
}

// 比较json字符串：首先按照JSON对象的键进行排序，然后递归比较JSON对象的值或数组的元素
fn compare_json(a: &JsonValue, b: &JsonValue) -> std::cmp::Ordering {
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

// 将地址链接中的日期（包括路径中的年、月），替换成今天的
fn replace_url_date_with_today(url: &str) -> String {
    // 获取当前日期的年份和月份
    let now = Local::now();
    let current_year = now.year().to_string();
    let current_month = now.format("%m").to_string();
    let current_date = now.format("%Y%m%d").to_string();
    // 正则表达式匹配路径中的年、月和日期
    let re = Regex::new(r"(\d{4})/(\d{2})/(\d{4})(\d{2})(\d{2})").unwrap();
    // 对URL应用正则表达式，查找并替换日期部分
    let new_url = re.replace_all(url, |caps: &regex::Captures| {
        // 检查路径中的年份和月份是否与日期部分匹配
        if &caps[1] == &caps[3][0..4] && &caps[2] == &caps[4] {
            let date_str = format!("{}-{}-{}", &caps[3], &caps[4], &caps[5]);
            // 尝试将捕获的数字转换为日期
            if chrono::NaiveDate::parse_from_str(&date_str, "%Y-%m-%d").is_ok() {
                // 替换为当前年份和月份，以及当前日期
                format!("{}/{}/{}", &current_year, &current_month, &current_date)
            } else {
                // 如果日期无效，保持原样
                caps[0].to_string()
            }
        } else {
            // 如果年份和月份不匹配，保持原样
            caps[0].to_string()
        }
    }).into_owned();
    // 处理不包含"年/月"路径的url
    let re_simple = Regex::new(r"(\d{4})(\d{2})(\d{2})").unwrap();
    let new_url = re_simple.replace_all(&new_url, |caps: &regex::Captures| {
        let date_str = format!("{}-{}-{}", &caps[1], &caps[2], &caps[3]);
        if let Ok(date) = chrono::NaiveDate::parse_from_str(&date_str, "%Y-%m-%d") {
            if date != now.date_naive() {
                return now.format("%Y%m%d").to_string();
            }
        }
        caps[0].to_string()
    });

    new_url.into_owned()
}

// 将地址链接中的日期（包括路径中的年、月），替换成昨天的
fn replace_url_date_with_yesterday(url: &str) -> String {
    // 正则表达式匹配带路径的年份、月份和日期或仅日期，以及可能的 .txt/.yaml/.yml 后缀
    let re = Regex::new(r"(?:(\d{4})/(\d{1,2})/)?(\d{4})(\d{2})(\d{2})").unwrap();
    // 符合就替换，不符合就使用原来的链接
    re.replace_all(url, |caps: &regex::Captures| {
        // 检查是否有匹配的年和月，如果没有则使用日期部分
        let path_year = caps.get(1).map_or("", |m| m.as_str());
        let path_month = caps.get(2).map_or("", |m| m.as_str());
        let date_year = &caps[3];
        let date_month = &caps[4];
        // 获取当前日期时间
        let current_date = Local::now();
        // 将当前日期向前推移一天
        let prev_date = current_date - chrono::Duration::days(1);
        // 构造新的日期字符串
        let new_date = format!("{:04}{:02}{:02}", prev_date.year(), prev_date.month(), prev_date.day());

        // 构造新的月份字符串（路径中的月份），1~9月份只有一位呢，还是2位（使用0填充呢？）
        let new_month = if path_month.len() == 1 {
            prev_date.month().to_string()  // 月份只有一位，不填充
        } else {
            format!("{:02}", prev_date.month()) // 填充一个零，使得月份为两位数
        };
        // 根据路径是否有"年/月"来决定如何替换URL
        match (path_year, path_month) {
            // 有的"年/月"的路径，且路径的年、月分别与链接后面8位数字的年、月一样
            (year_match, month_match) if year_match == date_year && month_match == date_month => {
                // 使用 prev_date 的月份
                format!("{}/{}/{}", prev_date.year(), new_month, new_date)
            }
            // 有的"年/月"的路径，且路径的年、月分别与链接后面8位数字的年、月都不一样（其中一个符合，就使用原路径的年、月）
            (year_match, month_match) if year_match != "" || month_match != "" => {
                // 使用 caps.get(1) 和 caps.get(2) 来获取原始值
                format!("{}/{}/{}", caps.get(1).map_or("", |m| m.as_str()), caps.get(2).map_or("", |m| m.as_str()), new_date)
            }
            // 没有路径年月时，就只处理后面8位数字（替换成昨天的时间）
            _ => format!("{}", new_date),
        }
    }).into_owned()
}

/* 辅助函数：等待用户按Enter键退出程序 */
fn wait_for_enter() {
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("无法读取行");
    // 移除输入中的换行符
    let _ = input.trim();
    io::stdout().flush().expect("无法刷新缓冲区");
}

// 【该函数没有使用到】先按照长度排序，然后在长度相同时按照字母顺序排序
fn _sort_json_fields_by_order(json_value: &mut JsonValue) {
    if let Some(obj) = json_value.as_object_mut() {
        let mut sorted_map: BTreeMap<String, JsonValue> = BTreeMap::new();
        // 按照字母顺序和单词长度对键进行排序
        let mut keys: Vec<_> = obj.keys().cloned().collect();
        keys.sort_by(|a, b| {
            a.len().cmp(&b.len()).then_with(|| a.cmp(b))
        });
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
            _sort_json_fields_by_order(value);
        }
    }
}