mod utils;

use base64::decode;
use regex::Regex;
use serde_yaml::Value as YamlValue;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, BufReader, Write},
    path::Path,
    rc::Rc,
};
use utils::{
    common::{
        is_protocol,    // 初步判断是否为代理链接
        wait_for_enter, // 等待用户输入回车键
    },
    custom_struct::{CustomString, UrlJsonPair}, // 自定义结构体
    data_process::{
        is_clash_data_insert_clash_set, // 判断是否为clash数据，如果是，就插入clash_set中
        is_json_data_insert_json_set,   // 判断是否为json数据，如果是，就插入json_set中
        is_liks_data_insert_links_set,  // 判断是否为liks数据，如果是，就插入links_set中
    },
    files::{
        create_folder_or_clear_file, // 创建文件夹或清空文件夹中的所有内容
        write_failed_urls_to_file,   // 将失败的URL写入文件
        write_to_file,               // 将内容写入文件
    },
    links::extract_links, // 从字符串中(网页中)提取是各大代理协议的链接，比如：ss://、ssr://、vless://等等
    network::fetch,       // 抓取网页的内容
    yaml::{
        can_convert_to_json_or_yaml, // 检查是否可以转为json或yaml
        extract_urls_of_yaml,        // 提取urls.yaml中的所有链接
        DataFormat,                  // 自定义的数据格式(是yaml、json、base64、其他格式的数据？)
    },
};

#[tokio::main]
async fn main() {
    let urls_config_file = "urls.yaml";

    // 读取 YAML 文件
    let file = File::open(urls_config_file).expect("Failed to open file");
    let reader = BufReader::new(file);
    // 解析 YAML 文件为 serde_yaml::Value
    let urls_config_yamlvalue: YamlValue =
        serde_yaml::from_reader(reader).expect("Failed to parse YAML");

    let github_proxy: String = match urls_config_yamlvalue.get("GithubProxy") {
        Some(value) => match value.as_str() {
            Some(value_str) => value_str
                .trim_start_matches("https://")
                .trim_end_matches("/")
                .to_string(),
            None => "".to_string(),
        },
        None => "".to_string(),
    };

    // 提取所有的值url
    let urls = extract_urls_of_yaml(&urls_config_yamlvalue);
    let output_folder = "output";

    /* 创建output文件夹，如果output文件夹已经存在，就删除里面存在的所有文件夹和文件 */
    create_folder_or_clear_file(Path::new(output_folder)).expect("创建文件或删除文件!");

    let tasks = urls
        .into_iter()
        .filter(|url| url != &github_proxy) // 剔除GitHub的代理地址
        .map(|url| tokio::spawn(fetch(url, github_proxy.clone())))
        .collect::<Vec<_>>();

    let mut failed_urls: Vec<String> = Vec::new();

    /* 用Rc和RefCell包装HashSet成Rc<RefCell<?>>的作用，让HashSet<String>在整个程序的生命周期内有效地共享和修改它。 */
    // links集合
    let links_prefix_set: Rc<RefCell<HashSet<String>>> = Rc::new(RefCell::new(HashSet::new()));
    let links_set: Rc<RefCell<HashSet<CustomString>>> = Rc::new(RefCell::new(HashSet::new()));
    // json集合
    let json_set: Rc<RefCell<HashSet<UrlJsonPair>>> = Rc::new(RefCell::new(HashSet::new()));
    let singbox_json_set: Rc<RefCell<HashSet<String>>> = Rc::new(RefCell::new(HashSet::new()));
    let xray_json_set: Rc<RefCell<HashSet<String>>> = Rc::new(RefCell::new(HashSet::new()));

    // clash集合
    let clash_name_field_set: Rc<RefCell<HashMap<String, String>>> =
        Rc::new(RefCell::new(HashMap::new()));
    let clash_set: Rc<RefCell<HashSet<String>>> = Rc::new(RefCell::new(HashSet::new()));

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

    for task in tasks {
        match task.await {
            Ok((url, body)) => {
                // 获取失败的URL
                if body == "Error" {
                    failed_urls.push(url.clone());
                }

                match can_convert_to_json_or_yaml(&body) {
                    DataFormat::Json => {
                        println!("- - - - - - - - - - - - - - - - - - - - - - - - - - - - 正在处理 json 数据...");
                        is_json_data_insert_json_set(
                            body,
                            url,
                            &json_set,
                            &singbox_json_set,
                            &xray_json_set,
                        )
                    }
                    DataFormat::Yaml => {
                        println!("- - - - - - - - - - - - - - - - - - - - - - - - - - - - 正在处理 yaml 数据...");
                        is_clash_data_insert_clash_set(body, &clash_name_field_set, &clash_set)
                    }
                    DataFormat::Base64 => {
                        println!("- - - - - - - - - - - - - - - - - - - - - - - - - - - - 正在处理Base64的v2ray链接...");
                        body.lines()
                            .filter(|line| !line.trim().is_empty()) // 过滤掉空行
                            .for_each(|line| {
                                if let Ok(decoded) = decode(line) {
                                    let decoded_str = String::from_utf8_lossy(&decoded);
                                    // base64解密后，存放到一个向量中（含多个代理链接）
                                    let base64_str_li: Vec<&str> = decoded_str.lines().collect();
                                    base64_str_li.iter().for_each(|base64_str| {
                                        let base64_trim = base64_str.trim();
                                        if !base64_trim.is_empty() && is_protocol(base64_trim) {
                                            let protocol_urls =
                                                extract_links(base64_trim, &protocols);
                                            protocol_urls.iter().for_each(|protocol_url| {
                                                is_liks_data_insert_links_set(
                                                    protocol_url.clone(),
                                                    &links_set,
                                                    &links_prefix_set,
                                                    protocols.clone(),
                                                );
                                            });
                                        }
                                    });
                                }
                            });
                    }
                    DataFormat::Other => {
                        println!("- - - - - - - - - - - - - - - - - - - - - - - - - - - - 正在处理明文的v2ray链接...");
                        body.lines()
                            .filter(|line| !line.trim().is_empty()) // 过滤掉空行
                            .for_each(|line| {
                                let protocol_urls: Vec<String> = extract_links(line, &protocols);
                                protocol_urls.iter().for_each(|protocol_url| {
                                    is_liks_data_insert_links_set(
                                        protocol_url.clone(),
                                        &links_set,
                                        &links_prefix_set,
                                        protocols.clone(),
                                    );
                                });
                            });
                    }
                }
            }
            Err(error) => eprintln!("Task failed: {:?}", error), // tokio::spawn失败
        }
    }

    // ---------------------------------- 写入文件 ----------------------------------

    write_to_file(
        singbox_json_set.borrow(),
        xray_json_set.borrow(),
        json_set.borrow(),
        clash_set.borrow(),
        links_set.borrow(),
        &urls_config_yamlvalue,
        output_folder,
    );

    write_failed_urls_to_file(failed_urls);

    // ------------------------------- 输出提示信息 ----------------------------------
    print!("\n程序运行结束，最终结果输出到{}文件夹中！", output_folder);
    io::stdout().flush().unwrap(); // 强制刷新标准输出缓冲区
    wait_for_enter(); // 等待用户按Enter键退出程序
}
