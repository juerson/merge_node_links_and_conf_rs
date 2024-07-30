use crate::Regex;

// 提取字符串中，protocols不同协议开头的链接
pub fn extract_links(s: &str, protocols: &[&str]) -> Vec<String> {
    let protocol_regex = build_regex(protocols);
    let re = Regex::new(&protocol_regex).unwrap();
    let mut links = Vec::new();
    let mut last_end = 0;
    for mat in re.find_iter(s) {
        let start = mat.start();
        let end = mat.end();
        if start > last_end {
            links.push(&s[last_end..start]);
        }
        links.push(&s[start..end]);
        last_end = end;
    }
    if last_end < s.len() {
        links.push(&s[last_end..]);
    }
    let merged_links: Vec<String> = links.chunks(2).map(|chunk| chunk.join("")).collect();
    merged_links
}

// 该代码动态生成一个正则表达式模式，可匹配以protocols切片中指定的不同协议开头的链接。
fn build_regex(protocols: &[&str]) -> String {
    let mut regex = String::from("(?i)(?:"); // 使用(?i)标志来忽略字符串的大小写
    for (index, protocol) in protocols.iter().enumerate() {
        if index != 0 {
            regex.push('|');
        }
        let mut modified_protocol = protocol.to_string();
        if protocol.contains("+") {
            modified_protocol = modified_protocol.replace("+", r"\+"); // 处理协议中可能存在的特殊字符
        }
        regex.push_str(&format!("{}://", modified_protocol));
    }
    regex.push_str(r#"[\w.-]+)"#); // 匹配链接的剩余部分

    regex
}
