use reqwest::Client;
use std::time::Duration;
use tokio::time;

pub async fn fetch(url: String, proxy_address: String) -> (String, String) {
    let proxy_url = if url.starts_with("https://raw.githubusercontent.com/")
        || url.starts_with("https://github.com/") // 针对类似https://github.com/2dust/v2rayN/blob/master/README.md
        || url.starts_with("https://www.github.com/")
    {
        format!("https://{}/{}", proxy_address, url)
    } else {
        url.clone()
    };
    let client = Client::new();
    // 设置超时时间为10秒
    let timeout_duration = Duration::from_secs(10);
    // 发起异步 HTTP 请求
    let response = match time::timeout(timeout_duration, client.get(&proxy_url).send()).await {
        Ok(result) => match result {
            Ok(response) => response,
            Err(_err) => {
                println!("URL: {} -> GET请求失败！", proxy_url.clone());
                return (url.to_string(), "Error".to_string());
            }
        },
        Err(_timeout_err) => {
            println!("URL: {} -> 请求超时！", proxy_url.clone());
            return (url.to_string(), "Timeout".to_string());
        }
    };

    // 检查响应是否成功
    if response.status().is_success() {
        // 获取响应体的字节内容
        let body_bytes = match response.bytes().await {
            Ok(bytes) => bytes,
            Err(_err) => {
                println!("URL: {} -> 获取response的字节内容失败！", proxy_url.clone());
                return (url.to_string(), "Error".to_string());
            }
        };
        // 将字节内容转换为字符串
        let mut body = String::from_utf8_lossy(&body_bytes)
            .to_string()
            .replace(r"\n\n", r"\n");
        println!("URL: {} -> 获取response内容成功！", proxy_url.clone());
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
        println!("URL: {} -> response的状态码不是'200'", proxy_url.clone());
        (url.to_string(), "Error".to_string())
    }
}
