use regex::Regex;
use std::io::{self, Write};

// 初步判断是否为代理链接
pub fn is_protocol(s: &str) -> bool {
    let re = Regex::new(r"^[a-zA-Z]+://").unwrap();
    re.is_match(s)
}

pub fn wait_for_enter() {
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("无法读取行");
    // 移除输入中的换行符
    let _ = input.trim();
    io::stdout().flush().expect("无法刷新缓冲区");
}

pub fn split_links_vec(vec: Vec<String>, chunk_size: usize) -> Vec<Vec<String>> {
    vec.chunks(chunk_size).map(|chunk| chunk.to_vec()).collect()
}
