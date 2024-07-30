use std::hash::{Hash, Hasher};
use std::{fmt, rc::Rc};

/*
下面的struct和impl的作用，只有(明文)节点链接中开头到#之间的字符串相同，
就进行hashset去重，不是按照整行节点链接相同才去重的
*/
#[derive(Debug, Eq, PartialEq, Hash)]
pub struct CustomString {
    pub inner: Rc<str>,
}

impl CustomString {
    pub fn new(inner: &str) -> Self {
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
pub struct UrlJsonPair {
    pub url: String,
    pub json_data: String,
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
