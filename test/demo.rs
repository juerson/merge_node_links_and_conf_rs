use chrono::Datelike;
use chrono::Local;
use regex::Regex;

fn main() {
    let urls = vec![
        "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/sub/2303/230321.txt",
        "https://clashgithub.com/wp-content/uploads/rss/20230206.txt",
        "https://nodefree.org/dy/2023/2/20230214.txt",
        "https://v2rayshare.com/wp-content/uploads/2023/03/20230324.txt",
        "https://raw.githubusercontent.com/telegeam/blog1/main/a/2023/2/20230206.txt",
        "https://raw.githubusercontent.com/aiboboxx/clashfree/main/clash.yml",
        "https://nodeshare.org/wp-content/uploads/2022/01/0114.txt",
    ];
    for url in urls {
        let s1 = replace_url_date_with_today(url);
        println!("{}", s1);
    }
}

#[allow(dead_code)]
fn replace_url_date_with_today(url: &str) -> String {
    let now = Local::now();
    let current_year = now.year().to_string();
    let current_year_short = now.format("%y").to_string();
    let current_month = now.format("%m").to_string();
    let current_month_single_digit = now.format("%-m").to_string(); // 获取单位的月份
    let current_date = now.format("%Y%m%d").to_string();
    let current_date_short = now.format("%y%m%d").to_string();
    // 匹配"2023/2/20230206"和"2023/02/20230214"这种情况
    let re = Regex::new(r"\b(\d{4})\b/\b(\d{1,2})\b/\b(\d{4})(\d{2})(\d{2})\b").unwrap();
    let new_url = re
        .replace_all(url, |caps: &regex::Captures| {
            if &caps[1] == &caps[3][0..4]
                && format!("{:02}", &caps[2].parse::<i32>().unwrap()) == &caps[4]
            {
                let date_str = format!("{}-{}-{}", &caps[3], &caps[4], &caps[5]);
                if chrono::NaiveDate::parse_from_str(&date_str, "%Y-%m-%d").is_ok() {
                    let current_month_to_use = if caps[2].len() == 1 {
                        &current_month_single_digit
                    } else {
                        &current_month
                    };
                    format!(
                        "{}/{}/{}",
                        &current_year, current_month_to_use, &current_date
                    )
                } else {
                    caps[0].to_string()
                }
            } else {
                caps[0].to_string()
            }
        })
        .into_owned();
    // 匹配链接中只有"20230206"日期的情况
    let re_simple = Regex::new(r"\b(\d{4})(\d{2})(\d{2})\b").unwrap();
    let new_url = re_simple.replace_all(&new_url, |caps: &regex::Captures| {
        let date_str = format!("{}-{}-{}", &caps[1], &caps[2], &caps[3]);
        if let Ok(date) = chrono::NaiveDate::parse_from_str(&date_str, "%Y-%m-%d") {
            if date != now.date_naive() {
                return now.format("%Y%m%d").to_string();
            }
        }
        caps[0].to_string()
    });
    // 匹配"2301/230119"这种两位年份的情况
    let re_sub = Regex::new(r"\b(\d{4})\b/\b(\d{6})\b").unwrap();
    let new_url = re_sub.replace_all(&new_url, |caps: &regex::Captures| {
        let date_str = format!("{}{}", &caps[2][0..2], &caps[2][2..6]);
        if chrono::NaiveDate::parse_from_str(&date_str, "%y%m%d").is_ok()
            && (&caps[1] == &caps[2][0..4])
        {
            format!(
                "{}{}/{}",
                &current_year_short, &current_month, &current_date_short
            )
        } else {
            format!("{}/{}", caps[1].to_string(), &current_date)
        }
    });
    // 匹配"2022/01/0114"这种情况
    let re_txt = Regex::new(r"\b(\d{4})\b/\b(\d{2})\b/\b(\d{2})(\d{2})\b").unwrap();
    let new_url = re_txt.replace_all(&new_url, |caps: &regex::Captures| {
        let date_str = format!("{}-{}-{}", &caps[1], &caps[2], &caps[4]);
        if chrono::NaiveDate::parse_from_str(&date_str, "%Y-%m-%d").is_ok() {
            let current_day = now.format("%d").to_string();
            format!(
                "{}/{}/{}{}",
                &current_year, &current_month, &current_month, &current_day
            )
        } else {
            caps[0].to_string()
        }
    });

    new_url.into_owned()
}

#[allow(dead_code)]
// 将地址链接中的日期（包括路径中的年、月），替换成昨天的
fn replace_url_date_with_yesterday(url: &str) -> String {
    let yesterday = Local::now() - chrono::Duration::days(1);
    let prev_year = yesterday.year().to_string();
    let prev_year_short = yesterday.format("%y").to_string();
    let prev_month = yesterday.format("%m").to_string();
    let prev_month_single_digit = yesterday.format("%-m").to_string();
    let prev_date = yesterday.format("%Y%m%d").to_string();
    let prev_date_short = yesterday.format("%y%m%d").to_string();

    let re = Regex::new(r"\b(\d{4})\b/\b(\d{1,2})\b/\b(\d{4})(\d{2})(\d{2})\b").unwrap();
    let new_url = re
        .replace_all(url, |caps: &regex::Captures| {
            let date_str = format!("{}-{}-{}", &caps[3], &caps[4], &caps[5]);
            if chrono::NaiveDate::parse_from_str(&date_str, "%Y-%m-%d").is_ok()
                && &caps[1] == &caps[3][0..4]
                && format!("{:02}", &caps[2].parse::<i32>().unwrap()) == &caps[4]
            {
                let prev_month_to_use = if caps[2].len() == 1 {
                    &prev_month_single_digit
                } else {
                    &prev_month
                };
                format!("{}/{}/{}", &prev_year, prev_month_to_use, &prev_date)
            } else {
                caps[0].to_string()
            }
        })
        .into_owned();

    let re_simple = Regex::new(r"\b(\d{4})(\d{2})(\d{2})\b").unwrap();
    let new_url = re_simple.replace_all(&new_url, |caps: &regex::Captures| {
        let date_str = format!("{}-{}-{}", &caps[1], &caps[2], &caps[3]);
        if chrono::NaiveDate::parse_from_str(&date_str, "%Y-%m-%d").is_ok() {
            if let Ok(date) = chrono::NaiveDate::parse_from_str(&date_str, "%Y-%m-%d") {
                if date != yesterday.naive_local().into() {
                    return yesterday.format("%Y%m%d").to_string();
                }
            }
        }
        caps[0].to_string()
    });

    let re_sub = Regex::new(r"\b(\d{4})\b/\b(\d{6})\b").unwrap();
    let new_url = re_sub.replace_all(&new_url, |caps: &regex::Captures| {
        let date_str = format!("{}{}", &caps[2][0..2], &caps[2][2..6]);
        if chrono::NaiveDate::parse_from_str(&date_str, "%y%m%d").is_ok()
            && &caps[1] == &caps[2][0..4]
        {
            format!("{}{}/{}", &prev_year_short, &prev_month, &prev_date_short)
        } else {
            format!("{}/{}", caps[1].to_string(), &prev_date_short)
        }
    });

    let re_txt = Regex::new(r"\b(\d{4})\b/\b(\d{2})\b/\b(\d{2})(\d{2})\b").unwrap();
    let new_url = re_txt.replace_all(&new_url, |caps: &regex::Captures| {
        let date_str = format!("{}-{}-{}", &caps[1], &caps[2], &caps[4]);
        if chrono::NaiveDate::parse_from_str(&date_str, "%Y-%m-%d").is_ok() {
            let prev_day = yesterday.format("%d").to_string();
            format!(
                "{}/{}/{}{}",
                &prev_year, &prev_month, &prev_month, &prev_day
            )
        } else {
            caps[0].to_string()
        }
    });
    new_url.into_owned()
}
