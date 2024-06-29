use ipnetwork::IpNetwork;
use reqwest::Client;
use std::io::Result;
use std::net::IpAddr;
use worker::*;

include!(concat!(env!("OUT_DIR"), "/prefixes.rs"));

pub async fn is_cloudflare(domain: &str) -> Result<bool> {
    if let Ok(ip) = domain.parse::<IpAddr>() {
        console_debug!("{} is ip", domain);
        Ok(is_ip_cloudflare(ip))
    } else {
        match Client::new()
            .get(format!("https://1.1.1.1/dns-query?name={}&type=A", domain))
            .header("Accept", "application/dns-json")
            .send()
            .await
        {
            Ok(resp) => {
                let text = resp.text().await.unwrap();
                let json: serde_json::Value = serde_json::from_str(&text)?;
                let ip = json["Answer"][0]["data"].as_str().unwrap();
                console_debug!("ip resolved: {}", ip);
                Ok(is_ip_cloudflare(ip.parse().unwrap()))
            }
            Err(err) => {
                console_debug!("dns query {} error: {}", domain, err.to_string());
                Ok(false)
            }
        }
    }
}

fn is_ip_cloudflare(ip: IpAddr) -> bool {
    PREFIXES.iter().any(|prefix| {
        if let Ok(prefix) = prefix.parse::<IpNetwork>() {
            prefix.contains(ip)
        } else {
            false
        }
    })
}
