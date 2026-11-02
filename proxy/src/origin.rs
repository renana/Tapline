use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub async fn run(addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(err) = handle(stream).await {
                eprintln!("origin: {err}");
            }
        });
    }
}

async fn handle(mut stream: TcpStream) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    let mut buf = vec![0u8; 16_384];
    let n = match tokio::time::timeout(Duration::from_millis(400), stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };
    if n == 0 {
        return Ok(());
    }
    let head = &buf[..n];
    if head.starts_with(b"GET ")
        || head.starts_with(b"POST ")
        || head.starts_with(b"PUT ")
        || head.starts_with(b"PATCH ")
        || head.starts_with(b"DELETE ")
        || head.starts_with(b"HEAD ")
        || head.starts_with(b"OPTIONS ")
    {
        return http(stream, head).await;
    }
    stream.write_all(head).await?;
    let (mut reader, mut writer) = stream.split();
    let _ = tokio::io::copy(&mut reader, &mut writer).await;
    Ok(())
}

async fn http(mut stream: TcpStream, head: &[u8]) -> std::io::Result<()> {
    let start_line = head.split(|&b| b == b'\n').next().unwrap_or(head);
    let start = String::from_utf8_lossy(start_line);
    let mut parts = start.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let target = parts.next().unwrap_or("/").trim_end_matches('\r').to_string();
    let path = target.split('?').next().unwrap_or("/").to_string();

    if path == "/slow" {
        tokio::time::sleep(Duration::from_millis(40)).await;
    }

    let (status, body) = match (method.as_str(), path.as_str()) {
        ("GET", "/") | ("GET", "/health") => {
            (200, r#"{"ok":true,"service":"envoy-standin"}"#.to_string())
        }
        ("GET", "/users") => (
            200,
            r#"[{"id":1,"name":"Ada Lovelace"},{"id":2,"name":"Alan Turing"}]"#.to_string(),
        ),
        ("GET", "/users/2") => (200, r#"{"id":2,"name":"Alan Turing"}"#.to_string()),
        ("POST", "/users") => (201, r#"{"id":3,"created":true}"#.to_string()),
        ("GET", "/error") => (500, r#"{"error":"origin_fault"}"#.to_string()),
        ("GET", "/status/401") => (401, r#"{"status":401}"#.to_string()),
        ("GET", "/headers") => (200, r#"{"via":"tapline"}"#.to_string()),
        _ => (404, format!(r#"{{"error":"not_found","path":"{}"}}"#, path)),
    };

    let reason = match status {
        201 => "Created",
        401 => "Unauthorized",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes()).await
}
