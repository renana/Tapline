use serde_json::{json, Value};

use crate::log::{Entry, Store};

const PROTOCOL: &str = "2025-03-26";
const SERVER: &str = "tapline";
const VERSION: &str = "0.1.0";

pub fn handle(method: &str, raw: &str, store: &Store) -> (u16, Vec<u8>, &'static str, Option<String>) {
    if method == "OPTIONS" {
        return (204, Vec::new(), "text/plain", None);
    }
    if method == "GET" {
        let body = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\",\"data\":\"tapline mcp ready\"}}\n\n";
        return (200, body.to_vec(), "text/event-stream", Some(session_id()));
    }
    if method != "POST" {
        return (
            405,
            br#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"POST JSON-RPC to /mcp"}}"#.to_vec(),
            "application/json",
            None,
        );
    }
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").trim_end_matches('\0');
    let parsed: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            return rpc_err(Value::Null, -32700, "parse error");
        }
    };
    if parsed.get("id").is_none() {
        // notification — accepted, no body
        return (202, Vec::new(), "application/json", None);
    }
    let id = parsed.get("id").cloned().unwrap_or(Value::Null);
    let rpc_method = parsed.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = parsed.get("params").cloned().unwrap_or(json!({}));
    match rpc_method {
        "initialize" => rpc_ok(
            id,
            json!({
                "protocolVersion": PROTOCOL,
                "capabilities": { "tools": { "listChanged": false }, "resources": { "listChanged": false } },
                "serverInfo": { "name": SERVER, "version": VERSION },
                "instructions": "Tapline sidecar: query recent TCP/UDP/HTTPS hops. Secrets in headers are redacted."
            }),
            Some(session_id()),
        ),
        "ping" => rpc_ok(id, json!({}), None),
        "tools/list" => rpc_ok(id, json!({ "tools": tools() }), None),
        "tools/call" => {
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            match call_tool(name, &args, store) {
                Ok(v) => rpc_ok(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": v.to_string() }],
                        "structuredContent": v,
                        "isError": false
                    }),
                    None,
                ),
                Err(msg) => rpc_ok(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": msg }],
                        "isError": true
                    }),
                    None,
                ),
            }
        }
        "resources/list" => rpc_ok(
            id,
            json!({
                "resources": [
                    { "uri": "tapline://stats", "name": "stats", "mimeType": "application/json", "description": "Live hop counters" },
                    { "uri": "tapline://hops", "name": "hops", "mimeType": "application/json", "description": "Recent hop summaries" }
                ]
            }),
            None,
        ),
        "resources/read" => {
            let uri = params.get("uri").and_then(|u| u.as_str()).unwrap_or("");
            let text = match uri {
                "tapline://stats" => serde_json::to_string_pretty(&store.stats()).unwrap_or_else(|_| "{}".into()),
                "tapline://hops" => {
                    serde_json::to_string_pretty(&store.query(None, None, None, None, 50)).unwrap_or_else(|_| "[]".into())
                }
                other if other.starts_with("tapline://hops/") => {
                    let hid = other.trim_start_matches("tapline://hops/");
                    match store.by_id(hid) {
                        Some(e) => serde_json::to_string_pretty(&redact(e)).unwrap_or_else(|_| "{}".into()),
                        None => "null".into(),
                    }
                }
                _ => return rpc_err(id, -32602, "unknown resource"),
            };
            rpc_ok(
                id,
                json!({
                    "contents": [{ "uri": uri, "mimeType": "application/json", "text": text }]
                }),
                None,
            )
        }
        "prompts/list" => rpc_ok(id, json!({ "prompts": [] }), None),
        _ => rpc_err(id, -32601, "method not found"),
    }
}

fn tools() -> Vec<Value> {
    vec![
        tool(
            "tapline_stats",
            "Live Tapline counters: totals, bytes, p50/p95, RPS.",
            json!({ "type": "object", "properties": {} }),
        ),
        tool(
            "tapline_list_hops",
            "List recent hops. Includes dlpDetectors / dlpBlocked. Filter protocol=mcp for MCP calls.",
            json!({
                "type": "object",
                "properties": {
                    "protocol": { "type": "string", "description": "tcp|udp|http1|h2|grpc|tls|dns|quic|mcp|websocket" },
                    "direction": { "type": "string", "description": "inbound|outbound" },
                    "instance": { "type": "string" },
                    "q": { "type": "string", "description": "substring on path, method, client, SNI, orig-dst" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 400 }
                }
            }),
        ),
        tool(
            "tapline_get_hop",
            "Full hop by id (headers redacted: cookie, authorization, set-cookie).",
            json!({
                "type": "object",
                "required": ["id"],
                "properties": { "id": { "type": "string" } }
            }),
        ),
        tool(
            "tapline_protocols",
            "Count hops by protocol in the in-memory ring.",
            json!({ "type": "object", "properties": {} }),
        ),
    ]
}

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({ "name": name, "description": description, "inputSchema": input_schema })
}

fn call_tool(name: &str, args: &Value, store: &Store) -> Result<Value, String> {
    match name {
        "tapline_stats" => Ok(serde_json::to_value(store.stats()).unwrap_or(json!({}))),
        "tapline_list_hops" => {
            let protocol = args.get("protocol").and_then(|v| v.as_str());
            let direction = args.get("direction").and_then(|v| v.as_str());
            let instance = args.get("instance").and_then(|v| v.as_str());
            let q = args.get("q").and_then(|v| v.as_str());
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
            Ok(json!(store.query(protocol, direction, instance, q, limit)))
        }
        "tapline_get_hop" => {
            let id = args.get("id").and_then(|v| v.as_str()).ok_or("missing id")?;
            store
                .by_id(id)
                .map(|e| serde_json::to_value(redact(e)).unwrap_or(json!({})))
                .ok_or_else(|| format!("hop {id} not found"))
        }
        "tapline_protocols" => {
            let mut counts = serde_json::Map::new();
            for s in store.summaries() {
                let n = counts.get(&s.protocol).and_then(|v| v.as_u64()).unwrap_or(0);
                counts.insert(s.protocol, json!(n + 1));
            }
            Ok(Value::Object(counts))
        }
        _ => Err(format!("unknown tool {name}")),
    }
}

fn rpc_ok(id: Value, result: Value, session: Option<String>) -> (u16, Vec<u8>, &'static str, Option<String>) {
    let body = json!({ "jsonrpc": "2.0", "id": id, "result": result });
    (
        200,
        serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
        "application/json",
        session,
    )
}

fn rpc_err(id: Value, code: i32, message: &str) -> (u16, Vec<u8>, &'static str, Option<String>) {
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    });
    (
        200,
        serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
        "application/json",
        None,
    )
}

fn session_id() -> String {
    format!("tl-{:x}", crate::log::now_ms())
}

fn redact(mut e: Entry) -> Entry {
    for h in e
        .request_headers
        .iter_mut()
        .chain(e.response_headers.iter_mut())
    {
        if secret_header(&h.name) {
            h.value = "[redacted]".into();
        }
    }
    e.request_body = None;
    e.response_body = None;
    e
}

fn secret_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "cookie"
            | "set-cookie"
            | "authorization"
            | "proxy-authorization"
            | "x-api-key"
            | "x-auth-token"
            | "authentication"
    )
}
