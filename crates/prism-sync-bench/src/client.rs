use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use reqwest::Client;
use serde_json::Value;
use std::time::Instant;

use crate::relay;
use crate::stats::{OpType, Stats};

pub struct SimulatedClient {
    pub sync_id: String,
    pub device_id: String,
    pub signing_key: SigningKey,
    pub token: Option<String>,
    pub last_server_seq: i64,
    pub epoch: i64,
}

impl SimulatedClient {
    pub fn new(sync_id: String) -> Self {
        Self {
            sync_id,
            device_id: relay::generate_device_id(),
            signing_key: SigningKey::generate(&mut OsRng),
            token: None,
            last_server_seq: 0,
            epoch: 0,
        }
    }

    pub async fn register(&mut self, http: &Client, base_url: &str, stats: &Stats) -> Result<()> {
        let start = Instant::now();
        match relay::register_device(
            http,
            base_url,
            &self.sync_id,
            &self.device_id,
            &self.signing_key,
        )
        .await
        {
            Ok(token) => {
                self.token = Some(token);
                stats.record(OpType::Register, start.elapsed());
                Ok(())
            }
            Err(e) => {
                stats.record_error(OpType::Register);
                Err(e)
            }
        }
    }

    fn token(&self) -> Result<&str> {
        self.token
            .as_deref()
            .ok_or_else(|| anyhow!("not registered"))
    }

    pub async fn push(&self, http: &Client, base_url: &str, stats: &Stats) -> Result<i64> {
        let token = self.token()?;
        let batch_id = uuid::Uuid::new_v4().to_string();
        let envelope =
            relay::make_test_envelope(&self.sync_id, &self.device_id, &batch_id, self.epoch);

        let start = Instant::now();
        let resp = http
            .put(format!("{base_url}/v1/sync/{}/changes", self.sync_id))
            .bearer_auth(token)
            .header("X-Device-Id", &self.device_id)
            .header("X-Batch-Id", &batch_id)
            .header("X-Epoch", self.epoch.to_string())
            .json(&envelope)
            .send()
            .await?;

        if !resp.status().is_success() {
            stats.record_error(OpType::Push);
            return Err(anyhow!("push failed: {}", resp.status()));
        }

        let body: Value = resp.json().await?;
        let server_seq = body["server_seq"].as_i64().unwrap_or(0);
        stats.record(OpType::Push, start.elapsed());
        Ok(server_seq)
    }

    pub async fn pull(&mut self, http: &Client, base_url: &str, stats: &Stats) -> Result<i64> {
        let token = self.token()?;

        let start = Instant::now();
        let resp = http
            .get(format!(
                "{base_url}/v1/sync/{}/changes?since={}&limit=100",
                self.sync_id, self.last_server_seq
            ))
            .bearer_auth(token)
            .header("X-Device-Id", &self.device_id)
            .send()
            .await?;

        if !resp.status().is_success() {
            stats.record_error(OpType::Pull);
            return Err(anyhow!("pull failed: {}", resp.status()));
        }

        let body: Value = resp.json().await?;
        let max_seq = body["max_server_seq"]
            .as_i64()
            .unwrap_or(self.last_server_seq);
        if max_seq > self.last_server_seq {
            self.last_server_seq = max_seq;
        }
        stats.record(OpType::Pull, start.elapsed());
        Ok(max_seq)
    }

    pub async fn ack(
        &self,
        http: &Client,
        base_url: &str,
        server_seq: i64,
        stats: &Stats,
    ) -> Result<()> {
        let token = self.token()?;

        let start = Instant::now();
        let resp = http
            .post(format!("{base_url}/v1/sync/{}/ack", self.sync_id))
            .bearer_auth(token)
            .header("X-Device-Id", &self.device_id)
            .json(&serde_json::json!({ "server_seq": server_seq }))
            .send()
            .await?;

        if !resp.status().is_success() {
            stats.record_error(OpType::Ack);
            return Err(anyhow!("ack failed: {}", resp.status()));
        }

        stats.record(OpType::Ack, start.elapsed());
        Ok(())
    }

    pub async fn ws_connect(
        &self,
        base_url: &str,
        stats: &Stats,
    ) -> Result<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    > {
        let token = self.token()?;
        let ws_url = base_url
            .replacen("http://", "ws://", 1)
            .replacen("https://", "wss://", 1);
        let url = format!("{ws_url}/v1/sync/{}/ws", self.sync_id);

        let start = Instant::now();
        let (mut ws, _) = tokio_tungstenite::connect_async(&url)
            .await
            .map_err(|e| anyhow!("ws connect failed: {e}"))?;

        // Send auth message
        use futures::SinkExt;
        use tokio_tungstenite::tungstenite::Message;
        let auth_msg = serde_json::json!({
            "type": "auth",
            "device_id": self.device_id,
            "token": token,
        });
        ws.send(Message::Text(auth_msg.to_string())).await?;

        // Wait for auth_ok
        use futures::StreamExt;
        let timeout = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next()).await;
        match timeout {
            Ok(Some(Ok(Message::Text(text)))) => {
                let json: Value = serde_json::from_str(&text)?;
                if json["type"].as_str() != Some("auth_ok") {
                    stats.record_error(OpType::WsConnect);
                    return Err(anyhow!("ws auth failed: {text}"));
                }
            }
            _ => {
                stats.record_error(OpType::WsConnect);
                return Err(anyhow!("ws auth timeout or error"));
            }
        }

        stats.record(OpType::WsConnect, start.elapsed());
        Ok(ws)
    }
}
