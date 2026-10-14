//! Requests from the extension: one frame from a relay connection, decided and answered,
//! queued for the user, or forwarded to the user's node.

use super::origin::valid_method;
use super::policy::take_token;
use super::proxy::proxy_call;
use super::*;
use std::sync::atomic::Ordering;

impl Bridge {
    /// One frame from a relay connection (already past the peer and caller checks).
    pub fn on_message(self: &Arc<Self>, conn: u64, msg: &Value) {
        match msg.get("type").and_then(Value::as_str) {
            Some("hello") => {
                let w = self.lock().conns.get(&conn).map(|c| c.writer.clone());
                if let Some(w) = w {
                    Self::send_to(
                        &w,
                        &json!({"type": "hello", "ok": true, "version": 1, "app": "Phone Vault Companion", "paired": self.paired().is_some()}),
                    );
                }
            }
            Some("request") => self.on_request(conn, msg),
            Some("show_window") => {
                // Extension popup: "Open Phone Vault Companion" (native messaging cannot start an
                // app, but it can ask the running one to come forward). Throttled.
                let now = Instant::now();
                let go = {
                    let mut g = self.lock();
                    let ok = g.last_show_window.is_none_or(|t| now.saturating_duration_since(t) >= SHOW_WINDOW_EVERY);
                    if ok {
                        g.last_show_window = Some(now);
                    }
                    ok
                };
                if go {
                    (self.alerts)(Alert::ShowWindow);
                }
                if let Some(id) = msg.get("id").and_then(Value::as_u64) {
                    self.reply(conn, id, Ok(json!(go)));
                }
            }
            Some("cancel") => {
                let Some(ext_id) = msg.get("id").and_then(Value::as_u64) else { return };
                let removed = {
                    let mut g = self.lock();
                    let gone: Vec<Pending> =
                        g.pending.iter().filter(|p| p.conn == conn && p.ext_id == ext_id).cloned().collect();
                    g.pending.retain(|p| !(p.conn == conn && p.ext_id == ext_id));
                    // A connection request withdrawn before the user answered (tab reload) counts
                    // towards the domain's connection backoff, so a reload loop cannot keep
                    // re-queueing it.
                    let now = Instant::now();
                    for p in gone.iter().filter(|p| p.kind == PendingKind::Connect) {
                        let domain = registrable_domain(&p.origin);
                        let next = Backoff::after_withdrawal(g.backoff.get(&domain).copied(), now);
                        g.backoff.insert(domain, next);
                    }
                    if g.backoff.len() > MAX_SITES {
                        g.backoff.retain(|_, b| b.remaining(now).is_some());
                    }
                    !gone.is_empty()
                };
                if removed {
                    (self.notify)();
                }
            }
            Some("site_status") => {
                // Popup: is this site connected? (origin from the active tab, set by the extension)
                let id = msg.get("id").and_then(Value::as_u64).unwrap_or(0);
                let Ok(origin) =
                    msg.get("origin").and_then(Value::as_str).ok_or(String::new()).and_then(normalize_origin)
                else {
                    return self.reply_err(conn, id, rpc(INVALID_REQUEST, "invalid origin"));
                };
                let paired = self.paired();
                let g = self.lock();
                let site = connected(g.sites.iter().find(|s| s.origin == origin), paired.as_deref()).cloned();
                drop(g);
                self.reply(conn, id, Ok(json!({"paired": paired.is_some(), "connected": site.is_some(), "chain": site.map(|s| s.active)})));
            }
            _ => {}
        }
    }

    fn on_request(self: &Arc<Self>, conn: u64, msg: &Value) {
        let Some(ext_id) = msg.get("id").and_then(Value::as_u64).filter(|i| *i < (1 << 53)) else { return };
        let origin = match msg
            .get("origin")
            .and_then(Value::as_str)
            .ok_or_else(|| "no origin".to_string())
            .and_then(normalize_origin)
        {
            Ok(o) => o,
            Err(e) => return self.reply_err(conn, ext_id, rpc(INVALID_REQUEST, format!("refused origin: {e}"))),
        };
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        if !valid_method(method) {
            return self.reply_err(conn, ext_id, rpc(INVALID_REQUEST, "invalid method name"));
        }
        let params = match msg.get("params") {
            None | Some(Value::Null) => json!([]),
            Some(p) => p.clone(),
        };
        let paired = self.paired();

        let site = {
            let mut g = self.lock();
            let bucket = g.buckets.entry(origin.clone()).or_insert((BUCKET_CAPACITY, Instant::now()));
            if !take_token(bucket, Instant::now()) {
                drop(g);
                return self.reply_err(conn, ext_id, rpc(LIMITED, "Too many requests from this site. Slow down."));
            }
            if g.buckets.len() > 4 * MAX_SITES {
                let keep = origin.clone();
                g.buckets.retain(|k, _| *k == keep);
            }
            g.sites.iter().find(|s| s.origin == origin).cloned()
        };

        match decide(method, &params, site.as_ref(), paired.as_deref()) {
            Decision::Answer(v) => self.reply(conn, ext_id, Ok(v)),
            Decision::Error(e) => self.reply_err(conn, ext_id, e),
            Decision::Revoke => {
                self.revoke(&origin);
                self.reply(conn, ext_id, Ok(Value::Null));
            }
            Decision::SwitchNow { chain } => {
                let _ = self.update_site(&origin, None, Some(chain));
                self.reply(conn, ext_id, Ok(Value::Null));
            }
            d @ (Decision::Connect | Decision::Prompt { .. }) => {
                let (kind, chain) = match d {
                    Decision::Prompt { chain } => (PendingKind::Request, chain),
                    _ => (PendingKind::Connect, DEFAULT_CHAIN),
                };
                // A sign-in (EIP-4361) message for another site than this one is refused here,
                // before any card: the origin is the browser's, so a mismatch is phishing.
                if method == "personal_sign" {
                    if let Some(text) =
                        paired.as_deref().and_then(|p| wc::personal_sign_params(&params, p).ok()).and_then(|(_, t)| t)
                    {
                        if let crate::siwe::Check::Mismatch { domain, site } = crate::siwe::check(&text, Some(&origin))
                        {
                            let message = crate::siwe::blocked_message(&site, &domain);
                            let show = {
                                let mut g = self.lock();
                                let now = Instant::now();
                                let due = g
                                    .blocked_shown
                                    .get(&origin)
                                    .is_none_or(|t| now.saturating_duration_since(*t) >= BLOCKED_NOTICE_EVERY);
                                if due {
                                    g.blocked_shown.insert(origin.clone(), now);
                                }
                                if g.blocked_shown.len() > MAX_SITES {
                                    g.blocked_shown
                                        .retain(|_, t| now.saturating_duration_since(*t) < BLOCKED_NOTICE_EVERY);
                                }
                                due
                            };
                            if show {
                                (self.alerts)(Alert::Blocked { origin: origin.clone(), message: message.clone() });
                            }
                            return self.reply_err(conn, ext_id, rpc(wc::UNAUTHORIZED, message));
                        }
                    }
                }
                let domain = registrable_domain(&origin);
                let mut g = self.lock();
                if kind == PendingKind::Connect {
                    let now = Instant::now();
                    if let Some((left, withdrawn)) =
                        g.backoff.get(&domain).and_then(|b| Some((b.remaining(now)?, b.withdrawn)))
                    {
                        drop(g);
                        let secs = left.as_secs().max(1);
                        return self.reply_err(conn, ext_id, rpc(USER_REJECTED, if withdrawn {
                            format!("A connection request from {domain} was withdrawn before you answered it in Phone Vault. Try again in {secs} s.")
                        } else {
                            format!("You rejected a connection from {domain} in Phone Vault. Try again in {secs} s.")
                        }));
                    }
                }
                if kind == PendingKind::Connect
                    && g.pending.iter().any(|p| p.origin == origin && p.kind == PendingKind::Connect)
                {
                    drop(g);
                    return self.reply_err(
                        conn,
                        ext_id,
                        rpc(ALREADY_PENDING, "A connection request from this site is already waiting in Phone Vault."),
                    );
                }
                if g.pending.iter().filter(|p| p.origin == origin).count() >= MAX_PENDING_PER_ORIGIN
                    || g.pending.iter().filter(|p| registrable_domain(&p.origin) == domain).count()
                        >= MAX_PENDING_PER_DOMAIN
                    || g.pending.len() >= MAX_PENDING_TOTAL
                {
                    drop(g);
                    return self.reply_err(
                        conn,
                        ext_id,
                        rpc(LIMITED, "Too many requests are waiting in Phone Vault. Answer or reject them first."),
                    );
                }
                let id = self.next_id.fetch_add(1, Ordering::SeqCst);
                g.pending.push(Pending {
                    id,
                    conn,
                    ext_id,
                    origin: origin.clone(),
                    method: method.to_string(),
                    params,
                    chain,
                    kind,
                    created: now_secs(),
                });
                let writer = g.conns.get(&conn).map(|c| c.writer.clone());
                // Window + notification at most once per QUEUED_ALERT_EVERY per site family (the
                // request still waits in the app's list either way).
                let now = Instant::now();
                let alert = g
                    .queued_alerted
                    .get(&domain)
                    .is_none_or(|t| now.saturating_duration_since(*t) >= QUEUED_ALERT_EVERY);
                if alert {
                    g.queued_alerted.insert(domain.clone(), now);
                }
                if g.queued_alerted.len() > MAX_SITES {
                    g.queued_alerted.retain(|_, t| now.saturating_duration_since(*t) < QUEUED_ALERT_EVERY);
                }
                drop(g);
                // Tell the extension this one waits for the user (badge), and bring the app forward.
                if let Some(w) = writer {
                    Self::send_to(&w, &json!({"type": "queued", "id": ext_id}));
                }
                (self.notify)();
                if alert {
                    (self.alerts)(Alert::Queued {
                        origin: origin.clone(),
                        connect: kind == PendingKind::Connect,
                        method: method.to_string(),
                    });
                }
            }
            Decision::Proxy { chain } => {
                let url = self.lock().nodes.get(&chain).cloned();
                let Some(url) = url else {
                    return self.reply_err(
                        conn,
                        ext_id,
                        rpc(
                            wc::CHAIN_DISCONNECTED,
                            format!("No node is set for {} in Phone Vault.", wc::chain_name(chain)),
                        ),
                    );
                };
                if self.proxies.fetch_add(1, Ordering::SeqCst) >= MAX_PROXY_INFLIGHT {
                    self.proxies.fetch_sub(1, Ordering::SeqCst);
                    return self.reply_err(conn, ext_id, rpc(LIMITED, "Too many node requests in flight. Try again."));
                }
                let me = self.clone();
                let method = method.to_string();
                std::thread::spawn(move || {
                    let known = me.lock().node_chain.get(&url).copied();
                    let out = proxy_call(&url, chain, known, &method, &params);
                    if let Ok((_, Some(c))) = &out {
                        me.lock().node_chain.insert(url.clone(), *c);
                    }
                    me.proxies.fetch_sub(1, Ordering::SeqCst);
                    me.reply(conn, ext_id, out.map(|(v, _)| v));
                });
            }
        }
    }
}
