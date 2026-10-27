//! Public Windows coding playground shell. Only its native APIs and owned UI assets are exposed.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use quixi_engine::QuixiEngine;
use std::{
    borrow::Cow,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    window::WindowBuilder,
};
use wry::{
    http::{header::CONTENT_TYPE, Response},
    WebContext, WebViewBuilder,
};

fn resources_dir() -> anyhow::Result<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("QUIXI_RESOURCES_DIR") {
        candidates.push(PathBuf::from(path));
    }
    if let Some(parent) = std::env::current_exe()?.parent() {
        candidates.push(parent.join("resources"));
        candidates.push(parent.join("../../resources"));
    }
    candidates.push(std::env::current_dir()?.join("resources"));
    candidates.into_iter().find(|p| p.join("playground/index.html").is_file())
        .ok_or_else(|| anyhow::anyhow!("Missing resources/playground/index.html. Extract the whole release ZIP before launching."))
}

fn response(status: u16, content_type: &str, bytes: Vec<u8>) -> Response<Cow<'static, [u8]>> {
    Response::builder().status(status).header(CONTENT_TYPE, content_type)
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-src 'none'")
        .body(Cow::Owned(bytes)).expect("constant HTTP headers are valid")
}

fn static_asset(root: &Path, path: &str) -> Response<Cow<'static, [u8]>> {
    let (file, mime) = match path {
        "/" | "/playground" | "/playground/" => {
            ("playground/index.html", "text/html; charset=utf-8")
        }
        "/playground/app.js" => ("playground/app.js", "text/javascript; charset=utf-8"),
        "/playground/reconstruction.js" => (
            "playground/reconstruction.js",
            "text/javascript; charset=utf-8",
        ),
        "/playground/style.css" => ("playground/style.css", "text/css; charset=utf-8"),
        "/quixi-mark.svg" => ("quixi-mark.svg", "image/svg+xml"),
        _ => return response(404, "text/plain", b"Not found".to_vec()),
    };
    match fs::read(root.join(file)) {
        Ok(bytes) => response(200, mime, bytes),
        Err(_) => response(
            500,
            "text/plain",
            b"An application resource is missing. Extract a fresh release.".to_vec(),
        ),
    }
}

fn local_url(url: &str) -> bool {
    url::Url::parse(url)
        .map(|u| {
            (u.scheme() == "app" && u.host_str() == Some("localhost"))
                || (u.scheme() == "http" && u.host_str() == Some("app.localhost"))
        })
        .unwrap_or(false)
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();
    if std::env::args().any(|arg| arg == "--version" || arg == "-v") {
        println!("QuixiDesk Windows {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let resources = resources_dir()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let _runtime_guard = runtime.enter();
    let engine = QuixiEngine::new(resources.clone());
    let event_loop = EventLoopBuilder::<()>::new().build();
    let window = WindowBuilder::new()
        .with_title("QuixiDesk · Coding & REA")
        .with_inner_size(LogicalSize::new(1440.0, 920.0))
        .with_min_inner_size(LogicalSize::new(480.0, 360.0))
        .with_visible(false)
        .build(&event_loop)?;
    let webview_data = dirs::data_local_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("QuixiDesk/WebView");
    fs::create_dir_all(&webview_data)?;
    let mut context = WebContext::new(Some(webview_data));
    let api_engine = Arc::clone(&engine);
    let webview = WebViewBuilder::with_web_context(&mut context)
        .with_background_color((16, 18, 20, 255))
        .with_clipboard(true)
        .with_devtools(
            cfg!(debug_assertions) || std::env::var("QUIXI_DEVTOOLS").as_deref() == Ok("1"),
        )
        .with_navigation_handler(|url| {
            if local_url(&url) {
                return true;
            }
            if url::Url::parse(&url)
                .map(|u| matches!(u.scheme(), "https" | "http"))
                .unwrap_or(false)
            {
                let _ = quixi_platform::open_external(&url);
            }
            false
        })
        .with_new_window_req_handler(|url| {
            if url::Url::parse(&url)
                .map(|u| matches!(u.scheme(), "https" | "http"))
                .unwrap_or(false)
            {
                let _ = quixi_platform::open_external(&url);
            }
            false
        })
        .with_asynchronous_custom_protocol("app".into(), move |_id, request, responder| {
            let engine = Arc::clone(&api_engine);
            let root = resources.clone();
            std::thread::spawn(move || {
                let reply = (|| {
                    if let Some(origin) = request.headers().get("origin") {
                        if !matches!(
                            origin.to_str(),
                            Ok("app://localhost" | "http://app.localhost")
                        ) {
                            return response(
                                403,
                                "text/plain",
                                b"External origins cannot access native APIs".to_vec(),
                            );
                        }
                    }
                    let method = request.method().as_str();
                    let path = request.uri().path();
                    if !matches!(method, "GET" | "POST") {
                        return response(405, "text/plain", b"Method not allowed".to_vec());
                    }
                    if request.body().len() > 16 * 1024 * 1024 {
                        return response(413, "text/plain", b"Request too large".to_vec());
                    }
                    if path.starts_with("/api/quixi/playground/")
                        || path.starts_with("/api/quixi/providers/")
                    {
                        let query = request
                            .uri()
                            .path_and_query()
                            .map(|q| q.as_str())
                            .unwrap_or(path);
                        let (status, content_type, body) =
                            engine.handle_api_request(method, query, request.body());
                        return response(status, &content_type, body);
                    }
                    if method != "GET" {
                        return response(405, "text/plain", b"Method not allowed".to_vec());
                    }
                    static_asset(&root, path)
                })();
                responder.respond(reply);
            });
        })
        .with_url("app://localhost/playground")
        .build(&window)?;
    window.set_visible(true);
    event_loop.run(move |event, _, control_flow| {
        let _keep_webview_alive = &webview;
        *control_flow = ControlFlow::Wait;
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            engine.rea.shutdown();
            *control_flow = ControlFlow::Exit;
        }
    });
}
