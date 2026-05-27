use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use axum::routing::post;
use axum::Router;
use registry_platform_httpsec::{body_limit_problem_response, request_body_limit, CorsPolicy};
use tower::ServiceExt;

/// P4 baseline: a router mounted with the standard 1 MiB limit must reject
/// a body of 1 MiB + 1 byte with PAYLOAD_TOO_LARGE, and `body_limit_problem_response`
/// must produce the full RFC 7807 shape (type, title, status, detail).
///
/// `RequestBodyLimitLayer` limits the body stream; the 413 is produced by the
/// handler when it reads past the cap, so the test handler explicitly reads the body.
#[tokio::test]
async fn body_limit_baseline_rejects_oversized_body_and_problem_response_has_full_shape() {
    let app = Router::new()
        .route(
            "/",
            post(|body: Body| async move {
                match to_bytes(body, usize::MAX).await {
                    Ok(_) => StatusCode::OK,
                    Err(_) => StatusCode::PAYLOAD_TOO_LARGE,
                }
            }),
        )
        .layer(request_body_limit(1_048_576));

    let large_body = vec![b'x'; 1_048_577];
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/")
                .body(Body::from(large_body))
                .expect("request builds"),
        )
        .await
        .expect("app responds");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let problem = body_limit_problem_response(Request::new(Body::empty())).await;
    assert_eq!(problem.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let bytes = to_bytes(problem.into_body(), 4096)
        .await
        .expect("problem body reads");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("problem body is JSON");
    assert_eq!(
        body["type"],
        "https://registry-platform.dev/problems/request/body-too-large"
    );
    assert_eq!(body["title"], "Payload Too Large");
    assert_eq!(body["status"], 413);
    assert_eq!(body["detail"], "request body exceeds the configured limit");
}

/// F-httpsec-2: a request carrying a non-allowlisted Origin must NOT receive
/// an Access-Control-Allow-Origin header in the response.
#[tokio::test]
async fn cors_layer_omits_acao_header_for_non_listed_origin() {
    let app = Router::new()
        .route("/", post(|| async { StatusCode::OK }))
        .layer(
            CorsPolicy {
                allowed_origins: vec!["https://app.example.test".to_string()],
                allowed_methods: vec![Method::GET, Method::POST, Method::OPTIONS],
                allowed_headers: Vec::new(),
                allow_credentials: false,
            }
            .layer(),
        );

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/")
                .header(header::ORIGIN, "https://attacker.example.test")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("app responds");

    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none(),
        "non-listed origin must not receive Access-Control-Allow-Origin"
    );
}
