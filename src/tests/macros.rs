macro_rules! request {
    ($app:ident, $method:tt, $uri:expr) => {
        tower::Service::call(
            ServiceExt::<Request<Body>>::ready(&mut $app).await.unwrap(),
            Request::builder()
                .uri($uri)
                .method(http::Method::$method)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    };
    ($app:ident, $method:tt, $uri:expr, $body:expr) => {
        tower::Service::call(
            ServiceExt::<Request<Body>>::ready(&mut $app).await.unwrap(),
            Request::builder()
                .uri($uri)
                .method(http::Method::$method)
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(serde_json::to_vec(&$body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
    };
}

macro_rules! request_auth {
    ($app:expr, $method:tt, $uri:expr, $token:expr) => {
        tower::Service::call(
            ServiceExt::<Request<Body>>::ready(&mut $app).await.unwrap(),
            Request::builder()
                .uri($uri)
                .method(http::Method::$method)
                .header("authorization", "Bearer ".to_owned() + &$token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    };
    ($app:expr, $method:tt, $uri:expr, $token:expr, $body:expr) => {
        tower::Service::call(
            ServiceExt::<Request<Body>>::ready(&mut $app).await.unwrap(),
            Request::builder()
                .uri($uri)
                .method(http::Method::$method)
                .header(http::header::CONTENT_TYPE, "application/json")
                .header("authorization", "Bearer ".to_owned() + &$token)
                .body(Body::from(serde_json::to_vec(&$body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
    };
}

macro_rules! oneshot_request {
    ($method:tt, $uri:expr) => {
        create_test_router()
            .oneshot(
                Request::builder()
                    .uri($uri)
                    .method(Method::$method)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    };
    ($method:tt, $uri:expr, $body:expr) => {
        create_test_router()
            .oneshot(
                Request::builder()
                    .uri($uri)
                    .method(http::Method::$method)
                    .body(Body::from(serde_json::to_vec(&$body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    };
}

macro_rules! oneshot_request_auth {
    ($app:expr, $method:tt, $uri:expr, $token:expr) => {
        create_test_router()
            .oneshot(
                Request::builder()
                    .uri($uri)
                    .method(http::Method::$method)
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .header("authorization", "Bearer ".to_owned() + &$token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    };
    ($app:expr, $method:tt, $uri:expr, $token:expr, $body:expr) => {
        create_test_router()
            .oneshot(
                Request::builder()
                    .uri($uri)
                    .method(http::Method::$method)
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .header("authorization", "Bearer ".to_owned() + &$token)
                    .body(Body::from(serde_json::to_vec(&$body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    };
}

pub(crate) use request;
pub(crate) use request_auth;
