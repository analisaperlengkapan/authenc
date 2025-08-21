#[cfg(test)]
mod tests {
    use actix_web::{test, App};
    use authence::api;
    use authence::services::{user_store::UserStore, realm_store::RealmStore};

    #[actix_web::test]
    async fn test_health() {
        let app = test::init_service(App::new().route("/health", actix_web::web::get().to(|| async { "OK" }))).await;
        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_create_realm() {
        let realm_store = actix_web::web::Data::new(RealmStore::new());
        let app = test::init_service(
            App::new()
                .app_data(realm_store.clone())
                .service(api::create_realm)
        ).await;
        let req = test::TestRequest::post()
            .uri("/realms")
            .set_json(&serde_json::json!({"name": "testrealm"}))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);
    }
}
