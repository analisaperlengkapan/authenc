    // Query events
    let params = authenc::database::operations::QueryEventLogParams {
        realm_id,
        event_category: None,
        event_type: None,
        resource_type: None,
        resource_id: None,
        user_id: None,
        from_date: None,
        to_date: None,
        success_only: None,
        offset: 0,
        limit: 10,
    };
    let events = authenc::database::operations::events::query_event_log(&db, params)
        .await
        .expect("Failed to query events");

    assert!(events.len() >= 5);

    // Query with category filter
    let filtered_params = authenc::database::operations::QueryEventLogParams {
        realm_id,
        event_category: Some("AUTH".to_string()),
        event_type: None,
        resource_type: None,
        resource_id: None,
        user_id: None,
        from_date: None,
        to_date: None,
        success_only: None,
        offset: 0,
        limit: 10,
    };
    let filtered_events = authenc::database::operations::events::query_event_log(&db, filtered_params)
