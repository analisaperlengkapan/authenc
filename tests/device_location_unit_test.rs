use authenc::services::device::DeviceLocation;
use serde_json::json;

#[test]
fn test_device_location_deserialization() {
    let json_data = json!({
        "country": "US",
        "region": "CA",
        "city": "San Francisco",
        "latitude": 37.7749,
        "longitude": -122.4194
    });

    let location: DeviceLocation = serde_json::from_value(json_data).expect("Failed to deserialize");

    assert_eq!(location.country, Some("US".to_string()));
    assert_eq!(location.region, Some("CA".to_string()));
    assert_eq!(location.city, Some("San Francisco".to_string()));
    assert_eq!(location.latitude, Some(37.7749));
    assert_eq!(location.longitude, Some(-122.4194));
}

#[test]
fn test_device_location_deserialization_partial() {
    let json_data = json!({
        "country": "UK",
        "city": "London"
    });

    let location: DeviceLocation = serde_json::from_value(json_data).expect("Failed to deserialize");

    assert_eq!(location.country, Some("UK".to_string()));
    assert!(location.region.is_none());
    assert_eq!(location.city, Some("London".to_string()));
    assert!(location.latitude.is_none());
    assert!(location.longitude.is_none());
}
