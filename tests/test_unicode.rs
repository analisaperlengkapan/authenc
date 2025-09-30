fn main() {
    let s1 = "straße";
    let s2 = "strasse";
    let s3 = "STRASSE";
    let s4 = "Straße";

    println!("'{}' to_lowercase: '{}'", s1, s1.to_lowercase());
    println!("'{}' to_lowercase: '{}'", s2, s2.to_lowercase());
    println!("'{}' to_lowercase: '{}'", s3, s3.to_lowercase());
    println!("'{}' to_lowercase: '{}'", s4, s4.to_lowercase());

    println!(
        "'strasse789' contains 'straße'.to_lowercase(): {}",
        "strasse789"
            .to_lowercase()
            .contains(&"straße".to_lowercase())
    );
    println!("'straße'.to_lowercase(): '{}'", "straße".to_lowercase());
    println!(
        "'strasse789'.to_lowercase(): '{}'",
        "strasse789".to_lowercase()
    );
}
