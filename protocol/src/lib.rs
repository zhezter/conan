pub fn greet(name: &str) -> String {
    let mut greet = "Hello ".to_string();
    greet.push_str(name);
    greet
}
