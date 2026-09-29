///|
fn main {
  let payload = "{\"user\": {\"name\": \"Ada\", \"email\": \"ada@example.com\"}, \"auth\": {\"password\": \"hunter2\", \"token\": \"ghp_1234567890abcdefghij\"}, \"ips\": [\"10.0.0.7\", \"192.168.0.2\"], \"port\": 5432, \"ok\": true}"
  let result = @scrub.redact_json(payload)
  println(result.text)
  println("parsed=" + result.parsed.to_string())
  println("changed-fields=" + result.changed_fields.to_string())
  for path in result.paths() {
    println("finding at " + path)
  }
}
