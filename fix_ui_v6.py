import re
import os

def fix_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    # Fix Request chains
    # .json(&req).send().await
    # to
    # .json(&req).map_err(|e| e.to_string())?.send().await
    # or just unwrap if we are in a context that allows it.

    content = content.replace('.json(&req).send().await', '.json(&req).unwrap().send().await')
    content = content.replace('.json(&login_req).send().await', '.json(&login_req).unwrap().send().await')

    # Add type annotations to match res
    content = content.replace('match response {', 'match response: std::result::Result<gloo_net::http::Response, gloo_net::Error> {')

    with open(filepath, 'w') as f:
        f.write(content)

# Apply
for root, dirs, files in os.walk('crates/ui/src/pages'):
    for file in files:
        if file.endswith('.rs'):
            fix_file(os.path.join(root, file))
