import re
import os

def fix_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    # Match common patterns in UI and fix them
    # Pattern: Request::post(...).json(...).send().await
    # Since Request::post(...).json(...) returns Result<RequestBuilder, Error> in gloo-net 0.7
    # We need to unwrap the result of .json() before .send()

    content = content.replace('.json(&req).send().await', '.json(&req).unwrap().send().await')
    content = content.replace('.json(&login_req).send().await', '.json(&login_req).unwrap().send().await')
    content = content.replace('.json(&req).await', '.json(&req).unwrap().await') # Should not happen usually

    with open(filepath, 'w') as f:
        f.write(content)

# Apply
for root, dirs, files in os.walk('crates/ui/src/pages'):
    for file in files:
        if file.endswith('.rs'):
            fix_file(os.path.join(root, file))
