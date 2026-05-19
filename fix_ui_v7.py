import re
import os

def fix_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    # Correct match syntax
    content = content.replace('match response: std::result::Result<gloo_net::http::Response, gloo_net::Error> {', 'let response: std::result::Result<gloo_net::http::Response, gloo_net::Error> = response; match response {')

    with open(filepath, 'w') as f:
        f.write(content)

# Apply
for root, dirs, files in os.walk('crates/ui/src/pages'):
    for file in files:
        if file.endswith('.rs'):
            fix_file(os.path.join(root, file))
