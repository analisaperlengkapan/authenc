import re
import os

def fix_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    # Match LocalResource::new(source, |arg| async move { ... })
    pattern = r'LocalResource::new\(\s*(.*?),\s*\|(.*?)\|\s*async move \{(.*?)\}\s*\)'

    def replacer(match):
        source = match.group(1).strip()
        arg = match.group(2).strip()
        body = match.group(3).strip()
        if source == "|| ()" or source == "||()":
             return f'LocalResource::new(move || async move {{ {body} }})'
        else:
             return f'LocalResource::new(move || {{ let {arg} = {source}(); async move {{ {body} }} }})'

    new_content = re.sub(pattern, replacer, content, flags=re.DOTALL)

    if new_content != content:
        with open(filepath, 'w') as f:
            f.write(new_content)

for root, dirs, files in os.walk('crates/ui/src'):
    for file in files:
        if file.endswith('.rs'):
            fix_file(os.path.join(root, file))
