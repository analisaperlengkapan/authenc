import re
import os

def fix_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    # 1. Fix LocalResource::new(source, fetcher) -> LocalResource::new(move || { let s = source(); ... })
    # This matches the pattern I see in error logs.
    pattern = r'LocalResource::new\(\s*(.*?),\s*\|(.*?)\|\s*async move \{(.*?)\}\s*\)'
    def resource_replacer(match):
        source = match.group(1).strip()
        arg = match.group(2).strip()
        body = match.group(3).strip()
        if source == "|| ()":
            return f'LocalResource::new(move || async move {{ {body} }})'
        else:
            return f'LocalResource::new(move || {{ let {arg} = {source}(); async move {{ {body} }} }})'

    content = re.sub(pattern, resource_replacer, content, flags=re.DOTALL)

    # 2. Fix Action dispatching inside on:click
    # Find on:click=move |_| action.dispatch(()) and wrap in { ... }
    content = re.sub(r'on:click=move \|_\| (.*?)action\.dispatch\(\(\)\)', r'on:click=move |_| { \1action.dispatch(()); }', content)

    # 3. Ensure match arms in .map() have explicit types for Result if they fail
    # We'll just target the known ones for now or do a generic replacement if safe.
    content = content.replace('.map(|res| match res {', '.map(|res: Result<_, String>| match res {')
    content = content.replace('.map(move |res| match res {', '.map(move |res: Result<_, String>| match res {')

    # 4. Unify match arm types with .into_any()
    # If a match has view! { ... } in one arm and view! { ... } in another,
    # and they aren't the same type, we need .into_any() on both.
    # My previous attempt at this was a bit broad.

    with open(filepath, 'w') as f:
        f.write(content)

# Apply to all files in crates/ui/src
for root, dirs, files in os.walk('crates/ui/src'):
    for file in files:
        if file.endswith('.rs'):
            fix_file(os.path.join(root, file))
