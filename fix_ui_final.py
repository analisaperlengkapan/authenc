import os
import re

def refactor_ui(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    # Imports
    content = content.replace('leptos::*', 'leptos::prelude::*')
    content = content.replace('use leptos::{', 'use leptos::prelude::{')

    # Primitives
    content = content.replace('create_signal(', 'signal(')
    content = content.replace('create_action(|', 'Action::new_local(|')

    # Resource - one argument in 0.8
    content = re.sub(r'create_resource\(([^,]+),\s*([^)]+)\)', r'LocalResource::new(\2)', content)

    # Callback run
    content = content.replace('.call(())', '.run(())')
    content = content.replace('.call(', '.run(')

    # Navigation
    content = content.replace('navigate("/', '(use_navigate())("/')

    # match arms AnyView
    # This is harder with regex but let's try to add .into_any() to common patterns
    content = content.replace('}.into_view()', '}.into_any()')

    with open(filepath, 'w') as f:
        f.write(content)

for root, dirs, files in os.walk('crates/ui/src'):
    for file in files:
        if file.endswith('.rs'):
            refactor_ui(os.path.join(root, file))
