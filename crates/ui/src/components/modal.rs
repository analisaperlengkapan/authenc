use leptos::*;

#[component]
pub fn Modal(
    #[prop(into)] title: String,
    children: ChildrenFn,
    #[prop(into)] is_open: Signal<bool>,
    #[prop(into)] on_close: Callback<()>,
) -> impl IntoView {
    view! {
        <Show when=move || is_open.get() fallback=|| ()>
            <div
                style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: flex; justify-content: center; align-items: center; z-index: 1000;"
                on:click=move |_| on_close.call(())
            >
                <div
                    style="background: white; padding: 20px; border-radius: 8px; min-width: 400px; max-width: 90%; box-shadow: 0 4px 6px rgba(0,0,0,0.1);"
                    on:click=move |e| e.stop_propagation()
                >
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid #eee; padding-bottom: 10px;">
                        <h3 style="margin: 0;">{title.clone()}</h3>
                        <button
                            style="background: none; border: none; font-size: 1.5rem; cursor: pointer; color: #666;"
                            on:click=move |_| on_close.call(())
                        >
                            "×"
                        </button>
                    </div>
                    <div>
                        {children()}
                    </div>
                </div>
            </div>
        </Show>
    }
}
