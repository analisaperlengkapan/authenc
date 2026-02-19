use leptos::*;

#[component]
pub fn Users() -> impl IntoView {
    view! {
        <div class="users-page">
            <div class="header-actions" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 style="margin: 0;">"Users"</h2>
                <button style="background: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold;">
                    <i class="fas fa-plus" style="margin-right: 5px;"></i> "Create User"
                </button>
            </div>

            <div class="table-container" style="background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden;">
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="background: #f8f9fa; border-bottom: 1px solid #dee2e6;">
                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Username"</th>
                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Email"</th>
                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Status"</th>
                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Actions"</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr style="border-bottom: 1px solid #dee2e6;">
                            <td style="padding: 15px;">"admin"</td>
                            <td style="padding: 15px;">"admin@authenc.dev"</td>
                            <td style="padding: 15px;">
                                <span style="background: #d4edda; color: #155724; padding: 5px 10px; border-radius: 20px; font-size: 0.85em; font-weight: 500;">"Enabled"</span>
                            </td>
                            <td style="padding: 15px;">
                                <button style="margin-right: 8px; padding: 6px 12px; border: 1px solid #dee2e6; background: white; border-radius: 4px; cursor: pointer; color: #495057;">
                                    <i class="fas fa-edit"></i> " Edit"
                                </button>
                                <button style="padding: 6px 12px; border: 1px solid #dc3545; background: white; border-radius: 4px; cursor: pointer; color: #dc3545;">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </td>
                        </tr>
                        <tr style="border-bottom: 1px solid #dee2e6;">
                            <td style="padding: 15px;">"jdoe"</td>
                            <td style="padding: 15px;">"john.doe@example.com"</td>
                            <td style="padding: 15px;">
                                <span style="background: #d4edda; color: #155724; padding: 5px 10px; border-radius: 20px; font-size: 0.85em; font-weight: 500;">"Enabled"</span>
                            </td>
                            <td style="padding: 15px;">
                                <button style="margin-right: 8px; padding: 6px 12px; border: 1px solid #dee2e6; background: white; border-radius: 4px; cursor: pointer; color: #495057;">
                                    <i class="fas fa-edit"></i> " Edit"
                                </button>
                                <button style="padding: 6px 12px; border: 1px solid #dc3545; background: white; border-radius: 4px; cursor: pointer; color: #dc3545;">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    }
}
