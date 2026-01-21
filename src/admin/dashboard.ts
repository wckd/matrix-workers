// Admin Dashboard HTML

export const adminDashboardHtml = (serverName: string) => `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Matrix-PQC Admin - ${serverName}</title>
  <style>
    :root {
      --primary: #0d9488;
      --primary-dark: #0f766e;
      --bg: #0f172a;
      --bg-card: #1e293b;
      --bg-hover: #334155;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --border: #334155;
      --danger: #ef4444;
      --success: #22c55e;
      --warning: #f59e0b;

      /* Glassmorphism */
      --glass-bg: rgba(30, 41, 59, 0.7);
      --glass-bg-light: rgba(30, 41, 59, 0.5);
      --glass-border: rgba(148, 163, 184, 0.1);
      --glass-blur: 12px;
      --glass-blur-heavy: 20px;

      /* Gradients */
      --gradient-primary: linear-gradient(135deg, #0d9488 0%, #0f766e 100%);
      --gradient-surface: linear-gradient(180deg, rgba(30, 41, 59, 0.9) 0%, rgba(15, 23, 42, 0.9) 100%);

      /* Shadows */
      --shadow-sm: 0 2px 8px rgba(0, 0, 0, 0.3);
      --shadow-md: 0 4px 16px rgba(0, 0, 0, 0.4);
      --shadow-lg: 0 8px 32px rgba(0, 0, 0, 0.5);
      --shadow-glow: 0 0 20px rgba(13, 148, 136, 0.2);

      /* Transitions */
      --transition-fast: 150ms ease;
      --transition-normal: 250ms ease;
      --transition-slow: 400ms ease;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      background-image:
        radial-gradient(ellipse at 20% 20%, rgba(13, 148, 136, 0.08) 0%, transparent 50%),
        radial-gradient(ellipse at 80% 80%, rgba(13, 148, 136, 0.05) 0%, transparent 50%),
        radial-gradient(ellipse at 50% 50%, rgba(30, 41, 59, 0.5) 0%, transparent 70%);
      background-attachment: fixed;
    }

    .login-container {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 20px;
    }

    .login-box {
      background: var(--glass-bg);
      backdrop-filter: blur(var(--glass-blur-heavy));
      -webkit-backdrop-filter: blur(var(--glass-blur-heavy));
      border-radius: 16px;
      padding: 40px;
      width: 100%;
      max-width: 400px;
      border: 1px solid var(--glass-border);
      box-shadow: var(--shadow-lg), var(--shadow-glow);
      position: relative;
      overflow: hidden;
    }

    .login-box::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 1px;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
    }

    .login-box h1 {
      text-align: center;
      margin-bottom: 30px;
      font-size: 24px;
    }

    .login-box .logo {
      text-align: center;
      font-size: 48px;
      margin-bottom: 20px;
    }

    .app-container {
      display: none;
    }

    .sidebar {
      position: fixed;
      left: 0;
      top: 0;
      bottom: 0;
      width: 260px;
      background: var(--glass-bg);
      backdrop-filter: blur(var(--glass-blur-heavy));
      -webkit-backdrop-filter: blur(var(--glass-blur-heavy));
      border-right: 1px solid var(--glass-border);
      padding: 24px 0;
      display: flex;
      flex-direction: column;
      box-shadow: var(--shadow-lg);
    }

    .sidebar-header {
      padding: 0 20px 20px;
      border-bottom: 1px solid var(--border);
    }

    .sidebar-header h1 {
      font-size: 20px;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .sidebar-header .server-name {
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 5px;
    }

    .nav-menu {
      padding: 20px 0;
      flex: 1;
      overflow-y: auto;
    }

    .nav-item {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 14px 24px;
      color: var(--text-muted);
      text-decoration: none;
      cursor: pointer;
      transition: all var(--transition-fast);
      border-left: 3px solid transparent;
      margin: 2px 0;
      position: relative;
    }

    .nav-item:hover {
      background: rgba(255, 255, 255, 0.05);
      color: var(--text);
    }

    .nav-item.active {
      background: rgba(13, 148, 136, 0.1);
      color: var(--text);
      border-left-color: var(--primary);
    }

    .nav-item svg {
      width: 20px;
      height: 20px;
      opacity: 0.7;
      transition: opacity var(--transition-fast);
      flex-shrink: 0;
      stroke: currentColor;
    }

    .nav-item:hover svg,
    .nav-item.active svg {
      opacity: 1;
    }

    .nav-item .badge-count {
      margin-left: auto;
      background: var(--danger);
      color: white;
      font-size: 10px;
      padding: 2px 6px;
      border-radius: 10px;
    }

    .main-content {
      margin-left: 260px;
      padding: 30px;
    }

    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 30px;
      flex-wrap: wrap;
      gap: 15px;
    }

    .header h2 {
      font-size: 24px;
    }

    .header-actions {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }

    .btn {
      padding: 10px 20px;
      border-radius: 10px;
      border: none;
      cursor: pointer;
      font-size: 14px;
      font-weight: 500;
      transition: all var(--transition-fast);
      display: inline-flex;
      align-items: center;
      gap: 8px;
      position: relative;
      overflow: hidden;
    }

    .btn::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: linear-gradient(180deg, rgba(255,255,255,0.1) 0%, transparent 50%);
      opacity: 0;
      transition: opacity var(--transition-fast);
    }

    .btn:hover::before {
      opacity: 1;
    }

    .btn:active {
      transform: scale(0.98);
    }

    .btn-primary {
      background: var(--gradient-primary);
      color: white;
      box-shadow: 0 2px 8px rgba(13, 148, 136, 0.3);
    }

    .btn-primary:hover {
      box-shadow: 0 4px 16px rgba(13, 148, 136, 0.4);
      transform: translateY(-1px);
    }

    .btn-primary:active {
      transform: translateY(0) scale(0.98);
    }

    .btn-danger {
      background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
      color: white;
      box-shadow: 0 2px 8px rgba(239, 68, 68, 0.3);
    }

    .btn-danger:hover {
      box-shadow: 0 4px 16px rgba(239, 68, 68, 0.4);
      transform: translateY(-1px);
    }

    .btn-secondary {
      background: rgba(255, 255, 255, 0.05);
      color: var(--text);
      border: 1px solid var(--glass-border);
      backdrop-filter: blur(8px);
    }

    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.1);
      border-color: rgba(255, 255, 255, 0.15);
    }

    .btn-warning {
      background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
      color: black;
      box-shadow: 0 2px 8px rgba(245, 158, 11, 0.3);
    }

    .btn-warning:hover {
      box-shadow: 0 4px 16px rgba(245, 158, 11, 0.4);
      transform: translateY(-1px);
    }

    .btn-success {
      background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
      color: white;
      box-shadow: 0 2px 8px rgba(34, 197, 94, 0.3);
    }

    .btn-success:hover {
      box-shadow: 0 4px 16px rgba(34, 197, 94, 0.4);
      transform: translateY(-1px);
    }

    .btn-sm {
      padding: 6px 12px;
      font-size: 12px;
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }

    .stat-card {
      background: var(--glass-bg);
      backdrop-filter: blur(var(--glass-blur));
      -webkit-backdrop-filter: blur(var(--glass-blur));
      border-radius: 16px;
      padding: 24px;
      border: 1px solid var(--glass-border);
      box-shadow: var(--shadow-sm);
      transition: all var(--transition-normal);
      position: relative;
      overflow: hidden;
    }

    .stat-card::after {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
      background: var(--gradient-primary);
      opacity: 0;
      transition: opacity var(--transition-normal);
    }

    .stat-card:hover {
      transform: translateY(-2px);
      box-shadow: var(--shadow-md), 0 0 20px rgba(13, 148, 136, 0.1);
    }

    .stat-card:hover::after {
      opacity: 1;
    }

    .stat-card .label {
      color: var(--text-muted);
      font-size: 14px;
      margin-bottom: 8px;
    }

    .stat-card .value {
      font-size: 32px;
      font-weight: 600;
    }

    .stat-card .change {
      font-size: 12px;
      margin-top: 8px;
    }

    .stat-card .change.positive {
      color: var(--success);
    }

    .card {
      background: var(--glass-bg);
      backdrop-filter: blur(var(--glass-blur));
      -webkit-backdrop-filter: blur(var(--glass-blur));
      border-radius: 16px;
      border: 1px solid var(--glass-border);
      margin-bottom: 24px;
      box-shadow: var(--shadow-sm);
      transition: box-shadow var(--transition-normal);
    }

    .card:hover {
      box-shadow: var(--shadow-md);
    }

    .card-header {
      padding: 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 10px;
    }

    .card-header h3 {
      font-size: 18px;
    }

    .card-body {
      padding: 20px;
    }

    .table {
      width: 100%;
      border-collapse: collapse;
    }

    .table th, .table td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }

    .table th {
      color: var(--text-muted);
      font-weight: 500;
      font-size: 12px;
      text-transform: uppercase;
    }

    .table tr:hover {
      background: var(--bg-hover);
    }

    .table tr:last-child td {
      border-bottom: none;
    }

    .badge {
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 500;
    }

    .badge-success {
      background: rgba(34, 197, 94, 0.2);
      color: var(--success);
    }

    .badge-danger {
      background: rgba(239, 68, 68, 0.2);
      color: var(--danger);
    }

    .badge-warning {
      background: rgba(245, 158, 11, 0.2);
      color: var(--warning);
    }

    .badge-info {
      background: rgba(13, 148, 136, 0.2);
      color: var(--primary);
    }

    .form-group {
      margin-bottom: 20px;
    }

    .form-group label {
      display: block;
      margin-bottom: 8px;
      color: var(--text-muted);
      font-size: 14px;
    }

    .form-control {
      width: 100%;
      padding: 12px 16px;
      border-radius: 10px;
      border: 1px solid var(--glass-border);
      background: rgba(15, 23, 42, 0.6);
      color: var(--text);
      font-size: 14px;
      transition: all var(--transition-fast);
    }

    .form-control:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(13, 148, 136, 0.2);
      background: rgba(15, 23, 42, 0.8);
    }

    .form-control::placeholder {
      color: var(--text-muted);
      opacity: 0.7;
    }

    .form-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 15px;
    }

    .search-box {
      display: flex;
      gap: 10px;
      margin-bottom: 20px;
    }

    .search-box input {
      flex: 1;
    }

    .filter-tabs {
      display: flex;
      gap: 10px;
      margin-bottom: 20px;
    }

    .filter-tab {
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      background: var(--bg);
      color: var(--text-muted);
      border: 1px solid var(--border);
      font-size: 13px;
    }

    .filter-tab.active {
      background: var(--primary);
      color: white;
      border-color: var(--primary);
    }

    .modal-overlay {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.6);
      backdrop-filter: blur(4px);
      -webkit-backdrop-filter: blur(4px);
      align-items: center;
      justify-content: center;
      z-index: 1000;
      padding: 20px;
      opacity: 0;
      transition: opacity var(--transition-normal);
    }

    .modal-overlay.active {
      display: flex;
      opacity: 1;
    }

    .modal {
      background: var(--glass-bg);
      backdrop-filter: blur(var(--glass-blur-heavy));
      -webkit-backdrop-filter: blur(var(--glass-blur-heavy));
      border-radius: 16px;
      width: 100%;
      max-width: 600px;
      max-height: 90vh;
      overflow: auto;
      border: 1px solid var(--glass-border);
      box-shadow: var(--shadow-lg);
      transform: scale(0.95) translateY(10px);
      transition: transform var(--transition-normal);
    }

    .modal-overlay.active .modal {
      transform: scale(1) translateY(0);
    }

    .modal.modal-lg {
      max-width: 900px;
    }

    .modal-header {
      padding: 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .modal-header h3 {
      font-size: 18px;
    }

    .modal-close {
      background: none;
      border: none;
      color: var(--text-muted);
      font-size: 24px;
      cursor: pointer;
    }

    .modal-body {
      padding: 20px;
    }

    .modal-footer {
      padding: 20px;
      border-top: 1px solid var(--border);
      display: flex;
      justify-content: flex-end;
      gap: 10px;
    }

    .actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }

    .action-btn {
      padding: 6px 12px;
      border-radius: 6px;
      border: none;
      cursor: pointer;
      font-size: 12px;
      background: var(--bg-hover);
      color: var(--text);
    }

    .action-btn:hover {
      background: var(--border);
    }

    .action-btn.danger {
      color: var(--danger);
    }

    .action-btn.success {
      color: var(--success);
    }

    .action-btn.warning {
      color: var(--warning);
    }

    /* Icon classes */
    svg.icon {
      width: 20px;
      height: 20px;
      display: inline-block;
      vertical-align: middle;
      flex-shrink: 0;
      stroke: currentColor;
    }

    svg.icon-sm {
      width: 16px;
      height: 16px;
    }

    svg.icon-lg {
      width: 24px;
      height: 24px;
    }

    svg.icon-xl {
      width: 32px;
      height: 32px;
    }

    .btn svg,
    .action-btn svg {
      width: 16px;
      height: 16px;
      stroke: currentColor;
    }

    .sidebar-header h1 svg {
      width: 24px;
      height: 24px;
      stroke: currentColor;
    }

    .login-box .logo svg {
      width: 48px;
      height: 48px;
      stroke: currentColor;
    }

    /* Skeleton Loaders */
    @keyframes skeleton-shimmer {
      0% { background-position: -200% 0; }
      100% { background-position: 200% 0; }
    }

    .skeleton {
      background: linear-gradient(
        90deg,
        rgba(255, 255, 255, 0.03) 25%,
        rgba(255, 255, 255, 0.08) 50%,
        rgba(255, 255, 255, 0.03) 75%
      );
      background-size: 200% 100%;
      animation: skeleton-shimmer 1.5s ease-in-out infinite;
      border-radius: 6px;
    }

    .skeleton-text {
      height: 14px;
      margin-bottom: 8px;
      border-radius: 4px;
    }

    .skeleton-text.short { width: 60%; }
    .skeleton-text.medium { width: 80%; }

    .skeleton-heading {
      height: 24px;
      width: 40%;
      margin-bottom: 12px;
    }

    .skeleton-stat {
      padding: 24px;
    }

    .skeleton-stat .skeleton-value {
      height: 32px;
      width: 80px;
      margin-bottom: 8px;
    }

    .skeleton-stat .skeleton-label {
      height: 14px;
      width: 100px;
    }

    .skeleton-table-row {
      display: grid;
      grid-template-columns: 2fr 1fr 1fr 1fr 1fr;
      gap: 16px;
      padding: 16px 12px;
      border-bottom: 1px solid var(--glass-border);
    }

    .skeleton-cell {
      height: 16px;
      border-radius: 4px;
    }

    /* Empty States */
    .empty-state {
      text-align: center;
      padding: 80px 40px;
      color: var(--text-muted);
    }

    .empty-state svg {
      width: 64px;
      height: 64px;
      margin: 0 auto 24px;
      opacity: 0.4;
      color: var(--primary);
      stroke: currentColor;
      display: block;
    }

    .empty-state h4 {
      font-size: 18px;
      color: var(--text);
      margin-bottom: 8px;
    }

    .empty-state p {
      font-size: 14px;
      max-width: 320px;
      margin: 0 auto 24px;
      line-height: 1.6;
    }

    .empty-state .btn {
      margin-top: 8px;
    }

    .pagination {
      display: flex;
      justify-content: center;
      gap: 10px;
      margin-top: 20px;
    }

    .hidden {
      display: none !important;
    }

    .toast {
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: var(--glass-bg);
      backdrop-filter: blur(var(--glass-blur));
      border: 1px solid var(--glass-border);
      border-radius: 12px;
      padding: 16px 20px;
      display: flex;
      align-items: center;
      gap: 12px;
      z-index: 1001;
      animation: toastSlideIn var(--transition-normal) ease-out;
      box-shadow: var(--shadow-md);
    }

    .toast.success {
      border-color: var(--success);
    }

    .toast.error {
      border-color: var(--danger);
    }

    .toast.removing {
      animation: toastSlideOut var(--transition-normal) ease-in forwards;
    }

    .toast svg {
      width: 18px;
      height: 18px;
      stroke: currentColor;
      flex-shrink: 0;
    }

    .toast.success svg {
      color: var(--success);
    }

    .toast.error svg {
      color: var(--danger);
    }

    @keyframes toastSlideIn {
      from {
        transform: translateX(100%);
        opacity: 0;
      }
      to {
        transform: translateX(0);
        opacity: 1;
      }
    }

    @keyframes toastSlideOut {
      from {
        transform: translateX(0);
        opacity: 1;
      }
      to {
        transform: translateX(100%);
        opacity: 0;
      }
    }

    /* Fade in animation */
    @keyframes fadeIn {
      from {
        opacity: 0;
        transform: translateY(8px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    .fade-in {
      animation: fadeIn var(--transition-normal) ease-out forwards;
    }

    /* Staggered fade-in for lists */
    .stagger-fade-in > * {
      opacity: 0;
      animation: fadeIn var(--transition-normal) ease-out forwards;
    }

    .stagger-fade-in > *:nth-child(1) { animation-delay: 0ms; }
    .stagger-fade-in > *:nth-child(2) { animation-delay: 50ms; }
    .stagger-fade-in > *:nth-child(3) { animation-delay: 100ms; }
    .stagger-fade-in > *:nth-child(4) { animation-delay: 150ms; }
    .stagger-fade-in > *:nth-child(5) { animation-delay: 200ms; }
    .stagger-fade-in > *:nth-child(6) { animation-delay: 250ms; }

    /* Page transitions */
    .page {
      animation: fadeIn var(--transition-normal) ease-out;
    }

    /* Pulse animation for badges */
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.6; }
    }

    .badge-count:not(.hidden) {
      animation: pulse 2s ease-in-out infinite;
    }

    /* Spin animation for loading */
    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }

    .btn-loading svg {
      animation: spin 1s linear infinite;
    }

    /* Table row hover transition */
    .table tbody tr {
      transition: background-color var(--transition-fast);
    }

    .user-info {
      padding: 20px;
      border-top: 1px solid var(--border);
    }

    .user-info .user-id {
      font-size: 12px;
      color: var(--text-muted);
      word-break: break-all;
    }

    .detail-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
    }

    .detail-item {
      padding: 16px;
      background: var(--bg);
      border-radius: 8px;
    }

    .detail-item .label {
      font-size: 12px;
      color: var(--text-muted);
      margin-bottom: 4px;
    }

    .detail-item .value {
      font-size: 16px;
      word-break: break-all;
    }

    .toggle-switch {
      position: relative;
      display: inline-block;
      width: 50px;
      height: 26px;
    }

    .toggle-switch input {
      opacity: 0;
      width: 0;
      height: 0;
    }

    .toggle-slider {
      position: absolute;
      cursor: pointer;
      inset: 0;
      background: var(--bg-hover);
      border-radius: 26px;
      transition: 0.3s;
    }

    .toggle-slider:before {
      position: absolute;
      content: "";
      height: 20px;
      width: 20px;
      left: 3px;
      bottom: 3px;
      background: white;
      border-radius: 50%;
      transition: 0.3s;
    }

    .toggle-switch input:checked + .toggle-slider {
      background: var(--success);
    }

    .toggle-switch input:checked + .toggle-slider:before {
      transform: translateX(24px);
    }

    .event-item {
      padding: 12px;
      background: var(--bg);
      border-radius: 8px;
      margin-bottom: 10px;
    }

    .event-item .event-header {
      display: flex;
      justify-content: space-between;
      margin-bottom: 8px;
      font-size: 12px;
      color: var(--text-muted);
    }

    .event-item .event-type {
      font-weight: 600;
      color: var(--primary);
    }

    .event-item .event-content {
      font-size: 13px;
      background: var(--bg-card);
      padding: 8px;
      border-radius: 4px;
      overflow-x: auto;
    }

    .report-card {
      background: var(--bg);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 12px;
    }

    .report-card.resolved {
      opacity: 0.7;
    }

    .report-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 12px;
    }

    .report-meta {
      font-size: 12px;
      color: var(--text-muted);
    }

    .checkbox-group {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 10px;
    }

    .checkbox-group input[type="checkbox"] {
      width: 18px;
      height: 18px;
      cursor: pointer;
    }

    @media (max-width: 768px) {
      .sidebar {
        transform: translateX(-100%);
      }
      .main-content {
        margin-left: 0;
      }
      .stats-grid {
        grid-template-columns: 1fr;
      }
      .form-row {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <!-- SVG Icon Definitions -->
  <svg style="display: none;" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <symbol id="icon-home" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>
      </symbol>
      <symbol id="icon-layout-dashboard" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/>
      </symbol>
      <symbol id="icon-users" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>
      </symbol>
      <symbol id="icon-user" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
      </symbol>
      <symbol id="icon-message-square" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
      </symbol>
      <symbol id="icon-folder" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>
      </symbol>
      <symbol id="icon-alert-triangle" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" x2="12" y1="9" y2="13"/><line x1="12" x2="12.01" y1="17" y2="17"/>
      </symbol>
      <symbol id="icon-globe" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>
      </symbol>
      <symbol id="icon-key" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>
      </symbol>
      <symbol id="icon-settings" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>
      </symbol>
      <symbol id="icon-refresh-cw" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>
      </symbol>
      <symbol id="icon-plus" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M5 12h14"/><path d="M12 5v14"/>
      </symbol>
      <symbol id="icon-trash-2" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/><line x1="10" x2="10" y1="11" y2="17"/><line x1="14" x2="14" y1="11" y2="17"/>
      </symbol>
      <symbol id="icon-eye" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>
      </symbol>
      <symbol id="icon-pencil" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/><path d="m15 5 4 4"/>
      </symbol>
      <symbol id="icon-search" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>
      </symbol>
      <symbol id="icon-x" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M18 6 6 18"/><path d="m6 6 12 12"/>
      </symbol>
      <symbol id="icon-log-out" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/>
      </symbol>
      <symbol id="icon-check-circle" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
      </symbol>
      <symbol id="icon-x-circle" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>
      </symbol>
      <symbol id="icon-lock" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      </symbol>
      <symbol id="icon-unlock" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>
      </symbol>
      <symbol id="icon-shield" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>
      </symbol>
      <symbol id="icon-send" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/>
      </symbol>
      <symbol id="icon-copy" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>
      </symbol>
      <symbol id="icon-info" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>
      </symbol>
      <symbol id="icon-server" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/>
      </symbol>
      <symbol id="icon-external-link" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
      </symbol>
      <symbol id="icon-clock" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
      </symbol>
      <symbol id="icon-inbox" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>
      </symbol>
      <symbol id="icon-file-text" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><line x1="16" x2="8" y1="13" y2="13"/><line x1="16" x2="8" y1="17" y2="17"/><line x1="10" x2="8" y1="9" y2="9"/>
      </symbol>
      <symbol id="icon-activity" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
      </symbol>
      <symbol id="icon-hard-drive" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <line x1="22" x2="2" y1="12" y2="12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><line x1="6" x2="6.01" y1="16" y2="16"/><line x1="10" x2="10.01" y1="16" y2="16"/>
      </symbol>
      <symbol id="icon-download" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/>
      </symbol>
      <symbol id="icon-upload" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" x2="12" y1="3" y2="15"/>
      </symbol>
      <symbol id="icon-ban" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/>
      </symbol>
      <symbol id="icon-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="20 6 9 17 4 12"/>
      </symbol>
      <symbol id="icon-chevron-left" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="m15 18-6-6 6-6"/>
      </symbol>
      <symbol id="icon-chevron-right" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="m9 18 6-6-6-6"/>
      </symbol>
      <symbol id="icon-toggle-left" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect width="20" height="12" x="2" y="6" rx="6" ry="6"/><circle cx="8" cy="12" r="2"/>
      </symbol>
      <symbol id="icon-toggle-right" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect width="20" height="12" x="2" y="6" rx="6" ry="6"/><circle cx="16" cy="12" r="2"/>
      </symbol>
      <symbol id="icon-link" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
      </symbol>
    </defs>
  </svg>

  <!-- Login Screen -->
  <div class="login-container" id="loginScreen">
    <div class="login-box">
      <div class="logo"><svg class="icon-xl" style="color: var(--primary);"><use href="#icon-home"/></svg></div>
      <h1>Matrix-PQC Admin</h1>
      <form id="loginForm">
        <div class="form-group">
          <label>Username</label>
          <input type="text" class="form-control" id="loginUsername" placeholder="admin" required>
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" class="form-control" id="loginPassword" required>
        </div>
        <button type="submit" class="btn btn-primary" style="width: 100%;">Sign In</button>
      </form>
      <div id="ssoProviders" style="margin-top: 20px; display: none;">
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 15px;">
          <hr style="flex: 1; border: none; border-top: 1px solid var(--border);">
          <span style="color: var(--text-muted); font-size: 12px;">or sign in with</span>
          <hr style="flex: 1; border: none; border-top: 1px solid var(--border);">
        </div>
        <div id="ssoButtons" style="display: flex; flex-direction: column; gap: 10px;"></div>
      </div>
      <p id="loginError" style="color: var(--danger); margin-top: 15px; text-align: center; display: none;"></p>
    </div>
  </div>

  <!-- Main App -->
  <div class="app-container" id="appContainer">
    <aside class="sidebar">
      <div class="sidebar-header">
        <h1><svg class="icon-lg" style="color: var(--primary);"><use href="#icon-home"/></svg> Matrix-PQC</h1>
        <div class="server-name">${serverName}</div>
      </div>
      <nav class="nav-menu">
        <a class="nav-item active" data-page="dashboard"><svg class="icon"><use href="#icon-layout-dashboard"/></svg><span>Dashboard</span></a>
        <a class="nav-item" data-page="users"><svg class="icon"><use href="#icon-users"/></svg><span>Users</span></a>
        <a class="nav-item" data-page="rooms"><svg class="icon"><use href="#icon-message-square"/></svg><span>Rooms</span></a>
        <a class="nav-item" data-page="media"><svg class="icon"><use href="#icon-folder"/></svg><span>Media</span></a>
        <a class="nav-item" data-page="reports"><svg class="icon"><use href="#icon-alert-triangle"/></svg><span>Reports</span><span class="badge-count hidden" id="reportsBadge">0</span></a>
        <a class="nav-item" data-page="federation"><svg class="icon"><use href="#icon-globe"/></svg><span>Federation</span></a>
        <a class="nav-item" data-page="idp"><svg class="icon"><use href="#icon-key"/></svg><span>Identity Providers</span></a>
        <a class="nav-item" data-page="config"><svg class="icon"><use href="#icon-settings"/></svg><span>Settings</span></a>
      </nav>
      <div class="user-info">
        <div style="font-weight: 500;" id="currentUserName">Admin</div>
        <div class="user-id" id="currentUserId"></div>
        <button class="btn btn-secondary" style="margin-top: 10px; width: 100%;" onclick="logout()"><svg class="icon"><use href="#icon-log-out"/></svg> Sign Out</button>
      </div>
    </aside>

    <main class="main-content">
      <!-- Dashboard Page -->
      <section id="page-dashboard" class="page">
        <div class="header">
          <h2>Dashboard</h2>
          <button class="btn btn-secondary" onclick="loadStats()"><svg class="icon"><use href="#icon-refresh-cw"/></svg> Refresh</button>
        </div>

        <div class="stats-grid">
          <div class="stat-card">
            <div class="label">Total Users</div>
            <div class="value" id="stat-users">-</div>
            <div class="change positive" id="stat-users-24h"></div>
          </div>
          <div class="stat-card">
            <div class="label">Active Users</div>
            <div class="value" id="stat-active">-</div>
          </div>
          <div class="stat-card">
            <div class="label">Total Rooms</div>
            <div class="value" id="stat-rooms">-</div>
          </div>
          <div class="stat-card">
            <div class="label">Total Events</div>
            <div class="value" id="stat-events">-</div>
            <div class="change positive" id="stat-events-24h"></div>
          </div>
          <div class="stat-card">
            <div class="label">Media Files</div>
            <div class="value" id="stat-media">-</div>
          </div>
          <div class="stat-card">
            <div class="label">Media Storage</div>
            <div class="value" id="stat-storage">-</div>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <h3>Server Information</h3>
          </div>
          <div class="card-body">
            <div class="detail-grid">
              <div class="detail-item">
                <div class="label">Server Name</div>
                <div class="value">${serverName}</div>
              </div>
              <div class="detail-item">
                <div class="label">Version</div>
                <div class="value" id="server-version">-</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- Users Page -->
      <section id="page-users" class="page hidden">
        <div class="header">
          <h2>Users</h2>
          <div class="header-actions">
            <button class="btn btn-danger" onclick="cleanupAllData()" title="Delete all non-admin users and rooms">Cleanup All</button>
            <button class="btn btn-primary" onclick="openModal('createUserModal')">+ Create User</button>
          </div>
        </div>

        <div class="search-box">
          <input type="text" class="form-control" id="userSearch" placeholder="Search users..." onkeyup="if(event.key==='Enter')searchUsers()">
          <button class="btn btn-primary" onclick="searchUsers()">Search</button>
        </div>

        <div class="card">
          <div class="card-body">
            <table class="table">
              <thead>
                <tr>
                  <th>User ID</th>
                  <th>Display Name</th>
                  <th>Status</th>
                  <th>Role</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody id="usersTable">
              </tbody>
            </table>
            <div class="pagination" id="usersPagination"></div>
          </div>
        </div>
      </section>

      <!-- Rooms Page -->
      <section id="page-rooms" class="page hidden">
        <div class="header">
          <h2>Rooms</h2>
        </div>

        <div class="search-box">
          <input type="text" class="form-control" id="roomSearch" placeholder="Search rooms by ID or name..." onkeyup="if(event.key==='Enter')searchRooms()">
          <button class="btn btn-primary" onclick="searchRooms()">Search</button>
          <button class="btn btn-secondary" onclick="clearRoomSearch()">Clear</button>
        </div>

        <div class="card">
          <div class="card-body">
            <table class="table">
              <thead>
                <tr>
                  <th>Room ID</th>
                  <th>Name</th>
                  <th>Members</th>
                  <th>Events</th>
                  <th>Public</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody id="roomsTable">
              </tbody>
            </table>
            <div class="pagination" id="roomsPagination"></div>
          </div>
        </div>
      </section>

      <!-- Media Page -->
      <section id="page-media" class="page hidden">
        <div class="header">
          <h2>Media Files</h2>
        </div>

        <div class="card">
          <div class="card-body">
            <table class="table">
              <thead>
                <tr>
                  <th>Media ID</th>
                  <th>Filename</th>
                  <th>Type</th>
                  <th>Size</th>
                  <th>Uploaded By</th>
                  <th>Status</th>
                  <th>Date</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody id="mediaTable">
              </tbody>
            </table>
            <div class="pagination" id="mediaPagination"></div>
          </div>
        </div>
      </section>

      <!-- Reports Page -->
      <section id="page-reports" class="page hidden">
        <div class="header">
          <h2>Content Reports</h2>
        </div>

        <div class="filter-tabs">
          <div class="filter-tab active" onclick="filterReports('pending')" data-filter="pending">Pending</div>
          <div class="filter-tab" onclick="filterReports('resolved')" data-filter="resolved">Resolved</div>
          <div class="filter-tab" onclick="filterReports('all')" data-filter="all">All</div>
        </div>

        <div id="reportsContainer">
        </div>
        <div class="pagination" id="reportsPagination"></div>
      </section>

      <!-- Federation Page -->
      <section id="page-federation" class="page hidden">
        <div class="header">
          <h2>Federation</h2>
        </div>

        <div class="card">
          <div class="card-header">
            <h3>Known Servers</h3>
          </div>
          <div class="card-body">
            <table class="table">
              <thead>
                <tr>
                  <th>Server Name</th>
                  <th>Last Contact</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody id="federationTable">
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- Identity Providers Page -->
      <section id="page-idp" class="page hidden">
        <div class="header">
          <h2>Identity Providers</h2>
          <button class="btn btn-primary" onclick="openCreateIdpModal()">+ Add Provider</button>
        </div>

        <div class="card">
          <div class="card-header">
            <h3>Configured Providers</h3>
          </div>
          <div class="card-body">
            <p style="margin-bottom: 15px; color: var(--text-muted); font-size: 13px;">
              Configure external identity providers (IdPs) to allow users to sign in using their existing accounts from Google, Microsoft, Okta, or any OIDC-compatible provider.
            </p>
            <table class="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Issuer URL</th>
                  <th>Linked Users</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody id="idpTable">
              </tbody>
            </table>
            <div id="idpEmpty" class="empty-state hidden">
              <svg><use href="#icon-key"/></svg>
              <h4>No identity providers</h4>
              <p>Click "Add Provider" to set up SSO authentication.</p>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <h3>SSO Login URL</h3>
          </div>
          <div class="card-body">
            <p style="margin-bottom: 10px; color: var(--text-muted); font-size: 13px;">
              Share this URL with users to access SSO login options:
            </p>
            <div style="display: flex; gap: 10px;">
              <input type="text" class="form-control" id="ssoLoginUrl" readonly value="https://${serverName}/auth/oidc/providers">
              <button class="btn btn-secondary" onclick="copySsoUrl()">Copy</button>
            </div>
          </div>
        </div>
      </section>

      <!-- Config Page -->
      <section id="page-config" class="page hidden">
        <div class="header">
          <h2>Settings</h2>
        </div>

        <div class="card">
          <div class="card-header">
            <h3>Server Configuration</h3>
          </div>
          <div class="card-body" id="configContent">
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <h3>Registration Control</h3>
          </div>
          <div class="card-body">
            <div style="display: flex; align-items: center; gap: 15px;">
              <label class="toggle-switch">
                <input type="checkbox" id="registrationToggle" onchange="toggleRegistration()">
                <span class="toggle-slider"></span>
              </label>
              <span id="registrationStatus">Loading...</span>
            </div>
            <p style="margin-top: 10px; color: var(--text-muted); font-size: 13px;">
              When disabled, new user registration will be blocked.
            </p>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <h3>Admin Management</h3>
          </div>
          <div class="card-body">
            <div class="form-group">
              <label>Grant Admin Privileges</label>
              <div style="display: flex; gap: 10px;">
                <input type="text" class="form-control" id="makeAdminUserId" placeholder="@user:${serverName}">
                <button class="btn btn-primary" onclick="makeAdmin()">Grant Admin</button>
              </div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <h3>Send Server Notice</h3>
          </div>
          <div class="card-body">
            <div class="form-group">
              <label>Recipient User ID</label>
              <input type="text" class="form-control" id="noticeUserId" placeholder="@user:${serverName}">
            </div>
            <div class="form-group">
              <label>Message</label>
              <textarea class="form-control" id="noticeMessage" rows="3" placeholder="Enter your notice message..."></textarea>
            </div>
            <button class="btn btn-primary" onclick="sendServerNotice()">Send Notice</button>
          </div>
        </div>
      </section>
    </main>
  </div>

  <!-- Create User Modal -->
  <div class="modal-overlay" id="createUserModal">
    <div class="modal">
      <div class="modal-header">
        <h3>Create New User</h3>
        <button class="modal-close" onclick="closeModal('createUserModal')">&times;</button>
      </div>
      <div class="modal-body">
        <div class="form-group">
          <label>Username</label>
          <input type="text" class="form-control" id="newUsername" placeholder="username">
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" class="form-control" id="newPassword" placeholder="Password">
        </div>
        <div class="form-group">
          <label>Display Name (optional)</label>
          <input type="text" class="form-control" id="newDisplayName" placeholder="Display Name">
        </div>
        <div class="checkbox-group">
          <input type="checkbox" id="newUserAdmin">
          <label for="newUserAdmin">Grant admin privileges</label>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="closeModal('createUserModal')">Cancel</button>
        <button class="btn btn-primary" onclick="createUser()">Create User</button>
      </div>
    </div>
  </div>

  <!-- User Detail Modal -->
  <div class="modal-overlay" id="userModal">
    <div class="modal modal-lg">
      <div class="modal-header">
        <h3>User Details</h3>
        <button class="modal-close" onclick="closeModal('userModal')">&times;</button>
      </div>
      <div class="modal-body" id="userModalContent">
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="closeModal('userModal')">Close</button>
      </div>
    </div>
  </div>

  <!-- Room Detail Modal -->
  <div class="modal-overlay" id="roomModal">
    <div class="modal modal-lg">
      <div class="modal-header">
        <h3>Room Details</h3>
        <button class="modal-close" onclick="closeModal('roomModal')">&times;</button>
      </div>
      <div class="modal-body" id="roomModalContent">
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="closeModal('roomModal')">Close</button>
      </div>
    </div>
  </div>

  <!-- Event Browser Modal -->
  <div class="modal-overlay" id="eventBrowserModal">
    <div class="modal modal-lg">
      <div class="modal-header">
        <h3>Event Browser</h3>
        <button class="modal-close" onclick="closeModal('eventBrowserModal')">&times;</button>
      </div>
      <div class="modal-body" id="eventBrowserContent">
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" id="loadMoreEvents">Load More</button>
        <button class="btn btn-secondary" onclick="closeModal('eventBrowserModal')">Close</button>
      </div>
    </div>
  </div>

  <!-- Reset Password Modal -->
  <div class="modal-overlay" id="resetPasswordModal">
    <div class="modal">
      <div class="modal-header">
        <h3>Reset Password</h3>
        <button class="modal-close" onclick="closeModal('resetPasswordModal')">&times;</button>
      </div>
      <div class="modal-body">
        <input type="hidden" id="resetPasswordUserId">
        <div class="form-group">
          <label>New Password</label>
          <input type="password" class="form-control" id="resetNewPassword" placeholder="Enter new password">
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="closeModal('resetPasswordModal')">Cancel</button>
        <button class="btn btn-primary" onclick="confirmResetPassword()">Reset Password</button>
      </div>
    </div>
  </div>

  <!-- Resolve Report Modal -->
  <div class="modal-overlay" id="resolveReportModal">
    <div class="modal">
      <div class="modal-header">
        <h3>Resolve Report</h3>
        <button class="modal-close" onclick="closeModal('resolveReportModal')">&times;</button>
      </div>
      <div class="modal-body">
        <input type="hidden" id="resolveReportId">
        <div class="form-group">
          <label>Resolution Note (optional)</label>
          <textarea class="form-control" id="resolutionNote" rows="3" placeholder="Add a note about this resolution..."></textarea>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="closeModal('resolveReportModal')">Cancel</button>
        <button class="btn btn-success" onclick="confirmResolveReport()">Resolve</button>
      </div>
    </div>
  </div>

  <!-- Create/Edit IdP Modal -->
  <div class="modal-overlay" id="createIdpModal">
    <div class="modal">
      <div class="modal-header">
        <h3 id="idpModalTitle">Add Identity Provider</h3>
        <button class="modal-close" onclick="closeModal('createIdpModal')">&times;</button>
      </div>
      <div class="modal-body">
        <input type="hidden" id="idpEditId">
        <div class="form-group">
          <label>Provider ID *</label>
          <input type="text" class="form-control" id="idpId" placeholder="e.g., google, okta, azure">
          <small style="color: var(--text-muted); font-size: 12px;">Unique identifier used in login URLs. Cannot be changed after creation.</small>
        </div>
        <div class="form-group">
          <label>Display Name *</label>
          <input type="text" class="form-control" id="idpName" placeholder="e.g., Google, Okta, Azure AD">
        </div>
        <div class="form-group">
          <label>Issuer URL *</label>
          <input type="text" class="form-control" id="idpIssuerUrl" placeholder="e.g., https://accounts.google.com">
          <small style="color: var(--text-muted); font-size: 12px;">The OIDC issuer URL. Must support /.well-known/openid-configuration</small>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Client ID *</label>
            <input type="text" class="form-control" id="idpClientId" placeholder="OAuth client ID">
          </div>
          <div class="form-group">
            <label>Client Secret *</label>
            <input type="password" class="form-control" id="idpClientSecret" placeholder="OAuth client secret">
            <small style="color: var(--text-muted); font-size: 12px;" id="idpSecretHint"></small>
          </div>
        </div>
        <div class="form-group">
          <label>Scopes</label>
          <input type="text" class="form-control" id="idpScopes" placeholder="openid profile email" value="openid profile email">
        </div>
        <div class="form-group">
          <label>Username Claim</label>
          <select class="form-control" id="idpUsernameClaim">
            <option value="email">email (part before @)</option>
            <option value="preferred_username">preferred_username</option>
            <option value="sub">sub (subject ID)</option>
          </select>
          <small style="color: var(--text-muted); font-size: 12px;">Which claim to use for deriving Matrix usernames</small>
        </div>
        <div class="form-group">
          <label>Icon URL (optional)</label>
          <input type="text" class="form-control" id="idpIconUrl" placeholder="https://example.com/icon.png">
        </div>
        <div class="form-group">
          <label>Display Order</label>
          <input type="number" class="form-control" id="idpDisplayOrder" value="0" min="0">
        </div>
        <div class="checkbox-group">
          <input type="checkbox" id="idpEnabled" checked>
          <label for="idpEnabled">Enabled</label>
        </div>
        <div class="checkbox-group">
          <input type="checkbox" id="idpAutoCreate" checked>
          <label for="idpAutoCreate">Auto-create accounts for new users</label>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="testIdpConnection()" id="testIdpBtn">Test Connection</button>
        <button class="btn btn-secondary" onclick="closeModal('createIdpModal')">Cancel</button>
        <button class="btn btn-primary" onclick="saveIdp()" id="saveIdpBtn">Add Provider</button>
      </div>
    </div>
  </div>

  <!-- IdP Detail Modal -->
  <div class="modal-overlay" id="idpDetailModal">
    <div class="modal modal-lg">
      <div class="modal-header">
        <h3>Identity Provider Details</h3>
        <button class="modal-close" onclick="closeModal('idpDetailModal')">&times;</button>
      </div>
      <div class="modal-body" id="idpDetailContent">
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="closeModal('idpDetailModal')">Close</button>
      </div>
    </div>
  </div>

  <!-- QR Code Modal - COMMENTED OUT: Requires MSC4108/OIDC for Element X support
  <div class="modal-overlay" id="qrCodeModal">
    <div class="modal">
      <div class="modal-header">
        <h3>Login QR Code</h3>
        <button class="modal-close" onclick="closeModal('qrCodeModal')">&times;</button>
      </div>
      <div class="modal-body" style="text-align: center;">
        <div id="qrCodeContainer" style="display: flex; justify-content: center; margin-bottom: 20px;">
          <div id="qrCode"></div>
        </div>
        <div id="qrUserInfo" style="margin-bottom: 16px;"></div>
        <div id="qrExpiry" style="color: var(--warning); font-size: 13px; margin-bottom: 16px;"></div>
        <div class="form-group" style="text-align: left;">
          <label>Login URL (share this link)</label>
          <div style="display: flex; gap: 8px;">
            <input type="text" class="form-control" id="qrUrl" readonly style="font-size: 12px;">
            <button class="btn btn-secondary" onclick="copyQrUrl()">Copy</button>
          </div>
        </div>
        <p style="font-size: 12px; color: var(--text-muted); margin-top: 12px;">
          User scans QR code with phone camera to open login page
        </p>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="closeModal('qrCodeModal')">Close</button>
        <button class="btn btn-primary" onclick="regenerateQr()">Generate New QR</button>
      </div>
    </div>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script>
  -->

  <script>
    let accessToken = localStorage.getItem('admin_token');
    let currentUserId = localStorage.getItem('admin_user_id');
    let currentPage = 'dashboard';
    let allRoomsCache = [];
    let currentEventRoomId = null;
    let currentEventsBefore = null;
    // let currentQrUserId = null; // QR feature commented out

    // Check if logged in
    if (accessToken) {
      showApp();
    } else {
      // Load SSO providers for login screen
      loadSsoProviders();
    }

    // Login form
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('loginUsername').value;
      const password = document.getElementById('loginPassword').value;

      try {
        const res = await fetch('/_matrix/client/v3/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: 'm.login.password',
            identifier: { type: 'm.id.user', user: username },
            password: password
          })
        });

        const data = await res.json();
        if (data.access_token) {
          accessToken = data.access_token;
          currentUserId = data.user_id;
          localStorage.setItem('admin_token', accessToken);
          localStorage.setItem('admin_user_id', currentUserId);
          showApp();
        } else {
          showLoginError(data.error || 'Login failed');
        }
      } catch (err) {
        showLoginError('Connection error');
      }
    });

    function showLoginError(msg) {
      const el = document.getElementById('loginError');
      el.textContent = msg;
      el.style.display = 'block';
    }

    async function loadSsoProviders() {
      try {
        const res = await fetch('/auth/oidc/providers');
        const data = await res.json();

        if (data.providers && data.providers.length > 0) {
          const container = document.getElementById('ssoProviders');
          const buttonsContainer = document.getElementById('ssoButtons');

          // Local escape function since escapeHtml isn't defined yet
          const esc = (str) => String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

          buttonsContainer.innerHTML = data.providers.map(p => \`
            <a href="\${esc(p.login_url)}?return_to=/admin" class="btn btn-secondary" style="width: 100%; justify-content: center;">
              \${p.icon_url ? \`<img src="\${esc(p.icon_url)}" style="width: 20px; height: 20px;">\` : '<svg class="icon"><use href="#icon-key"/></svg>'}
              Sign in with \${esc(p.name)}
            </a>
          \`).join('');

          container.style.display = 'block';
        }
      } catch (err) {
        // Silently fail - SSO is optional
        console.log('No SSO providers available');
      }
    }

    function showApp() {
      document.getElementById('loginScreen').style.display = 'none';
      document.getElementById('appContainer').style.display = 'block';
      document.getElementById('currentUserId').textContent = currentUserId;
      loadStats();
      loadUnresolvedReportsCount();
    }

    function logout() {
      localStorage.removeItem('admin_token');
      localStorage.removeItem('admin_user_id');
      accessToken = null;
      currentUserId = null;
      document.getElementById('loginScreen').style.display = 'flex';
      document.getElementById('appContainer').style.display = 'none';
    }

    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', () => {
        const page = item.dataset.page;
        navigateTo(page);
      });
    });

    function navigateTo(page) {
      currentPage = page;
      document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
      document.querySelector(\`[data-page="\${page}"]\`).classList.add('active');
      document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
      document.getElementById(\`page-\${page}\`).classList.remove('hidden');

      // Load page data
      switch (page) {
        case 'dashboard': loadStats(); break;
        case 'users': loadUsers(); break;
        case 'rooms': loadRooms(); break;
        case 'media': loadMedia(); break;
        case 'reports': loadReports(); break;
        case 'federation': loadFederation(); break;
        case 'idp': loadIdpProviders(); break;
        case 'config': loadConfig(); loadRegistrationStatus(); break;
      }
    }

    // API helper
    async function api(endpoint, options = {}) {
      const res = await fetch(endpoint, {
        ...options,
        headers: {
          'Authorization': \`Bearer \${accessToken}\`,
          'Content-Type': 'application/json',
          ...options.headers
        }
      });
      if (res.status === 401 || res.status === 403) {
        logout();
        throw new Error('Unauthorized');
      }
      return res.json();
    }

    // Dashboard
    async function loadStats() {
      try {
        const data = await api('/admin/api/stats');
        document.getElementById('stat-users').textContent = data.users.total;
        document.getElementById('stat-active').textContent = data.users.active;
        document.getElementById('stat-users-24h').textContent = \`+\${data.users.registrations_24h} today\`;
        document.getElementById('stat-rooms').textContent = data.rooms.total;
        document.getElementById('stat-events').textContent = formatNumber(data.events.total);
        document.getElementById('stat-events-24h').textContent = \`+\${formatNumber(data.events.last_24h)} today\`;
        document.getElementById('stat-media').textContent = data.media.count;
        document.getElementById('stat-storage').textContent = formatBytes(data.media.total_size_bytes);
        document.getElementById('server-version').textContent = data.server.version;
      } catch (err) {
        console.error('Failed to load stats:', err);
      }
    }

    // Load unresolved reports count for badge
    async function loadUnresolvedReportsCount() {
      try {
        const data = await api('/admin/api/reports?resolved=false&limit=1');
        const badge = document.getElementById('reportsBadge');
        if (data.total > 0) {
          badge.textContent = data.total > 99 ? '99+' : data.total;
          badge.classList.remove('hidden');
        } else {
          badge.classList.add('hidden');
        }
      } catch (err) {
        console.error('Failed to load reports count:', err);
      }
    }

    // Users
    let usersOffset = 0;
    async function loadUsers(offset = 0) {
      usersOffset = offset;
      const search = document.getElementById('userSearch').value;
      try {
        const data = await api(\`/admin/api/users?limit=20&offset=\${offset}\${search ? \`&search=\${encodeURIComponent(search)}\` : ''}\`);
        const tbody = document.getElementById('usersTable');
        tbody.innerHTML = data.users.map(u => \`
          <tr>
            <td style="font-size: 13px;">\${escapeHtml(u.user_id)}</td>
            <td>\${escapeHtml(u.display_name || '-')}</td>
            <td><span class="badge \${u.is_deactivated ? 'badge-danger' : 'badge-success'}">\${u.is_deactivated ? 'Deactivated' : 'Active'}</span></td>
            <td><span class="badge \${u.admin ? 'badge-warning' : 'badge-info'}">\${u.admin ? 'Admin' : 'User'}</span></td>
            <td>\${formatDate(u.created_at)}</td>
            <td class="actions">
              <button class="action-btn" onclick="viewUser('\${escapeAttr(u.user_id)}')">View</button>
              <button class="action-btn" onclick="resetPassword('\${escapeAttr(u.user_id)}')">Reset PW</button>
              \${u.is_deactivated ?
                \`<button class="action-btn success" onclick="reactivateUser('\${escapeAttr(u.user_id)}')">Reactivate</button>\` :
                \`<button class="action-btn danger" onclick="deactivateUser('\${escapeAttr(u.user_id)}')">Deactivate</button>\`
              }
              <button class="action-btn danger" onclick="purgeUser('\${escapeAttr(u.user_id)}')" title="Permanently delete">Purge</button>
            </td>
          </tr>
        \`).join('');
        renderPagination('usersPagination', data.total, 20, offset, loadUsers);
      } catch (err) {
        console.error('Failed to load users:', err);
      }
    }

    function searchUsers() {
      loadUsers(0);
    }

    async function createUser() {
      const username = document.getElementById('newUsername').value.trim();
      const password = document.getElementById('newPassword').value;
      const displayName = document.getElementById('newDisplayName').value.trim();
      const admin = document.getElementById('newUserAdmin').checked;

      if (!username || !password) {
        showToast('Username and password are required', 'error');
        return;
      }

      try {
        const result = await api('/admin/api/users/create', {
          method: 'POST',
          body: JSON.stringify({ username, password, display_name: displayName || null, admin })
        });

        if (result.success) {
          closeModal('createUserModal');
          document.getElementById('newUsername').value = '';
          document.getElementById('newPassword').value = '';
          document.getElementById('newDisplayName').value = '';
          document.getElementById('newUserAdmin').checked = false;
          loadUsers(usersOffset);
          showToast(\`User \${result.user_id} created successfully\`, 'success');
        } else {
          showToast(result.error || 'Failed to create user', 'error');
        }
      } catch (err) {
        showToast('Failed to create user', 'error');
      }
    }

    /* QR Code Functions - COMMENTED OUT: Requires MSC4108/OIDC for Element X support
    async function generateQrCode(userId) {
      currentQrUserId = userId;
      try {
        const result = await api(\`/admin/api/users/\${encodeURIComponent(userId)}/login-token\`, {
          method: 'POST',
          body: JSON.stringify({ ttl_minutes: 10 })
        });

        if (result.success) {
          displayQrCode(result.qr_url, userId, result.expires_at);
        } else {
          showToast(result.error || 'Failed to generate QR code', 'error');
        }
      } catch (err) {
        showToast('Failed to generate QR code', 'error');
      }
    }

    function displayQrCode(url, userId, expiresAt) {
      const qrContainer = document.getElementById('qrCode');
      qrContainer.innerHTML = '';
      try {
        if (typeof window.qrcode !== 'function') {
          throw new Error('QR code library not loaded');
        }
        const qrGen = window.qrcode(0, 'M');
        qrGen.addData(url);
        qrGen.make();
        qrContainer.innerHTML = qrGen.createSvgTag({ scalable: true });
        const svg = qrContainer.querySelector('svg');
        if (svg) {
          svg.style.width = '200px';
          svg.style.height = '200px';
        }
      } catch (err) {
        console.error('QR code generation failed:', err);
        qrContainer.innerHTML = '<p style="color: var(--danger);">Failed to generate QR code</p>';
      }
      document.getElementById('qrUserInfo').innerHTML = \`<strong>User:</strong> \${escapeHtml(userId)}\`;
      document.getElementById('qrUrl').value = url;
      const updateExpiry = () => {
        const remaining = Math.max(0, Math.ceil((expiresAt - Date.now()) / 60000));
        document.getElementById('qrExpiry').textContent = remaining > 0
          ? \`Expires in \${remaining} minute\${remaining !== 1 ? 's' : ''}\`
          : 'Token expired - generate a new one';
      };
      updateExpiry();
      const expiryInterval = setInterval(updateExpiry, 30000);
      const modal = document.getElementById('qrCodeModal');
      const observer = new MutationObserver(() => {
        if (!modal.classList.contains('active')) {
          clearInterval(expiryInterval);
          observer.disconnect();
        }
      });
      observer.observe(modal, { attributes: true, attributeFilter: ['class'] });
      openModal('qrCodeModal');
    }

    function copyQrUrl() {
      const input = document.getElementById('qrUrl');
      input.select();
      document.execCommand('copy');
      showToast('URL copied to clipboard', 'success');
    }

    function regenerateQr() {
      if (currentQrUserId) {
        generateQrCode(currentQrUserId);
      }
    }
    */

    async function viewUser(userId) {
      try {
        const [userData, sessionsData] = await Promise.all([
          api(\`/admin/api/users/\${encodeURIComponent(userId)}\`),
          api(\`/admin/api/users/\${encodeURIComponent(userId)}/sessions\`)
        ]);

        document.getElementById('userModalContent').innerHTML = \`
          <div class="detail-grid">
            <div class="detail-item">
              <div class="label">User ID</div>
              <div class="value" style="font-size: 13px;">\${escapeHtml(userData.user_id)}</div>
            </div>
            <div class="detail-item">
              <div class="label">Display Name</div>
              <div class="value">\${escapeHtml(userData.display_name || '-')}</div>
            </div>
            <div class="detail-item">
              <div class="label">Status</div>
              <div class="value">\${userData.is_deactivated ? '<span class="badge badge-danger">Deactivated</span>' : '<span class="badge badge-success">Active</span>'}</div>
            </div>
            <div class="detail-item">
              <div class="label">Role</div>
              <div class="value">
                \${userData.admin ? '<span class="badge badge-warning">Admin</span>' : '<span class="badge badge-info">User</span>'}
                \${userData.admin && userData.user_id !== currentUserId ?
                  \`<button class="action-btn danger" style="margin-left: 10px;" onclick="removeAdmin('\${escapeAttr(userData.user_id)}')">Remove Admin</button>\` :
                  (!userData.admin ? \`<button class="action-btn" style="margin-left: 10px;" onclick="makeAdminFromModal('\${escapeAttr(userData.user_id)}')">Make Admin</button>\` : '')}
              </div>
            </div>
            <div class="detail-item">
              <div class="label">Guest</div>
              <div class="value">\${userData.is_guest ? 'Yes' : 'No'}</div>
            </div>
            <div class="detail-item">
              <div class="label">Created</div>
              <div class="value">\${formatDate(userData.created_at)}</div>
            </div>
          </div>

          <h4 style="margin: 20px 0 10px; display: flex; justify-content: space-between; align-items: center;">
            Sessions (\${sessionsData.sessions.length})
            \${sessionsData.sessions.length > 0 ? \`<button class="btn btn-danger btn-sm" onclick="revokeAllSessions('\${escapeAttr(userData.user_id)}')">Revoke All</button>\` : ''}
          </h4>
          <table class="table">
            <tr><th>Device ID</th><th>Created</th><th>Actions</th></tr>
            \${sessionsData.sessions.map(s => \`
              <tr>
                <td style="font-size: 12px;">\${escapeHtml(s.device_id || 'Unknown')}</td>
                <td>\${formatDate(s.created_at)}</td>
                <td><button class="action-btn danger" onclick="revokeSession(\${s.id})">Revoke</button></td>
              </tr>
            \`).join('') || '<tr><td colspan="3" style="text-align: center;">No active sessions</td></tr>'}
          </table>

          <h4 style="margin: 20px 0 10px;">Devices (\${userData.devices.length})</h4>
          <table class="table">
            <tr><th>Device ID</th><th>Name</th><th>Last Seen</th></tr>
            \${userData.devices.map(d => \`
              <tr>
                <td style="font-size: 12px;">\${escapeHtml(d.device_id)}</td>
                <td>\${escapeHtml(d.display_name || '-')}</td>
                <td>\${d.last_seen_ts ? formatDate(d.last_seen_ts) : '-'}</td>
              </tr>
            \`).join('') || '<tr><td colspan="3" style="text-align: center;">No devices</td></tr>'}
          </table>

          <h4 style="margin: 20px 0 10px;">Rooms (\${userData.rooms.length})</h4>
          <table class="table">
            <tr><th>Room ID</th><th>Membership</th></tr>
            \${userData.rooms.slice(0, 10).map(r => \`
              <tr>
                <td style="font-size: 12px;">\${escapeHtml(r.room_id)}</td>
                <td><span class="badge badge-info">\${r.membership}</span></td>
              </tr>
            \`).join('')}
            \${userData.rooms.length > 10 ? \`<tr><td colspan="2">... and \${userData.rooms.length - 10} more</td></tr>\` : ''}
          </table>
        \`;
        openModal('userModal');
      } catch (err) {
        showToast('Failed to load user details', 'error');
      }
    }

    function resetPassword(userId) {
      document.getElementById('resetPasswordUserId').value = userId;
      document.getElementById('resetNewPassword').value = '';
      openModal('resetPasswordModal');
    }

    async function confirmResetPassword() {
      const userId = document.getElementById('resetPasswordUserId').value;
      const password = document.getElementById('resetNewPassword').value;
      if (!password) {
        showToast('Please enter a password', 'error');
        return;
      }
      try {
        await api(\`/admin/api/users/\${encodeURIComponent(userId)}/reset-password\`, {
          method: 'POST',
          body: JSON.stringify({ password })
        });
        closeModal('resetPasswordModal');
        showToast('Password reset successfully', 'success');
      } catch (err) {
        showToast('Failed to reset password', 'error');
      }
    }

    async function deactivateUser(userId) {
      if (!confirm(\`Are you sure you want to deactivate \${userId}?\`)) return;
      try {
        await api(\`/admin/api/users/\${encodeURIComponent(userId)}\`, { method: 'DELETE' });
        showToast('User deactivated', 'success');
        loadUsers(usersOffset);
      } catch (err) {
        showToast('Failed to deactivate user', 'error');
      }
    }

    async function reactivateUser(userId) {
      if (!confirm(\`Reactivate \${userId}?\`)) return;
      try {
        await api(\`/admin/api/users/\${encodeURIComponent(userId)}/reactivate\`, { method: 'POST' });
        showToast('User reactivated', 'success');
        loadUsers(usersOffset);
      } catch (err) {
        showToast('Failed to reactivate user', 'error');
      }
    }

    async function removeAdmin(userId) {
      if (!confirm(\`Remove admin privileges from \${userId}?\`)) return;
      try {
        await api('/admin/api/remove-admin', {
          method: 'POST',
          body: JSON.stringify({ user_id: userId })
        });
        showToast('Admin privileges removed', 'success');
        closeModal('userModal');
        loadUsers(usersOffset);
      } catch (err) {
        showToast('Failed to remove admin', 'error');
      }
    }

    async function makeAdminFromModal(userId) {
      if (!confirm(\`Grant admin privileges to \${userId}?\`)) return;
      try {
        await api('/admin/api/make-admin', {
          method: 'POST',
          body: JSON.stringify({ user_id: userId })
        });
        showToast('Admin privileges granted', 'success');
        closeModal('userModal');
        loadUsers(usersOffset);
      } catch (err) {
        showToast('Failed to grant admin', 'error');
      }
    }

    async function revokeSession(sessionId) {
      if (!confirm('Revoke this session?')) return;
      try {
        await api(\`/admin/api/sessions/\${sessionId}\`, { method: 'DELETE' });
        showToast('Session revoked', 'success');
        closeModal('userModal');
      } catch (err) {
        showToast('Failed to revoke session', 'error');
      }
    }

    async function revokeAllSessions(userId) {
      if (!confirm(\`Revoke ALL sessions for \${userId}? This will log them out everywhere.\`)) return;
      try {
        const result = await api(\`/admin/api/users/\${encodeURIComponent(userId)}/sessions\`, { method: 'DELETE' });
        showToast(\`\${result.revoked} session(s) revoked\`, 'success');
        closeModal('userModal');
      } catch (err) {
        showToast('Failed to revoke sessions', 'error');
      }
    }

    async function purgeUser(userId) {
      if (!confirm(\`PERMANENTLY DELETE \${userId} and ALL their data? This cannot be undone!\`)) return;
      if (!confirm(\`Are you REALLY sure? Type "DELETE" in the next prompt to confirm.\`)) return;
      const confirmText = prompt('Type DELETE to confirm permanent deletion:');
      if (confirmText !== 'DELETE') {
        showToast('Deletion cancelled', 'info');
        return;
      }
      try {
        await api(\`/admin/api/users/\${encodeURIComponent(userId)}/purge\`, { method: 'DELETE' });
        showToast('User permanently deleted', 'success');
        closeModal('userModal');
        loadUsers(usersOffset);
      } catch (err) {
        showToast('Failed to delete user', 'error');
      }
    }

    async function cleanupAllData() {
      if (!confirm('This will DELETE all non-admin users and ALL rooms. Are you sure?')) return;
      if (!confirm('This action CANNOT be undone. Are you REALLY sure?')) return;
      const confirmText = prompt('Type CLEANUP to confirm:');
      if (confirmText !== 'CLEANUP') {
        showToast('Cleanup cancelled', 'info');
        return;
      }
      try {
        const result = await api('/admin/api/cleanup', { method: 'POST' });
        showToast(\`Cleanup complete. Deleted \${result.users_deleted} users.\`, 'success');
        loadStats();
        loadUsers(0);
        loadRooms(0);
      } catch (err) {
        showToast('Failed to cleanup', 'error');
      }
    }

    // Rooms
    let roomsOffset = 0;
    let roomSearchQuery = '';

    async function loadRooms(offset = 0) {
      roomsOffset = offset;
      try {
        const data = await api(\`/admin/api/rooms?limit=20&offset=\${offset}\`);
        allRoomsCache = data.rooms;
        displayRooms(roomSearchQuery ? filterRoomsLocally(data.rooms, roomSearchQuery) : data.rooms, data.total);
      } catch (err) {
        console.error('Failed to load rooms:', err);
      }
    }

    function filterRoomsLocally(rooms, query) {
      const q = query.toLowerCase();
      return rooms.filter(r =>
        r.room_id.toLowerCase().includes(q) ||
        (r.name && r.name.toLowerCase().includes(q))
      );
    }

    function displayRooms(rooms, total) {
      const tbody = document.getElementById('roomsTable');
      tbody.innerHTML = rooms.map(r => \`
        <tr>
          <td style="font-size: 12px; max-width: 200px; overflow: hidden; text-overflow: ellipsis;">\${escapeHtml(r.room_id)}</td>
          <td>\${escapeHtml(r.name || '-')}</td>
          <td>\${r.member_count}</td>
          <td>\${formatNumber(r.event_count)}</td>
          <td><span class="badge \${r.is_public ? 'badge-success' : 'badge-info'}">\${r.is_public ? 'Public' : 'Private'}</span></td>
          <td>\${formatDate(r.created_at)}</td>
          <td class="actions">
            <button class="action-btn" onclick="viewRoom('\${escapeAttr(r.room_id)}')">View</button>
            <button class="action-btn" onclick="browseEvents('\${escapeAttr(r.room_id)}')">Events</button>
            <button class="action-btn danger" onclick="deleteRoom('\${escapeAttr(r.room_id)}')">Delete</button>
          </td>
        </tr>
      \`).join('');

      if (!roomSearchQuery) {
        renderPagination('roomsPagination', total, 20, roomsOffset, loadRooms);
      } else {
        document.getElementById('roomsPagination').innerHTML = '';
      }
    }

    function searchRooms() {
      roomSearchQuery = document.getElementById('roomSearch').value.trim();
      if (roomSearchQuery && allRoomsCache.length > 0) {
        displayRooms(filterRoomsLocally(allRoomsCache, roomSearchQuery), 0);
      } else {
        loadRooms(0);
      }
    }

    function clearRoomSearch() {
      roomSearchQuery = '';
      document.getElementById('roomSearch').value = '';
      loadRooms(0);
    }

    async function viewRoom(roomId) {
      try {
        const data = await api(\`/admin/api/rooms/\${encodeURIComponent(roomId)}\`);
        document.getElementById('roomModalContent').innerHTML = \`
          <div class="detail-grid">
            <div class="detail-item">
              <div class="label">Room ID</div>
              <div class="value" style="font-size: 12px;">\${escapeHtml(data.room_id)}</div>
            </div>
            <div class="detail-item">
              <div class="label">Name</div>
              <div class="value">\${escapeHtml(data.name || '-')}</div>
            </div>
            <div class="detail-item">
              <div class="label">Topic</div>
              <div class="value">\${escapeHtml(data.topic || '-')}</div>
            </div>
            <div class="detail-item">
              <div class="label">Join Rule</div>
              <div class="value">\${data.join_rule || 'invite'}</div>
            </div>
            <div class="detail-item">
              <div class="label">Version</div>
              <div class="value">\${data.room_version}</div>
            </div>
            <div class="detail-item">
              <div class="label">Members</div>
              <div class="value">\${data.member_count}</div>
            </div>
          </div>
          \${data.aliases.length ? \`
            <h4 style="margin: 20px 0 10px;">Aliases</h4>
            <ul style="margin-left: 20px;">\${data.aliases.map(a => \`<li>\${escapeHtml(a)}</li>\`).join('')}</ul>
          \` : ''}
          <h4 style="margin: 20px 0 10px;">Members (\${data.members.length})</h4>
          <table class="table">
            <tr><th>User</th><th>Membership</th></tr>
            \${data.members.slice(0, 20).map(m => \`
              <tr>
                <td>\${escapeHtml(m.display_name || m.user_id)}</td>
                <td><span class="badge badge-info">\${m.membership}</span></td>
              </tr>
            \`).join('')}
            \${data.members.length > 20 ? \`<tr><td colspan="2">... and \${data.members.length - 20} more</td></tr>\` : ''}
          </table>
        \`;
        openModal('roomModal');
      } catch (err) {
        showToast('Failed to load room details', 'error');
      }
    }

    async function browseEvents(roomId) {
      currentEventRoomId = roomId;
      currentEventsBefore = null;
      document.getElementById('eventBrowserContent').innerHTML = '<p>Loading events...</p>';
      openModal('eventBrowserModal');
      await loadMoreRoomEvents(true);

      document.getElementById('loadMoreEvents').onclick = () => loadMoreRoomEvents(false);
    }

    async function loadMoreRoomEvents(clear = false) {
      try {
        let url = \`/admin/api/rooms/\${encodeURIComponent(currentEventRoomId)}/events?limit=20\`;
        if (currentEventsBefore) {
          url += \`&before=\${currentEventsBefore}\`;
        }

        const data = await api(url);

        const eventsHtml = data.events.map(e => \`
          <div class="event-item">
            <div class="event-header">
              <span class="event-type">\${escapeHtml(e.event_type)}\${e.state_key !== null ? \` (\${escapeHtml(e.state_key || '*')})\` : ''}</span>
              <span>\${formatDate(e.origin_server_ts)}</span>
            </div>
            <div style="margin-bottom: 6px; font-size: 12px; color: var(--text-muted);">
              From: \${escapeHtml(e.sender)}
            </div>
            <div class="event-content">
              <pre style="margin: 0; white-space: pre-wrap;">\${escapeHtml(JSON.stringify(e.content, null, 2))}</pre>
            </div>
          </div>
        \`).join('');

        if (clear) {
          document.getElementById('eventBrowserContent').innerHTML = eventsHtml || '<p>No events found</p>';
        } else {
          document.getElementById('eventBrowserContent').innerHTML += eventsHtml;
        }

        if (data.events.length > 0) {
          currentEventsBefore = data.events[data.events.length - 1].stream_position;
        }

        document.getElementById('loadMoreEvents').style.display = data.events.length < 20 ? 'none' : 'inline-flex';
      } catch (err) {
        showToast('Failed to load events', 'error');
      }
    }

    async function deleteRoom(roomId) {
      if (!confirm(\`Are you sure you want to DELETE this room? This cannot be undone!\`)) return;
      try {
        await api(\`/admin/api/rooms/\${encodeURIComponent(roomId)}\`, { method: 'DELETE' });
        showToast('Room deleted', 'success');
        loadRooms(roomsOffset);
      } catch (err) {
        showToast('Failed to delete room', 'error');
      }
    }

    // Media
    let mediaOffset = 0;
    async function loadMedia(offset = 0) {
      mediaOffset = offset;
      try {
        const data = await api(\`/admin/api/media?limit=20&offset=\${offset}\`);
        const tbody = document.getElementById('mediaTable');
        tbody.innerHTML = data.media.map(m => \`
          <tr>
            <td style="font-size: 12px;">\${escapeHtml(m.media_id)}</td>
            <td>\${escapeHtml(m.filename || '-')}</td>
            <td>\${escapeHtml(m.content_type)}</td>
            <td>\${formatBytes(m.content_length)}</td>
            <td style="font-size: 12px;">\${escapeHtml(m.user_id)}</td>
            <td><span class="badge \${m.quarantined ? 'badge-danger' : 'badge-success'}">\${m.quarantined ? 'Quarantined' : 'Active'}</span></td>
            <td>\${formatDate(m.created_at)}</td>
            <td class="actions">
              <a class="action-btn" href="/_matrix/media/v3/download/${serverName}/\${m.media_id}" target="_blank">Download</a>
              \${!m.quarantined ? \`<button class="action-btn warning" onclick="quarantineMedia('\${escapeAttr(m.media_id)}')">Quarantine</button>\` : ''}
              <button class="action-btn danger" onclick="deleteMedia('\${escapeAttr(m.media_id)}')">Delete</button>
            </td>
          </tr>
        \`).join('');
        renderPagination('mediaPagination', data.total, 20, offset, loadMedia);
      } catch (err) {
        console.error('Failed to load media:', err);
      }
    }

    async function quarantineMedia(mediaId) {
      if (!confirm('Quarantine this media? It will no longer be accessible.')) return;
      try {
        await api(\`/admin/api/media/\${mediaId}/quarantine\`, { method: 'POST' });
        showToast('Media quarantined', 'success');
        loadMedia(mediaOffset);
      } catch (err) {
        showToast('Failed to quarantine media', 'error');
      }
    }

    async function deleteMedia(mediaId) {
      if (!confirm('Delete this media file permanently?')) return;
      try {
        await api(\`/admin/api/media/\${mediaId}\`, { method: 'DELETE' });
        showToast('Media deleted', 'success');
        loadMedia(mediaOffset);
      } catch (err) {
        showToast('Failed to delete media', 'error');
      }
    }

    // Reports
    let reportsOffset = 0;
    let reportsFilter = 'pending';

    function filterReports(filter) {
      reportsFilter = filter;
      reportsOffset = 0;
      document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
      document.querySelector(\`[data-filter="\${filter}"]\`).classList.add('active');
      loadReports();
    }

    async function loadReports(offset = 0) {
      reportsOffset = offset;
      try {
        let url = \`/admin/api/reports?limit=20&offset=\${offset}\`;
        if (reportsFilter === 'pending') url += '&resolved=false';
        else if (reportsFilter === 'resolved') url += '&resolved=true';

        const data = await api(url);
        const container = document.getElementById('reportsContainer');

        if (data.reports.length === 0) {
          container.innerHTML = '<div class="empty-state"><svg><use href="#icon-inbox"/></svg><h4>All clear!</h4><p>No pending content reports.</p></div>';
        } else {
          container.innerHTML = data.reports.map(r => \`
            <div class="report-card \${r.resolved ? 'resolved' : ''}">
              <div class="report-header">
                <div>
                  <span class="badge \${r.resolved ? 'badge-success' : 'badge-danger'}">\${r.resolved ? 'Resolved' : 'Pending'}</span>
                  <span class="badge badge-info">\${escapeHtml(r.event_type || 'Unknown')}</span>
                </div>
                <div class="actions">
                  \${r.resolved ?
                    \`<button class="action-btn warning" onclick="unresolveReport(\${r.id})">Reopen</button>\` :
                    \`<button class="action-btn success" onclick="openResolveModal(\${r.id})">Resolve</button>\`
                  }
                </div>
              </div>
              <div class="report-meta">
                <strong>Reported by:</strong> \${escapeHtml(r.reporter_user_id)}<br>
                <strong>Reported user:</strong> \${escapeHtml(r.reported_user_id || 'Unknown')}<br>
                <strong>Room:</strong> \${escapeHtml(r.room_id)}<br>
                <strong>Date:</strong> \${formatDate(r.created_at)}<br>
                \${r.reason ? \`<strong>Reason:</strong> \${escapeHtml(r.reason)}<br>\` : ''}
                \${r.resolved ? \`
                  <strong>Resolved by:</strong> \${escapeHtml(r.resolved_by)}<br>
                  <strong>Resolved at:</strong> \${formatDate(r.resolved_at)}<br>
                  \${r.resolution_note ? \`<strong>Note:</strong> \${escapeHtml(r.resolution_note)}<br>\` : ''}
                \` : ''}
              </div>
              \${r.event_content ? \`
                <div style="margin-top: 12px;">
                  <strong style="font-size: 12px; color: var(--text-muted);">Event Content:</strong>
                  <div class="event-content" style="margin-top: 6px;">
                    <pre style="margin: 0; white-space: pre-wrap; font-size: 12px;">\${escapeHtml(JSON.stringify(r.event_content, null, 2))}</pre>
                  </div>
                </div>
              \` : ''}
            </div>
          \`).join('');
        }

        renderPagination('reportsPagination', data.total, 20, offset, loadReports);
        loadUnresolvedReportsCount();
      } catch (err) {
        console.error('Failed to load reports:', err);
      }
    }

    function openResolveModal(reportId) {
      document.getElementById('resolveReportId').value = reportId;
      document.getElementById('resolutionNote').value = '';
      openModal('resolveReportModal');
    }

    async function confirmResolveReport() {
      const reportId = document.getElementById('resolveReportId').value;
      const note = document.getElementById('resolutionNote').value.trim();

      try {
        await api(\`/admin/api/reports/\${reportId}/resolve\`, {
          method: 'POST',
          body: JSON.stringify({ note: note || null })
        });
        closeModal('resolveReportModal');
        showToast('Report resolved', 'success');
        loadReports(reportsOffset);
      } catch (err) {
        showToast('Failed to resolve report', 'error');
      }
    }

    async function unresolveReport(reportId) {
      if (!confirm('Reopen this report?')) return;
      try {
        await api(\`/admin/api/reports/\${reportId}/unresolve\`, { method: 'POST' });
        showToast('Report reopened', 'success');
        loadReports(reportsOffset);
      } catch (err) {
        showToast('Failed to reopen report', 'error');
      }
    }

    // Federation
    async function loadFederation() {
      try {
        const data = await api('/admin/api/federation/servers');
        const tbody = document.getElementById('federationTable');
        if (data.servers.length === 0) {
          tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-muted);">No federated servers yet</td></tr>';
        } else {
          tbody.innerHTML = data.servers.map(s => \`
            <tr>
              <td>\${escapeHtml(s.server_name)}</td>
              <td>\${s.last_successful_fetch ? formatDate(s.last_successful_fetch) : 'Never'}</td>
              <td><span class="badge \${s.retry_count > 0 ? 'badge-warning' : 'badge-success'}">\${s.retry_count > 0 ? \`Retry \${s.retry_count}\` : 'OK'}</span></td>
            </tr>
          \`).join('');
        }
      } catch (err) {
        console.error('Failed to load federation:', err);
      }
    }

    // Identity Providers
    async function loadIdpProviders() {
      try {
        const data = await api('/admin/api/idp/providers');
        const tbody = document.getElementById('idpTable');
        const emptyState = document.getElementById('idpEmpty');

        if (data.providers.length === 0) {
          tbody.innerHTML = '';
          emptyState.classList.remove('hidden');
        } else {
          emptyState.classList.add('hidden');
          tbody.innerHTML = data.providers.map(p => \`
            <tr>
              <td>
                \${p.icon_url ? \`<img src="\${escapeHtml(p.icon_url)}" style="width: 20px; height: 20px; vertical-align: middle; margin-right: 8px;">\` : ''}
                \${escapeHtml(p.name)}
                <span style="font-size: 11px; color: var(--text-muted); margin-left: 8px;">(\${escapeHtml(p.id)})</span>
              </td>
              <td style="font-size: 12px; max-width: 200px; overflow: hidden; text-overflow: ellipsis;">\${escapeHtml(p.issuer_url)}</td>
              <td>\${p.linked_users_count || 0}</td>
              <td><span class="badge \${p.enabled ? 'badge-success' : 'badge-danger'}">\${p.enabled ? 'Enabled' : 'Disabled'}</span></td>
              <td class="actions">
                <button class="action-btn" onclick="viewIdp('\${escapeAttr(p.id)}')">View</button>
                <button class="action-btn" onclick="editIdp('\${escapeAttr(p.id)}')">Edit</button>
                <button class="action-btn \${p.enabled ? 'warning' : 'success'}" onclick="toggleIdp('\${escapeAttr(p.id)}', \${!p.enabled})">\${p.enabled ? 'Disable' : 'Enable'}</button>
                <button class="action-btn danger" onclick="deleteIdp('\${escapeAttr(p.id)}')">Delete</button>
              </td>
            </tr>
          \`).join('');
        }
      } catch (err) {
        console.error('Failed to load IdP providers:', err);
        showToast('Failed to load identity providers', 'error');
      }
    }

    function openCreateIdpModal() {
      // Reset form for new provider
      document.getElementById('idpModalTitle').textContent = 'Add Identity Provider';
      document.getElementById('idpEditId').value = '';
      document.getElementById('idpId').value = '';
      document.getElementById('idpId').disabled = false;
      document.getElementById('idpName').value = '';
      document.getElementById('idpIssuerUrl').value = '';
      document.getElementById('idpClientId').value = '';
      document.getElementById('idpClientSecret').value = '';
      document.getElementById('idpSecretHint').textContent = '';
      document.getElementById('idpScopes').value = 'openid profile email';
      document.getElementById('idpUsernameClaim').value = 'email';
      document.getElementById('idpIconUrl').value = '';
      document.getElementById('idpDisplayOrder').value = '0';
      document.getElementById('idpEnabled').checked = true;
      document.getElementById('idpAutoCreate').checked = true;
      document.getElementById('saveIdpBtn').textContent = 'Add Provider';
      openModal('createIdpModal');
    }

    async function editIdp(providerId) {
      try {
        const data = await api(\`/admin/api/idp/providers/\${encodeURIComponent(providerId)}\`);

        document.getElementById('idpModalTitle').textContent = 'Edit Identity Provider';
        document.getElementById('idpEditId').value = data.id;
        document.getElementById('idpId').value = data.id;
        document.getElementById('idpId').disabled = true;
        document.getElementById('idpName').value = data.name;
        document.getElementById('idpIssuerUrl').value = data.issuer_url;
        document.getElementById('idpClientId').value = data.client_id;
        document.getElementById('idpClientSecret').value = '';
        document.getElementById('idpSecretHint').textContent = 'Leave blank to keep existing secret';
        document.getElementById('idpScopes').value = data.scopes;
        document.getElementById('idpUsernameClaim').value = data.username_claim;
        document.getElementById('idpIconUrl').value = data.icon_url || '';
        document.getElementById('idpDisplayOrder').value = data.display_order;
        document.getElementById('idpEnabled').checked = data.enabled;
        document.getElementById('idpAutoCreate').checked = data.auto_create_users;
        document.getElementById('saveIdpBtn').textContent = 'Save Changes';
        openModal('createIdpModal');
      } catch (err) {
        showToast('Failed to load provider details', 'error');
      }
    }

    async function saveIdp() {
      const editId = document.getElementById('idpEditId').value;
      const isEdit = !!editId;

      const payload = {
        id: document.getElementById('idpId').value.trim(),
        name: document.getElementById('idpName').value.trim(),
        issuer_url: document.getElementById('idpIssuerUrl').value.trim(),
        client_id: document.getElementById('idpClientId').value.trim(),
        client_secret: document.getElementById('idpClientSecret').value,
        scopes: document.getElementById('idpScopes').value.trim(),
        username_claim: document.getElementById('idpUsernameClaim').value,
        icon_url: document.getElementById('idpIconUrl').value.trim() || null,
        display_order: parseInt(document.getElementById('idpDisplayOrder').value) || 0,
        enabled: document.getElementById('idpEnabled').checked,
        auto_create_users: document.getElementById('idpAutoCreate').checked
      };

      // Validation
      if (!payload.id || !payload.name || !payload.issuer_url || !payload.client_id) {
        showToast('Please fill in all required fields', 'error');
        return;
      }

      if (!isEdit && !payload.client_secret) {
        showToast('Client secret is required for new providers', 'error');
        return;
      }

      // Remove empty client_secret on edit (keep existing)
      if (isEdit && !payload.client_secret) {
        delete payload.client_secret;
      }

      try {
        if (isEdit) {
          await api(\`/admin/api/idp/providers/\${encodeURIComponent(editId)}\`, {
            method: 'PUT',
            body: JSON.stringify(payload)
          });
          showToast('Provider updated successfully', 'success');
        } else {
          await api('/admin/api/idp/providers', {
            method: 'POST',
            body: JSON.stringify(payload)
          });
          showToast('Provider created successfully', 'success');
        }
        closeModal('createIdpModal');
        loadIdpProviders();
      } catch (err) {
        showToast(\`Failed to \${isEdit ? 'update' : 'create'} provider\`, 'error');
      }
    }

    async function viewIdp(providerId) {
      try {
        const data = await api(\`/admin/api/idp/providers/\${encodeURIComponent(providerId)}\`);

        document.getElementById('idpDetailContent').innerHTML = \`
          <div class="detail-grid">
            <div class="detail-item">
              <div class="label">Provider ID</div>
              <div class="value">\${escapeHtml(data.id)}</div>
            </div>
            <div class="detail-item">
              <div class="label">Display Name</div>
              <div class="value">\${escapeHtml(data.name)}</div>
            </div>
            <div class="detail-item">
              <div class="label">Issuer URL</div>
              <div class="value" style="font-size: 13px;">\${escapeHtml(data.issuer_url)}</div>
            </div>
            <div class="detail-item">
              <div class="label">Client ID</div>
              <div class="value" style="font-size: 13px;">\${escapeHtml(data.client_id)}</div>
            </div>
            <div class="detail-item">
              <div class="label">Status</div>
              <div class="value"><span class="badge \${data.enabled ? 'badge-success' : 'badge-danger'}">\${data.enabled ? 'Enabled' : 'Disabled'}</span></div>
            </div>
            <div class="detail-item">
              <div class="label">Auto-create Users</div>
              <div class="value">\${data.auto_create_users ? 'Yes' : 'No'}</div>
            </div>
            <div class="detail-item">
              <div class="label">Username Claim</div>
              <div class="value">\${escapeHtml(data.username_claim)}</div>
            </div>
            <div class="detail-item">
              <div class="label">Scopes</div>
              <div class="value">\${escapeHtml(data.scopes)}</div>
            </div>
          </div>

          <div style="margin-top: 20px; padding: 16px; background: var(--bg); border-radius: 8px;">
            <div class="label" style="margin-bottom: 8px;">Login URL</div>
            <div style="display: flex; gap: 8px;">
              <input type="text" class="form-control" readonly value="https://${serverName}/auth/oidc/\${escapeHtml(data.id)}/login" style="font-size: 12px;">
              <button class="btn btn-secondary btn-sm" onclick="navigator.clipboard.writeText('https://${serverName}/auth/oidc/\${escapeAttr(data.id)}/login'); showToast('Copied!', 'success');">Copy</button>
            </div>
          </div>

          <h4 style="margin: 20px 0 10px;">Linked Users (\${data.linked_users?.length || 0})</h4>
          \${data.linked_users && data.linked_users.length > 0 ? \`
            <table class="table">
              <thead>
                <tr>
                  <th>Matrix User</th>
                  <th>External ID</th>
                  <th>Email</th>
                  <th>Last Login</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                \${data.linked_users.map(u => \`
                  <tr>
                    <td style="font-size: 12px;">\${escapeHtml(u.user_id)}</td>
                    <td style="font-size: 12px;">\${escapeHtml(u.external_id)}</td>
                    <td>\${escapeHtml(u.external_email || '-')}</td>
                    <td>\${u.last_login_at ? formatDate(u.last_login_at) : 'Never'}</td>
                    <td>
                      <button class="action-btn danger" onclick="unlinkIdpUser('\${escapeAttr(data.id)}', \${u.id})">Unlink</button>
                    </td>
                  </tr>
                \`).join('')}
              </tbody>
            </table>
          \` : '<p style="color: var(--text-muted);">No users have logged in via this provider yet.</p>'}
        \`;
        openModal('idpDetailModal');
      } catch (err) {
        showToast('Failed to load provider details', 'error');
      }
    }

    async function toggleIdp(providerId, enabled) {
      try {
        await api(\`/admin/api/idp/providers/\${encodeURIComponent(providerId)}\`, {
          method: 'PUT',
          body: JSON.stringify({ enabled })
        });
        showToast(\`Provider \${enabled ? 'enabled' : 'disabled'}\`, 'success');
        loadIdpProviders();
      } catch (err) {
        showToast('Failed to update provider', 'error');
      }
    }

    async function deleteIdp(providerId) {
      if (!confirm(\`Are you sure you want to delete this identity provider? All user links will be removed.\`)) return;
      try {
        await api(\`/admin/api/idp/providers/\${encodeURIComponent(providerId)}\`, { method: 'DELETE' });
        showToast('Provider deleted', 'success');
        loadIdpProviders();
      } catch (err) {
        showToast('Failed to delete provider', 'error');
      }
    }

    async function unlinkIdpUser(providerId, linkId) {
      if (!confirm('Unlink this user from the identity provider? They will need to re-authenticate.')) return;
      try {
        await api(\`/admin/api/idp/providers/\${encodeURIComponent(providerId)}/links/\${linkId}\`, { method: 'DELETE' });
        showToast('User unlinked', 'success');
        viewIdp(providerId); // Refresh the modal
      } catch (err) {
        showToast('Failed to unlink user', 'error');
      }
    }

    async function testIdpConnection() {
      const issuerUrl = document.getElementById('idpIssuerUrl').value.trim();
      if (!issuerUrl) {
        showToast('Please enter an issuer URL first', 'error');
        return;
      }

      const btn = document.getElementById('testIdpBtn');
      const originalText = btn.textContent;
      btn.textContent = 'Testing...';
      btn.disabled = true;

      try {
        const providerId = document.getElementById('idpEditId').value || document.getElementById('idpId').value;
        if (providerId) {
          const result = await api(\`/admin/api/idp/providers/\${encodeURIComponent(providerId)}/test\`, { method: 'POST' });
          if (result.success) {
            showToast(\`Connection successful! Found endpoints: \${result.endpoints_found.join(', ')}\`, 'success');
          } else {
            showToast(\`Connection failed: \${result.error}\`, 'error');
          }
        } else {
          // For new providers, just test the issuer URL directly
          const discoveryUrl = issuerUrl.replace(/\\/$/, '') + '/.well-known/openid-configuration';
          const res = await fetch(discoveryUrl);
          if (res.ok) {
            const discovery = await res.json();
            if (discovery.issuer && discovery.authorization_endpoint && discovery.token_endpoint) {
              showToast('OIDC discovery successful! Provider is valid.', 'success');
            } else {
              showToast('Invalid OIDC discovery: missing required fields', 'error');
            }
          } else {
            showToast(\`Failed to fetch OIDC discovery: \${res.status}\`, 'error');
          }
        }
      } catch (err) {
        showToast(\`Connection test failed: \${err.message}\`, 'error');
      } finally {
        btn.textContent = originalText;
        btn.disabled = false;
      }
    }

    function copySsoUrl() {
      const input = document.getElementById('ssoLoginUrl');
      input.select();
      document.execCommand('copy');
      showToast('SSO URL copied to clipboard', 'success');
    }

    // Config
    async function loadConfig() {
      try {
        const data = await api('/admin/api/config');
        document.getElementById('configContent').innerHTML = \`
          <div class="detail-grid">
            <div class="detail-item">
              <div class="label">Server Name</div>
              <div class="value">\${escapeHtml(data.server_name)}</div>
            </div>
            <div class="detail-item">
              <div class="label">Version</div>
              <div class="value">\${escapeHtml(data.version)}</div>
            </div>
            <div class="detail-item">
              <div class="label">Max Upload Size</div>
              <div class="value">\${formatBytes(data.limits.max_upload_size)}</div>
            </div>
            <div class="detail-item">
              <div class="label">Federation</div>
              <div class="value">\${data.features.federation ? 'Enabled' : 'Disabled'}</div>
            </div>
            <div class="detail-item">
              <div class="label">VoIP (TURN)</div>
              <div class="value">\${data.features.voip ? 'Enabled' : 'Disabled'}</div>
            </div>
            <div class="detail-item">
              <div class="label">Media Upload</div>
              <div class="value">\${data.features.media_upload ? 'Enabled' : 'Disabled'}</div>
            </div>
          </div>
        \`;
      } catch (err) {
        console.error('Failed to load config:', err);
      }
    }

    async function loadRegistrationStatus() {
      try {
        const data = await api('/admin/api/registration');
        document.getElementById('registrationToggle').checked = data.enabled;
        document.getElementById('registrationStatus').textContent = data.enabled ? 'Registration is enabled' : 'Registration is disabled';
      } catch (err) {
        document.getElementById('registrationStatus').textContent = 'Unable to load status';
      }
    }

    async function toggleRegistration() {
      const enabled = document.getElementById('registrationToggle').checked;
      try {
        await api('/admin/api/registration', {
          method: 'PUT',
          body: JSON.stringify({ enabled })
        });
        document.getElementById('registrationStatus').textContent = enabled ? 'Registration is enabled' : 'Registration is disabled';
        showToast(\`Registration \${enabled ? 'enabled' : 'disabled'}\`, 'success');
      } catch (err) {
        showToast('Failed to update registration setting', 'error');
        document.getElementById('registrationToggle').checked = !enabled;
      }
    }

    async function makeAdmin() {
      const userId = document.getElementById('makeAdminUserId').value.trim();
      if (!userId) {
        showToast('Please enter a user ID', 'error');
        return;
      }
      try {
        await api('/admin/api/make-admin', {
          method: 'POST',
          body: JSON.stringify({ user_id: userId })
        });
        showToast(\`\${userId} is now an admin\`, 'success');
        document.getElementById('makeAdminUserId').value = '';
      } catch (err) {
        showToast('Failed to grant admin', 'error');
      }
    }

    async function sendServerNotice() {
      const userId = document.getElementById('noticeUserId').value.trim();
      const message = document.getElementById('noticeMessage').value.trim();

      if (!userId || !message) {
        showToast('User ID and message are required', 'error');
        return;
      }

      try {
        const result = await api('/admin/api/server-notice', {
          method: 'POST',
          body: JSON.stringify({ user_id: userId, message })
        });
        showToast(\`Notice sent to \${result.devices_notified} device(s)\`, 'success');
        document.getElementById('noticeUserId').value = '';
        document.getElementById('noticeMessage').value = '';
      } catch (err) {
        showToast('Failed to send notice', 'error');
      }
    }

    // Utilities
    function formatNumber(n) {
      return new Intl.NumberFormat().format(n || 0);
    }

    function formatBytes(bytes) {
      if (!bytes) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    function formatDate(ts) {
      if (!ts) return '-';
      return new Date(ts).toLocaleDateString() + ' ' + new Date(ts).toLocaleTimeString();
    }

    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function escapeAttr(str) {
      // Escape for use inside single-quoted JS strings in HTML attributes
      return String(str).replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'");
    }

    function renderPagination(elementId, total, limit, offset, callback) {
      const el = document.getElementById(elementId);
      const pages = Math.ceil(total / limit);
      const current = Math.floor(offset / limit);
      if (pages <= 1) {
        el.innerHTML = '';
        return;
      }
      let html = '';
      if (current > 0) {
        html += \`<button class="btn btn-secondary" onclick="\${callback.name}(\${(current - 1) * limit})">Previous</button>\`;
      }
      html += \`<span style="padding: 10px;">Page \${current + 1} of \${pages}</span>\`;
      if (current < pages - 1) {
        html += \`<button class="btn btn-secondary" onclick="\${callback.name}(\${(current + 1) * limit})">Next</button>\`;
      }
      el.innerHTML = html;
    }

    function openModal(id) {
      document.getElementById(id).classList.add('active');
    }

    function closeModal(id) {
      document.getElementById(id).classList.remove('active');
    }

    function showToast(message, type = 'success') {
      const toast = document.createElement('div');
      toast.className = \`toast \${type}\`;
      toast.innerHTML = \`<svg class="icon-sm"><use href="#icon-\${type === 'success' ? 'check-circle' : 'x-circle'}"/></svg> \${escapeHtml(message)}\`;
      document.body.appendChild(toast);
      setTimeout(() => {
        toast.classList.add('removing');
        setTimeout(() => toast.remove(), 250);
      }, 2750);
    }

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        document.querySelectorAll('.modal-overlay.active').forEach(m => m.classList.remove('active'));
      }
    });
  </script>
</body>
</html>
`;
