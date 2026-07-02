import asyncio
import json
import logging
import os
import re
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Import ADK and Vertex AI
import vertexai
from google.adk.sessions import VertexAiSessionService
from vertexai._genai.types import QueryAgentEngineConfig

# Load dotenv if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = FastAPI(title="AutoPatch Maintainer Dashboard")

# Read env variables
project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
agent_runtime_id = os.environ.get("AGENT_RUNTIME_ID")

if not project_id or not agent_runtime_id:
    raise RuntimeError("Missing GOOGLE_CLOUD_PROJECT or AGENT_RUNTIME_ID in environment")

# Parse region/location and engine_id from agent_runtime_id
location = "us-west1"
engine_id = agent_runtime_id

if "/" in agent_runtime_id:
    parts = agent_runtime_id.split("/")
    if len(parts) >= 6:
        project_id = parts[1]
        location = parts[3]
        engine_id = parts[5]

# Initialize Session Service
session_service = VertexAiSessionService(
    project=project_id,
    location=location,
    agent_engine_id=engine_id,
)

# HTML Template Embedded
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AutoPatch Maintainer Dashboard</title>
    <!-- Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Space+Grotesk:wght@500;700&display=swap" rel="stylesheet">
    <style>
        /* CSS resets and custom variables */
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            background-color: #0A0A0A;
            color: #E5E5E5;
            font-family: 'Inter', sans-serif;
            min-height: 100vh;
            padding-bottom: 80px;
        }
        h1, h2, h3, .stat-number {
            font-family: 'Space Grotesk', sans-serif;
            font-weight: 700;
            letter-spacing: -0.02em;
        }

        /* Top Bar Styling */
        .topbar-wrapper {
            background: radial-gradient(circle at 50% 0%, rgba(182, 255, 59, 0.08) 0%, transparent 60%);
            border-bottom: 1px solid #1A1A1A;
            padding: 16px 24px;
        }
        .topbar-content {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .nav-left {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        .logo-pill {
            background-color: #000000;
            border: 1px solid #2A2A2A;
            border-radius: 9999px;
            padding: 6px 16px 6px 12px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .logo-mark {
            width: 16px;
            height: 16px;
            border-radius: 50%;
            background-color: #B6FF3B;
        }
        .logo-text {
            font-family: 'Space Grotesk', sans-serif;
            font-weight: 700;
            color: #FFFFFF;
            font-size: 14px;
        }
        .nav-buttons {
            display: flex;
            background-color: #161616;
            border: 1px solid #2A2A2A;
            border-radius: 9999px;
            padding: 4px;
        }
        .nav-btn {
            background: transparent;
            border: none;
            color: #888888;
            font-family: 'Inter', sans-serif;
            font-weight: 500;
            font-size: 13px;
            padding: 6px 16px;
            border-radius: 9999px;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .nav-btn.active {
            background-color: #2A2A2A;
            color: #FFFFFF;
        }
        .nav-right {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .search-circle {
            width: 36px;
            height: 36px;
            border-radius: 50%;
            border: 1px solid #2A2A2A;
            background-color: #161616;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #888888;
            cursor: pointer;
        }
        .profile-chip {
            background-color: #161616;
            border: 1px solid #2A2A2A;
            border-radius: 9999px;
            padding: 4px 12px 4px 6px;
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
            font-weight: 500;
            color: #FFFFFF;
        }
        .profile-avatar {
            width: 24px;
            height: 24px;
            border-radius: 50%;
            background-color: #2A2A2A;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #B6FF3B;
            font-weight: 700;
        }

        /* Container */
        .container {
            max-width: 1200px;
            margin: 40px auto 0 auto;
            padding: 0 24px;
        }

        /* Stats Row with Dot-Grid Background */
        .stats-wrapper {
            background-image: radial-gradient(#222222 1px, transparent 1px);
            background-size: 16px 16px;
            border: 1px solid #1A1A1A;
            border-radius: 24px;
            padding: 24px;
            margin-bottom: 40px;
        }
        .stats-row {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
        }
        .stat-card {
            background-color: #161616;
            border: 1px solid #2A2A2A;
            border-radius: 16px;
            padding: 20px;
        }
        .stat-label {
            font-size: 12px;
            font-weight: 500;
            color: #888888;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 8px;
        }
        .stat-value-container {
            display: flex;
            align-items: baseline;
            gap: 10px;
        }
        .stat-number {
            font-size: 36px;
            color: #FFFFFF;
        }
        .stat-delta {
            font-size: 12px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 2px;
        }
        .stat-delta.green {
            color: #B6FF3B;
        }
        .stat-delta.orange {
            color: #FF8A1E;
        }

        /* Timeline Header */
        .timeline-header {
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .timeline-title {
            font-size: 20px;
            color: #FFFFFF;
        }

        /* Issue Timeline Panel */
        .timeline-panel {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        /* Pill Row */
        .session-pill-row {
            display: flex;
            flex-direction: column;
            background-color: #161616;
            border: 1px solid #2A2A2A;
            border-radius: 20px;
            overflow: hidden;
            transition: border-color 0.2s ease;
        }
        .session-pill-header {
            display: grid;
            grid-template-columns: 140px 2fr 1.2fr 150px 40px;
            align-items: center;
            padding: 14px 20px;
            cursor: pointer;
            user-select: none;
        }
        .session-pill-header:hover {
            background-color: #1A1A1A;
        }

        /* Status Badge */
        .status-badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 28px;
            height: 28px;
            border-radius: 50%;
            flex-shrink: 0;
        }
        .status-badge.clean {
            background-color: rgba(182, 255, 59, 0.1);
            color: #B6FF3B;
            border: 1px solid rgba(182, 255, 59, 0.3);
        }
        .status-badge.flagged {
            background-color: rgba(255, 138, 30, 0.1);
            color: #FF8A1E;
            border: 1px solid rgba(255, 138, 30, 0.3);
        }

        .badge-and-id {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .card-id {
            font-family: 'Space Grotesk', sans-serif;
            font-weight: 500;
            font-size: 13px;
            color: #CCCCCC;
        }
        .repo-and-age {
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        .repo-age {
            font-size: 11px;
            color: #666666;
        }

        /* Session metadata fields */
        .issue-title {
            font-weight: 600;
            font-size: 14px;
            color: #FFFFFF;
            padding-right: 20px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .repo-name {
            font-size: 13px;
            color: #888888;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .source-icon {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
            color: #CCCCCC;
        }
        .octocat-svg {
            color: #888888;
        }
        .expand-chevron {
            color: #888888;
            transition: transform 0.2s ease;
            display: flex;
            justify-content: center;
        }
        .session-pill-row.expanded .expand-chevron {
            transform: rotate(180deg);
        }

        /* Expanded Details Card */
        .expanded-details {
            display: none;
            border-top: 1px solid #2A2A2A;
            background-color: #0E0E0E;
            padding: 24px;
        }
        .session-pill-row.expanded .expanded-details {
            display: block;
        }

        /* Grid inside details */
        .details-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-bottom: 24px;
        }
        .details-section-title {
            font-size: 12px;
            font-weight: 500;
            color: #888888;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 12px;
        }
        .root-cause-box {
            background-color: #161616;
            border: 1px solid #2A2A2A;
            border-radius: 12px;
            padding: 16px;
            font-size: 14px;
            line-height: 1.6;
            color: #D5D5D5;
        }

        /* Diff highlight container */
        .diff-wrapper {
            grid-column: span 2;
        }
        .diff-code {
            background-color: #050505;
            border: 1px solid #2A2A2A;
            border-radius: 12px;
            padding: 16px;
            font-family: 'Fira Code', 'Courier New', monospace;
            font-size: 12px;
            line-height: 1.5;
            overflow-x: auto;
            max-height: 350px;
        }
        .diff-line {
            white-space: pre;
            padding: 2px 8px;
            border-radius: 2px;
        }
        .diff-add {
            background-color: rgba(182, 255, 59, 0.1);
            color: #B6FF3B;
        }
        .diff-remove {
            background-color: rgba(255, 138, 30, 0.1);
            color: #FF8A1E;
        }
        .diff-meta {
            color: #666666;
            background-color: rgba(255, 255, 255, 0.02);
        }

        /* Security Findings */
        .findings-list {
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .finding-item {
            background-color: rgba(255, 138, 30, 0.08);
            border: 1px solid rgba(255, 138, 30, 0.2);
            color: #FF8A1E;
            border-radius: 8px;
            padding: 12px 16px;
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        /* Action Buttons */
        .action-bar {
            display: flex;
            justify-content: flex-end;
            gap: 12px;
            border-top: 1px solid #2A2A2A;
            padding-top: 20px;
        }
        .btn {
            font-family: 'Inter', sans-serif;
            font-weight: 600;
            font-size: 14px;
            padding: 12px 24px;
            border-radius: 12px;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s ease;
        }
        .btn-approve {
            background-color: #B6FF3B;
            color: #0A0A0A;
            border: none;
        }
        .btn-approve:hover {
            background-color: #c4ff60;
        }
        .btn-reject {
            background-color: transparent;
            color: #FF8A1E;
            border: 1px solid #FF8A1E;
        }
        .btn-reject:hover {
            background-color: rgba(255, 138, 30, 0.05);
        }
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        /* Agent response inline panel */
        .agent-response-box {
            border-top: 1px solid #2A2A2A;
            margin-top: 20px;
            padding-top: 20px;
        }
        .response-content {
            background-color: #161616;
            border: 1px solid #2A2A2A;
            border-radius: 12px;
            padding: 16px;
            font-family: 'Inter', sans-serif;
            font-size: 14px;
            line-height: 1.6;
            color: #E5E5E5;
            white-space: pre-wrap;
        }

        /* Empty state */
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            border: 1px dashed #2A2A2A;
            border-radius: 20px;
            color: #888888;
        }
        .empty-icon {
            font-size: 32px;
            margin-bottom: 12px;
            color: #B6FF3B;
        }

        /* Spinner */
        .spinner {
            width: 16px;
            height: 16px;
            border: 2px solid transparent;
            border-radius: 50%;
            animation: spin 0.6s linear infinite;
            display: inline-block;
        }
        .spinner-green {
            border-top-color: #0A0A0A;
        }
        .spinner-orange {
            border-top-color: #FF8A1E;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>

    <!-- Top Bar -->
    <div class="topbar-wrapper">
        <div class="topbar-content">
            <div class="nav-left">
                <div class="logo-pill">
                    <div class="logo-mark"></div>
                    <div class="logo-text">AutoPatch</div>
                </div>
                <div class="nav-buttons">
                    <button class="nav-btn active">Dashboard</button>
                    <button class="nav-btn">Issues</button>
                    <button class="nav-btn">Security</button>
                </div>
            </div>
            <div class="nav-right">
                <div class="search-circle">
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M11.5 7a4.499 4.499 0 1 1-8.998 0A4.499 4.499 0 0 1 11.5 7zm-.82 4.74a6 6 0 1 1 1.06-1.06l3.04 3.04a.75.75 0 1 1-1.06 1.06l-3.04-3.04z"/></svg>
                </div>
                <div class="profile-chip">
                    <div class="profile-avatar">M</div>
                    <span>Maintainer</span>
                </div>
            </div>
        </div>
    </div>

    <!-- Main Container -->
    <div class="container">
        <!-- Stats Wrapper -->
        <div class="stats-wrapper">
            <div class="stats-row">
                <div class="stat-card">
                    <div class="stat-label">Pending Review</div>
                    <div class="stat-value-container">
                        <div class="stat-number" id="stat-pending">0</div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Auto-Approved Today</div>
                    <div class="stat-value-container">
                        <div class="stat-number" id="stat-approved">0</div>
                        <div class="stat-delta green">
                            <svg width="10" height="10" viewBox="0 0 10 10" fill="currentColor"><path d="M5 1L9 5H6v4H4V5H1L5 1z"/></svg>
                            <span>+15%</span>
                        </div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Security Flags</div>
                    <div class="stat-value-container">
                        <div class="stat-number" id="stat-flagged">0</div>
                        <div class="stat-delta orange">
                            <svg width="10" height="10" viewBox="0 0 10 10" fill="currentColor"><path d="M5 1L9 5H6v4H4V5H1L5 1z"/></svg>
                            <span>+4%</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Issue Timeline -->
        <div class="timeline-header">
            <h2 class="timeline-title">Pending Approvals</h2>
        </div>

        <div class="timeline-panel" id="timeline-list">
            <!-- Loading State -->
            <div class="empty-state">
                <div class="empty-icon">⚡</div>
                <p>Loading pending reviews from Agent Runtime...</p>
            </div>
        </div>
    </div>

    <script>
        let expandedSessionId = null;
        let pendingSessions = [];

        function escapeHtml(unsafe) {
            return unsafe
                 .replace(/&/g, "&amp;")
                 .replace(/</g, "&lt;")
                 .replace(/>/g, "&gt;")
                 .replace(/"/g, "&quot;")
                 .replace(/'/g, "&#039;");
        }

        function highlightDiff(diffText) {
            if (!diffText) return '<div class="diff-line">No proposed diff for this session.</div>';
            const lines = diffText.split('\n');
            return lines.map(line => {
                let cls = '';
                if (line.startsWith('+')) cls = 'diff-add';
                else if (line.startsWith('-')) cls = 'diff-remove';
                else if (line.startsWith('@@')) cls = 'diff-meta';
                return `<div class="diff-line ${cls}">${escapeHtml(line)}</div>`;
            }).join('');
        }

        async function fetchPending() {
            try {
                const response = await fetch('/api/pending');
                const data = await response.json();

                // Update stats
                document.getElementById('stat-pending').innerText = data.stats.pending_review;
                document.getElementById('stat-approved').innerText = data.stats.auto_approved_today;
                document.getElementById('stat-flagged').innerText = data.stats.security_flags;

                pendingSessions = data.sessions;
                renderTimeline();
            } catch (err) {
                console.error("Error fetching pending:", err);
            }
        }

        function toggleExpand(sessionId) {
            const row = document.getElementById(`session-${sessionId}`);
            if (expandedSessionId === sessionId) {
                expandedSessionId = null;
                row.classList.remove('expanded');
            } else {
                if (expandedSessionId) {
                    const prev = document.getElementById(`session-${expandedSessionId}`);
                    if (prev) prev.classList.remove('expanded');
                }
                expandedSessionId = sessionId;
                row.classList.add('expanded');
            }
        }

        async function takeAction(sessionId, interruptId, approved, invocationId) {
            const btnApprove = document.getElementById(`btn-approve-${invocationId}`);
            const btnReject = document.getElementById(`btn-reject-${invocationId}`);

            // Disable buttons and show spinner
            btnApprove.disabled = true;
            btnReject.disabled = true;

            const spinnerId = approved ? `spinner-approve-${invocationId}` : `spinner-reject-${invocationId}`;
            const labelId = approved ? `label-approve-${invocationId}` : `label-reject-${invocationId}`;

            document.getElementById(spinnerId).style.display = 'inline-block';
            document.getElementById(labelId).style.display = 'none';

            try {
                const response = await fetch(`/api/action/${sessionId}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        interrupt_id: interruptId,
                        approved: approved,
                        invocation_id: invocationId
                    })
                });

                const result = await response.json();

                // Render agent final response inline
                const responsePanel = document.getElementById(`agent-response-${invocationId}`);
                responsePanel.innerHTML = `
                    <div class="agent-response-box">
                        <div class="details-section-title">Agent Final Output</div>
                        <div class="response-content">${escapeHtml(result.response)}</div>
                    </div>
                `;
            } catch (err) {
                alert(`Error executing action: ${err}`);
                btnApprove.disabled = false;
                btnReject.disabled = false;
                document.getElementById(spinnerId).style.display = 'none';
                document.getElementById(labelId).style.display = 'inline';
            }
        }

        function renderTimeline() {
            const container = document.getElementById('timeline-list');
            if (pendingSessions.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-icon">✓</div>
                        <p>No pending review sessions found. All clean!</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = pendingSessions.map(session => {
                const isFlagged = session.security_findings && session.security_findings.length > 0;
                const isExpanded = expandedSessionId === session.invocation_id;

                const findingsHtml = isFlagged
                    ? session.security_findings.map(f => `
                        <li class="finding-item">
                            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0c-.22 0-.43.08-.6.22L1.22 5c-.14.12-.22.3-.22.49v5.02c0 3.73 4.2 5.09 6.64 5.47a1.004 1.004 0 0 0 .72 0C10.8 15.6 15 14.24 15 10.51V5.49c0-.19-.08-.37-.22-.49L8.6 0.22A1.003 1.003 0 0 0 8 0z"/></svg>
                            <span>${escapeHtml(f)}</span>
                        </li>
                    `).join('')
                    : `<li class="finding-item" style="background-color: rgba(182, 255, 59, 0.08); border-color: rgba(182, 255, 59, 0.2); color: #B6FF3B;">✓ Clean session. No security findings.</li>`;

                return `
                    <div class="session-pill-row ${isExpanded ? 'expanded' : ''}" id="session-${session.invocation_id}">
                        <div class="session-pill-header" onclick="toggleExpand('${session.invocation_id}')">
                            <div class="badge-and-id">
                                <span class="status-badge ${isFlagged ? 'flagged' : 'clean'}">
                                    ${isFlagged
                                        ? '<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0c-.22 0-.43.08-.6.22L1.22 5c-.14.12-.22.3-.22.49v5.02c0 3.73 4.2 5.09 6.64 5.47a1.004 1.004 0 0 0 .72 0C10.8 15.6 15 14.24 15 10.51V5.49c0-.19-.08-.37-.22-.49L8.6 0.22A1.003 1.003 0 0 0 8 0z"/></svg>'
                                        : '<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M13.78 4.22a.75.75 0 0 1 0 1.06l-7.25 7.25a.75.75 0 0 1-1.06 0L2.22 9.28a.75.75 0 0 1 1.06-1.06L6 10.94l6.72-6.72a.75.75 0 0 1 1.06 0z"/></svg>'
                                    }
                                </span>
                                <span class="card-id">${escapeHtml(session.display_id)}</span>
                            </div>
                            <div class="issue-title" title="${escapeHtml(session.issue_title)}">${escapeHtml(session.issue_title)}</div>
                            <div class="repo-and-age">
                                <span class="repo-name">${escapeHtml(session.repo_full_name)}</span>
                                <span class="repo-age">${escapeHtml(session.age)}</span>
                            </div>
                            <div class="source-icon">
                                <svg class="octocat-svg" width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.21-1.61.55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.35 3.12.91 0 .68.01 1.24.01 1.41 0 .21-.15.46-.55.38A8.013 8.013 0 0 1 16 8c0-4.42-3.58-8-8-8z"/></svg>
                                <span>GitHub</span>
                            </div>
                            <div class="expand-chevron">
                                <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor"><path d="M1.5 5.25a.75.75 0 0 1 1.06 0L8 10.69l5.44-5.44a.75.75 0 1 1 1.06 1.06l-6 6a.75.75 0 0 1-1.06 0l-6-6a.75.75 0 0 1 0-1.06z"/></svg>
                            </div>
                        </div>
                        <div class="expanded-details">
                            <div class="details-grid">
                                <div>
                                    <div class="details-section-title">Root Cause Summary</div>
                                    <div class="root-cause-box">${escapeHtml(session.root_cause_summary)}</div>
                                </div>
                                <div>
                                    <div class="details-section-title">Security Status</div>
                                    <ul class="findings-list">${findingsHtml}</ul>
                                </div>
                                <div class="diff-wrapper">
                                    <div class="details-section-title">Proposed Patch Diff</div>
                                    <div class="diff-code">${highlightDiff(session.diff)}</div>
                                </div>
                            </div>
                            <div id="agent-response-${session.invocation_id}"></div>
                            <div class="action-bar" id="action-bar-${session.invocation_id}">
                                <button class="btn btn-reject" id="btn-reject-${session.invocation_id}" onclick="takeAction('${session.session_id}', '${session.interrupt_id}', false, '${session.invocation_id}')">
                                    <span class="spinner spinner-orange" id="spinner-reject-${session.invocation_id}" style="display: none;"></span>
                                    <span id="label-reject-${session.invocation_id}">Reject Patch</span>
                                </button>
                                <button class="btn btn-approve" id="btn-approve-${session.invocation_id}" onclick="takeAction('${session.session_id}', '${session.interrupt_id}', true, '${session.invocation_id}')">
                                    <span class="spinner spinner-green" id="spinner-approve-${session.invocation_id}" style="display: none;"></span>
                                    <span id="label-approve-${session.invocation_id}">Approve & Merge</span>
                                </button>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
        }

        // Initial fetch and start polling
        fetchPending();
        setInterval(fetchPending, 5000);
    </script>
</body>
</html>
"""

def format_relative_time(timestamp: float) -> str:
    import datetime
    now = datetime.datetime.now(datetime.UTC).timestamp()
    diff = now - timestamp
    if diff < 0:
        diff = 0
    if diff < 60:
        return "Just now"
    elif diff < 3600:
        mins = int(diff / 60)
        return f"{mins}m ago" if mins > 1 else "1m ago"
    elif diff < 86400:
        hours = int(diff / 3600)
        return f"{hours}h ago" if hours > 1 else "1h ago"
    else:
        days = int(diff / 86400)
        return f"{days}d ago" if days > 1 else "1d ago"

def parse_message_fields(message: str):
    # Normalize newlines to prevent matching failures
    message = message.replace("\r\n", "\n")

    root_cause = "No root cause summary available."
    diff = ""
    title_override = None

    # Extract Issue Title
    title_match = re.search(r"Issue Title:\s*(.*)", message)
    if title_match:
        title_override = title_match.group(1).strip()

    # Extract Root Cause Summary
    rc_match = re.search(r"## Root Cause Summary\n(.*?)(?=\n##|$)", message, re.DOTALL)
    if rc_match:
        root_cause = rc_match.group(1).strip()

    # Extract Diff
    diff_match = re.search(r"## Proposed Changes\n```diff\n(.*?)\n```", message, re.DOTALL)
    if diff_match:
        diff = diff_match.group(1).strip()
    else:
        diff_match = re.search(r"## Proposed Changes\n```\n(.*?)\n```", message, re.DOTALL)
        if diff_match:
            diff = diff_match.group(1).strip()

    # Clean/nullify if prompt injection is detected to avoid cross-contamination
    if title_override and "prompt injection" in title_override.lower():
        root_cause = "Prompt injection attempt detected and blocked. The session has been halted to prevent execution of unauthorized commands."
        diff = ""

    return title_override, root_cause, diff

class ActionPayload(BaseModel):
    interrupt_id: str
    approved: bool
    invocation_id: str | None = None

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    return HTMLResponse(content=DASHBOARD_HTML)

@app.get("/api/pending")
async def get_pending():
    try:
        # We list all sessions with user_id=None because that returns all sessions on Vertex AI
        resp = await session_service.list_sessions(app_name="autopatch", user_id=None)

        import datetime
        today_start = datetime.datetime.now(datetime.UTC).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()

        auto_approved_today = 0
        security_flags = 0
        pending_list = []

        async def process_session(s) -> list[dict[str, Any]]:
            nonlocal auto_approved_today, security_flags

            full_session = await session_service.get_session(
                app_name="autopatch",
                user_id=s.user_id,
                session_id=s.id
            )
            if not full_session:
                return []

            state = full_session.state or {}

            # Stats updates
            if state.get("pull_request_created") is True and full_session.last_update_time >= today_start:
                auto_approved_today += 1

            findings = state.get("security_findings") or []
            is_flagged = False
            if isinstance(findings, str):
                findings_str = findings.strip()
                if findings_str and findings_str.lower() not in ("clean", "[]", "none"):
                    is_flagged = True
            elif isinstance(findings, list) and len(findings) > 0:
                is_flagged = True

            if is_flagged:
                security_flags += 1

            # 1. Find resolved invocation IDs
            resolved_invocations = set()
            for event in full_session.events:
                if event.author == "user" and event.content and event.content.parts:
                    for part in event.content.parts:
                        if part.function_response and part.function_response.name == "adk_request_input":
                            resolved_invocations.add(event.invocation_id)

            # 2. Find unresolved interrupts
            unresolved_interrupts = []
            for event in full_session.events:
                if event.content and event.content.parts:
                    for part in event.content.parts:
                        if part.function_call and part.function_call.name == "adk_request_input":
                            if event.invocation_id not in resolved_invocations:
                                args = part.function_call.args or {}
                                message_arg = args.get("message") or ""
                                interrupt_id = args.get("interruptId") or "approved"
                                unresolved_interrupts.append({
                                    "invocation_id": event.invocation_id,
                                    "interrupt_id": interrupt_id,
                                    "message": message_arg,
                                    "event_timestamp": event.timestamp or full_session.last_update_time
                                })

            # 3. For each unresolved interrupt, build the pending review record
            session_pending = []
            for item in unresolved_interrupts:
                target_inv_id = item["invocation_id"]
                message_arg = item["message"]

                # Extract title, root_cause_summary, diff from message_arg
                title_override, root_cause, diff = parse_message_fields(message_arg)

                title = title_override or "Untitled Issue"
                repo_full_name = "unknown/repo"
                issue_number = None

                # Find user event for this invocation to get repo name and issue number
                user_event = next((e for e in full_session.events if e.invocation_id == target_inv_id and e.author == "user"), None)
                if user_event and user_event.content and user_event.content.parts:
                    for part in user_event.content.parts:
                        if part.text:
                            try:
                                payload = json.loads(part.text)
                                if not title_override:
                                    title = payload.get("title") or title
                                repo_full_name = payload.get("repo_full_name") or repo_full_name
                                issue_number = payload.get("issue_number")
                            except Exception:
                                if not title_override:
                                    title = part.text or title

                # Determine display ID (issue number if present, else first 8 chars of session_id)
                display_id = f"Issue #{issue_number}" if issue_number is not None else f"ID: {full_session.id[:8]}"

                # Compute relative age
                age = format_relative_time(item["event_timestamp"])

                # Security findings mapping
                findings_list = []
                is_injection = "prompt injection" in title.lower() or "prompt injection" in message_arg.lower()
                if is_injection:
                    findings_list = ["Prompt injection attempt detected and blocked."]
                else:
                    if isinstance(findings, str):
                        findings_str = findings.strip()
                        if findings_str and findings_str.lower() not in ("clean", "[]", "none"):
                            try:
                                parsed = json.loads(findings_str)
                                if isinstance(parsed, list):
                                    findings_list = [str(f) for f in parsed]
                                else:
                                    findings_list = [findings_str]
                            except Exception:
                                findings_list = [findings_str]
                    elif isinstance(findings, list):
                        findings_list = [str(f) for f in findings]
                    elif findings:
                        findings_list = [str(findings)]

                session_pending.append({
                    "session_id": full_session.id,
                    "invocation_id": target_inv_id,
                    "display_id": display_id,
                    "age": age,
                    "interrupt_id": item["interrupt_id"],
                    "issue_title": title,
                    "repo_full_name": repo_full_name,
                    "root_cause_summary": root_cause,
                    "diff": diff,
                    "security_findings": findings_list,
                    "last_updated": item["event_timestamp"],
                })

            return session_pending

        # Fetch all session details concurrently
        tasks = [process_session(s) for s in resp.sessions]
        results = await asyncio.gather(*tasks)
        pending_list = []
        for r in results:
            pending_list.extend(r)

        # Sort pending sessions by last updated time descending
        pending_list.sort(key=lambda x: x["last_updated"], reverse=True)

        return {
            "sessions": pending_list,
            "stats": {
                "pending_review": len(pending_list),
                "auto_approved_today": auto_approved_today,
                "security_flags": security_flags
            }
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/action/{session_id}")
async def take_action(session_id: str, payload: ActionPayload):
    try:
        try:
            session = await session_service.get_session(
                app_name="autopatch",
                user_id="default-user",
                session_id=session_id
            )
        except ValueError:
            session = await session_service.get_session(
                app_name="autopatch",
                user_id="vais-query-reasoning-engine",
                session_id=session_id
            )
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        last_invocation_id = payload.invocation_id
        if not last_invocation_id:
            if session.events:
                for event in reversed(session.events):
                    if event.invocation_id:
                        last_invocation_id = event.invocation_id
                        break

        if not last_invocation_id:
            last_invocation_id = ""

        # 2. Construct the resume message.
        # Pass: role: user, parts: [function_response: {id: interrupt_id, name: adk_request_input, response: {approved: True/False}}]
        message = {
            "role": "user",
            "parts": [
                {
                    "function_response": {
                        "id": payload.interrupt_id,
                        "name": "adk_request_input",
                        "response": {
                            "result": "approve" if payload.approved else "reject"
                        }
                    }
                }
            ]
        }

        # 3. Call remote reasoning engine using the vertexai Client
        client = vertexai.Client(project=project_id, location=location)
        engine_name = f"projects/{project_id}/locations/{location}/reasoningEngines/{engine_id}"

        # Resume the session by calling async_stream_query remotely.
        # Set user_id strictly to "default-user".
        config = QueryAgentEngineConfig(
            class_method="async_stream_query",
            input={
                "message": message,
                "user_id": "default-user",
                "session_id": session_id,
                "invocation_id": last_invocation_id
            }
        )

        # Run the async stream query remotely
        response_stream = client.agent_engines._async_stream_query(name=engine_name, config=config)
        final_text = ""
        async for event_dict in response_stream:
            if isinstance(event_dict, dict):
                content = event_dict.get("content")
                if content and isinstance(content, dict):
                    parts = content.get("parts") or []
                    t_parts = [p.get("text") for p in parts if p.get("text")]
                    if t_parts:
                        final_text = "\n".join(t_parts)

        if not final_text:
            final_text = "Action processed. Check the pull requests or comments for changes."

        return {"status": "success", "response": final_text}

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


def normalize_webhook_payload(payload: Any) -> Any:
    """Normalizes GitHub webhook payload.

    Extracts the payload from a 'data' key if base64-encoded or string.
    """
    import base64
    if isinstance(payload, dict) and "data" in payload:
        inner = payload["data"]
        if isinstance(inner, str):
            try:
                decoded_bytes = base64.b64decode(inner.strip(), validate=True)
                decoded_str = decoded_bytes.decode("utf-8")
                try:
                    return json.loads(decoded_str)
                except json.JSONDecodeError:
                    return decoded_str
            except Exception:
                try:
                    return json.loads(inner)
                except json.JSONDecodeError:
                    return inner
        return inner
    return payload


async def run_workflow_task(payload: Any):
    logger.info("Starting AutoPatch ADK workflow run from webhook event (dashboard transform).")
    try:
        normalized_payload = normalize_webhook_payload(payload)

        # Extract metadata to create a descriptive session_id
        repo_name = None
        issue_num = None
        if isinstance(normalized_payload, dict):
            repo_name = normalized_payload.get("repo_full_name")
            if not repo_name:
                repo_dict = normalized_payload.get("repository")
                if isinstance(repo_dict, dict):
                    repo_name = repo_dict.get("full_name")

            issue_num = normalized_payload.get("issue_number")
            if issue_num is None:
                issue_dict = normalized_payload.get("issue")
                if isinstance(issue_dict, dict):
                    issue_num = issue_dict.get("number")

        if repo_name and issue_num:
            clean_repo = str(repo_name).replace("/", "-").lower()
            session_id = f"session-{clean_repo}-{issue_num}"
        else:
            import uuid
            session_id = f"session-{uuid.uuid4()}".lower()

        user_id = "default-user"

        # Prepare the message content for ADK workflow with structured dictionary payload
        message = {
            "role": "user",
            "parts": [
                {
                    "function_response": {
                        "name": "webhook_event",
                        "response": normalized_payload,
                    }
                }
            ],
        }

        # Create session first using the initialized session_service
        logger.info(f"Creating session {session_id} in Vertex AI...")
        try:
            await session_service.create_session(
                app_name="autopatch",
                user_id=user_id,
                session_id=session_id,
            )
            logger.info(f"Session {session_id} created successfully.")
        except Exception as create_err:
            logger.warning(f"Could not create session {session_id} (it may already exist): {create_err}")

        logger.info(f"Triggering ADK workflow for session_id: {session_id}, user_id: {user_id}")

        # Call remote reasoning engine using the vertexai Client
        client = vertexai.Client(project=project_id, location=location)
        engine_name = f"projects/{project_id}/locations/{location}/reasoningEngines/{engine_id}"

        config = QueryAgentEngineConfig(
            class_method="async_stream_query",
            input={
                "message": message,
                "user_id": user_id,
                "session_id": session_id,
            }
        )

        response_stream = client.agent_engines._async_stream_query(name=engine_name, config=config)
        async for event in response_stream:
            # Consume the stream so that Agent Runtime executes the workflow to completion
            if isinstance(event, dict):
                content = event.get("content")
                if content and isinstance(content, dict):
                    parts = content.get("parts") or []
                    for part in parts:
                        if part.get("text"):
                            logger.info(f"[{session_id}] Event text: {part.get('text')}")

        logger.info(f"ADK workflow for session_id: {session_id} finished successfully.")
    except Exception as e:
        logger.exception(f"Error running ADK workflow for webhook: {e}")


@app.post("/webhook")
async def receive_webhook(request: Request, background_tasks: BackgroundTasks):
    try:
        payload = await request.json()
    except Exception as e:
        logger.error(f"Failed to parse incoming request JSON: {e}")
        return {"status": "error", "message": "Invalid JSON body"}

    background_tasks.add_task(run_workflow_task, payload)
    return {"status": "accepted"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
