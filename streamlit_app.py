#!/usr/bin/env python3
"""
Streamlit Web Interface for AI Code Quality Analyzer
A modern, interactive web interface for analyzing AI-generated code quality.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import tempfile
import os
import json
from typing import Dict, List
import datetime

# Import our analyzer (assumes the analyzer code is in ai_code_analyzer.py)
try:
    from ai_code_analyzer import AICodeAnalyzer, Severity, Issue
except ImportError:
    st.error("Please ensure ai_code_analyzer.py is in the same directory")
    st.stop()


def setup_page():
    """Configure Streamlit page settings."""
    st.set_page_config(
        page_title="AI Code Quality Analyzer",
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Custom CSS for better styling
    st.markdown("""
        <style>
        .main-header {
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            padding: 2rem;
            border-radius: 10px;
            color: white;
            margin-bottom: 2rem;
        }
        .metric-card {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid #007bff;
            margin: 0.5rem 0;
        }
        .severity-critical {
            border-left-color: #dc3545 !important;
            background-color: #fff5f5 !important;
        }
        .severity-high {
            border-left-color: #fd7e14 !important;
            background-color: #fff8f0 !important;
        }
        .severity-medium {
            border-left-color: #ffc107 !important;
            background-color: #fffbf0 !important;
        }
        .severity-low {
            border-left-color: #28a745 !important;
            background-color: #f8fff8 !important;
        }
        .stTextArea textarea {
            font-family: 'Courier New', monospace;
        }
        </style>
    """, unsafe_allow_html=True)


def create_sample_code() -> str:
    """Return sample problematic code for demonstration."""
    return '''import os
import subprocess
import sys

# Sample AI-generated code with various quality issues
def process_user_data(username, password, email, phone, address, country, age, preferences, settings):
    """This function processes user data"""
    
    # Hardcoded credentials (security issue)
    api_key = "sk-1234567890abcdef"
    secret = "my_secret_password"
    
    # SQL injection vulnerability
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    
    # Dangerous eval usage
    config = eval(open('config.txt').read())
    
    # Inefficient string concatenation
    result = ""
    for i in range(1000):
        result += str(i) + ", "
    
    # Overly broad exception handling
    try:
        # Complex nested logic
        for i in range(10):
            for j in range(10):
                for k in range(10):
                    for l in range(10):
                        if i + j + k + l > 20:
                            print(f"Processing: {i}, {j}, {k}, {l}")
                            
    except Exception:
        pass
    
    # TODO: Fix this later
    # HACK: This is a temporary solution
    
    return result

# Missing docstring function
def another_function():
    exec("print('This is dangerous')")
    
# Long line that exceeds reasonable length limits and should be broken into multiple lines for better readability
def very_long_function_name_that_exceeds_reasonable_limits():
    pass
'''


def analyze_code(code_content: str) -> tuple:
    """Analyze code and return results."""
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code_content)
        temp_file = f.name
    
    try:
        analyzer = AICodeAnalyzer()
        issues = analyzer.analyze_file(temp_file)
        return issues, analyzer.metrics
    finally:
        # Clean up temp file
        os.unlink(temp_file)


def create_severity_chart(issues: List[Issue]) -> go.Figure:
    """Create a pie chart showing issue distribution by severity."""
    severity_counts = {}
    for issue in issues:
        severity_counts[issue.severity.value] = severity_counts.get(issue.severity.value, 0) + 1
    
    if not severity_counts:
        return go.Figure().add_annotation(text="No issues found", showarrow=False)
    
    colors = {
        'critical': '#dc3545',
        'high': '#fd7e14', 
        'medium': '#ffc107',
        'low': '#28a745'
    }
    
    fig = go.Figure(data=[go.Pie(
        labels=list(severity_counts.keys()),
        values=list(severity_counts.values()),
        hole=0.4,
        marker_colors=[colors.get(k, '#007bff') for k in severity_counts.keys()]
    )])
    
    fig.update_layout(
        title="Issues by Severity",
        showlegend=True,
        height=400
    )
    
    return fig


def create_category_chart(issues: List[Issue]) -> go.Figure:
    """Create a bar chart showing issues by category."""
    category_counts = {}
    for issue in issues:
        category_counts[issue.category or 'other'] = category_counts.get(issue.category or 'other', 0) + 1
    
    if not category_counts:
        return go.Figure().add_annotation(text="No issues found", showarrow=False)
    
    fig = go.Figure(data=[go.Bar(
        x=list(category_counts.keys()),
        y=list(category_counts.values()),
        marker_color='#667eea'
    )])
    
    fig.update_layout(
        title="Issues by Category",
        xaxis_title="Category",
        yaxis_title="Count",
        height=400
    )
    
    return fig


def create_line_chart(issues: List[Issue]) -> go.Figure:
    """Create a line chart showing issue distribution across code lines."""
    line_issues = {}
    for issue in issues:
        line_issues[issue.line_number] = line_issues.get(issue.line_number, 0) + 1
    
    if not line_issues:
        return go.Figure().add_annotation(text="No issues found", showarrow=False)
    
    sorted_lines = sorted(line_issues.items())
    
    fig = go.Figure(data=go.Scatter(
        x=[line for line, count in sorted_lines],
        y=[count for line, count in sorted_lines],
        mode='lines+markers',
        marker=dict(size=8, color='#764ba2'),
        line=dict(color='#667eea', width=2)
    ))
    
    fig.update_layout(
        title="Issues Distribution Across Code Lines",
        xaxis_title="Line Number",
        yaxis_title="Issue Count",
        height=400
    )
    
    return fig


def display_issues_table(issues: List[Issue]):
    """Display issues in an interactive table."""
    if not issues:
        st.success("🎉 No issues found! Your code looks great.")
        return
    
    # Convert issues to DataFrame
    issues_data = []
    for issue in issues:
        issues_data.append({
            'Line': issue.line_number,
            'Severity': issue.severity.value.title(),
            'Category': issue.category.title(),
            'Rule ID': issue.rule_id,
            'Message': issue.message,
            'Suggestion': issue.suggestion or 'N/A'
        })
    
    df = pd.DataFrame(issues_data)
    
    # Add severity filtering
    col1, col2 = st.columns(2)
    with col1:
        severity_filter = st.multiselect(
            "Filter by Severity:",
            options=['Critical', 'High', 'Medium', 'Low'],
            default=['Critical', 'High', 'Medium', 'Low']
        )
    
    with col2:
        category_filter = st.multiselect(
            "Filter by Category:",
            options=df['Category'].unique(),
            default=df['Category'].unique()
        )
    
    # Apply filters
    filtered_df = df[
        (df['Severity'].isin(severity_filter)) &
        (df['Category'].isin(category_filter))
    ]
    
    # Display table with color coding
    st.dataframe(
        filtered_df,
        use_container_width=True,
        height=400
    )
    
    # Export functionality
    if st.button("📊 Export Results as CSV"):
        csv = filtered_df.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name=f"code_analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )


def main():
    """Main Streamlit application."""
    setup_page()
    
    # Header
    st.markdown("""
        <div class="main-header">
            <h1>🔍 AI Code Quality Analyzer</h1>
            <p>Analyze your AI-generated code for security, performance, and quality issues</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        analysis_mode = st.radio(
            "Choose Analysis Mode:",
            ["Upload File", "Paste Code", "Use Sample"]
        )
        
        st.markdown("---")
        st.header("📊 Quick Stats")
        
        # Placeholder for stats (will be updated after analysis)
        stats_placeholder = st.empty()
        
        st.markdown("---")
        st.markdown("""
        ### 🛡️ What We Check:
        - **Security**: Dangerous functions, hardcoded secrets
        - **Performance**: Inefficient patterns, complexity
        - **Style**: PEP 8 compliance, line length
        - **Best Practices**: Error handling, documentation
        - **AI-Specific**: Common LLM code issues
        """)
    
    # Main content area
    code_content = ""
    
    if analysis_mode == "Upload File":
        st.subheader("📁 Upload Python File")
        uploaded_file = st.file_uploader(
            "Choose a Python file",
            type=['py'],
            help="Upload a .py file to analyze"
        )
        
        if uploaded_file:
            code_content = uploaded_file.read().decode('utf-8')
            st.code(code_content, language='python')
    
    elif analysis_mode == "Paste Code":
        st.subheader("📝 Paste Your Code")
        code_content = st.text_area(
            "Python Code:",
            height=400,
            placeholder="Paste your Python code here...",
            help="Paste your Python code for analysis"
        )
    
    else:  # Use Sample
        st.subheader("🧪 Sample Code Analysis")
        st.info("Using sample code with intentional quality issues for demonstration")
        code_content = create_sample_code()
        
        with st.expander("View Sample Code"):
            st.code(code_content, language='python')
    
    # Analyze button
    if code_content and st.button("🔍 Analyze Code", type="primary"):
        with st.spinner("Analyzing code..."):
            issues, metrics = analyze_code(code_content)
        
        # Update sidebar stats
        with stats_placeholder.container():
            st.metric("Total Issues", len(issues))
            critical = len([i for i in issues if i.severity == Severity.CRITICAL])
            if critical > 0:
                st.metric("Critical Issues", critical, delta=None, delta_color="inverse")
            else:
                st.metric("Critical Issues", critical)
        
        # Results section
        if issues or True:  # Always show results section
            st.markdown("---")
            st.header("📈 Analysis Results")
            
            # Summary metrics
            col1, col2, col3, col4 = st.columns(4)
            
            severity_counts = {
                'critical': len([i for i in issues if i.severity == Severity.CRITICAL]),
                'high': len([i for i in issues if i.severity == Severity.HIGH]),
                'medium': len([i for i in issues if i.severity == Severity.MEDIUM]),
                'low': len([i for i in issues if i.severity == Severity.LOW])
            }
            
            with col1:
                st.metric("🚨 Critical", severity_counts['critical'])
            with col2:
                st.metric("⚠️ High", severity_counts['high'])
            with col3:
                st.metric("⚡ Medium", severity_counts['medium'])
            with col4:
                st.metric("ℹ️ Low", severity_counts['low'])
            
            # Charts
            if issues:
                st.subheader("📊 Visual Analysis")
                
                col1, col2 = st.columns(2)
                with col1:
                    fig_severity = create_severity_chart(issues)
                    st.plotly_chart(fig_severity, use_container_width=True)
                
                with col2:
                    fig_category = create_category_chart(issues)
                    st.plotly_chart(fig_category, use_container_width=True)
                
                # Line distribution chart
                fig_lines = create_line_chart(issues)
                st.plotly_chart(fig_lines, use_container_width=True)
            
            # Detailed issues table
            st.subheader("🔍 Detailed Issues")
            display_issues_table(issues)
            
            # Recommendations
            if issues:
                st.subheader("💡 Recommendations")
                
                critical_issues = [i for i in issues if i.severity == Severity.CRITICAL]
                if critical_issues:
                    st.error("🚨 **Critical Issues Found!** These should be addressed immediately:")
                    for issue in critical_issues[:3]:  # Show top 3
                        st.markdown(f"- **Line {issue.line_number}**: {issue.message}")
                
                high_issues = [i for i in issues if i.severity == Severity.HIGH]
                if high_issues:
                    st.warning("⚠️ **High Priority Issues** - Address these soon:")
                    for issue in high_issues[:3]:  # Show top 3
                        st.markdown(f"- **Line {issue.line_number}**: {issue.message}")
                
                # General recommendations
                st.info("""
                🎯 **General Recommendations:**
                - Fix critical and high severity issues first
                - Review security-related findings carefully
                - Consider refactoring complex functions
                - Add proper error handling and documentation
                - Test your fixes thoroughly
                """)
    
    # Footer
    st.markdown("---")
    st.markdown("""
        <div style="text-align: center; color: #666;">
            <p>Built with ❤️ using Streamlit | AI Code Quality Analyzer v1.0</p>
            <p>Perfect for analyzing AI-generated code from ChatGPT, Claude, Copilot, and more!</p>
        </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()