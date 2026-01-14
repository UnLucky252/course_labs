#!/bin/bash

# Установите путь к корневой директории проекта
PROJECT_ROOT="$(pwd)/.."
REPORT_DIR="${PROJECT_ROOT}/unified_reports"
mkdir -p "${REPORT_DIR}"

# Функция для извлечения данных из SCA (Dependency Check)
parse_sca_reports() {
    local sca_dir="${PROJECT_ROOT}/sca/dependency-check-report"
    local output_json="${REPORT_DIR}/sca_data.json"
    
    if [ -f "${sca_dir}/dependency-check-report.json" ]; then
        cp "${sca_dir}/dependency-check-report.json" "${output_json}"
    elif [ -f "${sca_dir}/dependency-check-gitlab.json" ]; then
        cp "${sca_dir}/dependency-check-gitlab.json" "${output_json}"
    else
        echo '{"dependencies": []}' > "${output_json}"
    fi
    
    echo "${output_json}"
}

# Функция для извлечения данных из SAST (Checkov)
parse_checkov_report() {
    local checkov_dir="${PROJECT_ROOT}/sast/checkov-report.json"
    local output_json="${REPORT_DIR}/checkov_data.json"
    
    if [ -f "${checkov_dir}/results_json.json" ]; then
        cp "${checkov_dir}/results_json.json" "${output_json}"
    else
        echo '{"results": {"passed_checks": [], "failed_checks": [], "skipped_checks": []}}' > "${output_json}"
    fi
    
    echo "${output_json}"
}

# Функция для извлечения данных из SAST (Semgrep)
parse_semgrep_report() {
    local semgrep_file="${PROJECT_ROOT}/sast/semgrep-report.json"
    local output_json="${REPORT_DIR}/semgrep_data.json"
    
    if [ -f "${semgrep_file}" ]; then
        cp "${semgrep_file}" "${output_json}"
    else
        echo '{"results": []}' > "${output_json}"
    fi
    
    echo "${output_json}"
}

# Функция для создания единого JSON отчета
create_unified_json() {
    local sca_file="$1"
    local checkov_file="$2"
    local semgrep_file="$3"
    local output_json="${REPORT_DIR}/unified_report.json"
    
    # Читаем содержимое файлов
    local sca_content=$(cat "${sca_file}")
    local checkov_content=$(cat "${checkov_file}")
    local semgrep_content=$(cat "${semgrep_file}")
    
    # Если файлы пустые, создаем пустые структуры
    [ -z "$sca_content" ] && sca_content='{"dependencies": []}'
    [ -z "$checkov_content" ] && checkov_content='{"results": {"passed_checks": [], "failed_checks": [], "skipped_checks": []}}'
    [ -z "$semgrep_content" ] && semgrep_content='{"results": []}'
    
    cat > "${output_json}" << EOF
{
  "report_metadata": {
    "generated_at": "$(date -Iseconds)",
    "report_type": "unified_security_scan",
    "tools_included": ["dependency-check", "checkov", "semgrep"]
  },
  "summary": {
    "total_vulnerabilities": 0,
    "by_severity": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 0
    },
    "by_tool": {
      "dependency-check": 0,
      "checkov": 0,
      "semgrep": 0
    }
  },
  "sca_results": ${sca_content},
  "sast_results": {
    "checkov": ${checkov_content},
    "semgrep": ${semgrep_content}
  }
}
EOF
    
    # Обновляем summary
    update_summary "${output_json}"
    
    echo "${output_json}"
}

# Функция для обновления summary в JSON
update_summary() {
    local json_file="$1"
    
    if command -v jq &> /dev/null; then
        # Подсчет с использованием jq
        local sca_count=$(jq '.sca_results.dependencies | length' "${json_file}" 2>/dev/null || echo "0")
        local checkov_count=$(jq '.sast_results.checkov.results.failed_checks | length' "${json_file}" 2>/dev/null || echo "0")
        local semgrep_count=$(jq '.sast_results.semgrep.results | length' "${json_file}" 2>/dev/null || echo "0")
        
        local total=$((sca_count + checkov_count + semgrep_count))
        
        # Создаем временный файл с обновленными значениями
        jq --argjson sca "${sca_count}" \
           --argjson checkov "${checkov_count}" \
           --argjson semgrep "${semgrep_count}" \
           --argjson total "${total}" \
        '.summary.total_vulnerabilities = $total |
         .summary.by_tool."dependency-check" = $sca |
         .summary.by_tool.checkov = $checkov |
         .summary.by_tool.semgrep = $semgrep' \
        "${json_file}" > "${json_file}.tmp" && mv "${json_file}.tmp" "${json_file}"
    fi
}

# Функция для создания CSV отчета
create_unified_csv() {
    local json_file="$1"
    local output_csv="${REPORT_DIR}/unified_report.csv"
    
    # Заголовок CSV
    echo "Tool,Scan Type,Severity,Component/File,Description,Location,ID" > "${output_csv}"
    
    if command -v jq &> /dev/null; then
        # Извлекаем SCA данные
        jq -r '
            .sca_results.dependencies[]? | 
            select(.vulnerabilities != null and .vulnerabilities != []) | 
            . as $dep | 
            .vulnerabilities[]? | 
            ["dependency-check", "SCA", (.severity // "UNKNOWN"), ($dep.fileName // "Unknown"), 
             (.name // .description // "No description"), ($dep.filePath // "Unknown"), 
             (.name // .cve // "N/A")] | @csv
        ' "${json_file}" >> "${output_csv}"
        
        # Извлекаем Checkov данные
        jq -r '
            .sast_results.checkov.results.failed_checks[]? | 
            ["checkov", "SAST", (.check_class // .check_type // "UNKNOWN"), 
             (.resource // "Unknown"), (.check_name // "No check name"), 
             (.file_path // "Unknown"), (.check_id // "N/A")] | @csv
        ' "${json_file}" >> "${output_csv}"
        
        # Извлекаем Semgrep данные
        jq -r '
            .sast_results.semgrep.results[]? | 
            ["semgrep", "SAST", (.extra.severity // .extra.metadata.severity // "UNKNOWN"), 
             (.path // "Unknown"), (.extra.message // "No message"), 
             "Line \(.start.line)", (.check_id // .rule_id // "N/A")] | @csv
        ' "${json_file}" >> "${output_csv}"
    fi
    
    # Если CSV пустой, добавляем сообщение
    if [ ! -s "${output_csv}" ] || [ $(wc -l < "${output_csv}") -eq 1 ]; then
        echo "dependency-check,SCA,INFO,No vulnerabilities found,N/A,N/A,N/A" >> "${output_csv}"
        echo "checkov,SAST,INFO,No vulnerabilities found,N/A,N/A,N/A" >> "${output_csv}"
        echo "semgrep,SAST,INFO,No vulnerabilities found,N/A,N/A,N/A" >> "${output_csv}"
    fi
    
    echo "${output_csv}"
}

# Функция для создания HTML отчета с использованием Python
create_unified_html_with_python() {
    local csv_file="$1"
    local output_html="${REPORT_DIR}/unified_report.html"
    
    echo "Creating HTML report using Python..."
    
    # Создаем простой Python скрипт для генерации HTML
    python3 << EOF > "${output_html}"
import csv
import html

def read_csv_data(csv_file):
    """Читаем CSV файл и возвращаем данные по категориям"""
    data = {
        'dependency-check': [],
        'checkov': [],
        'semgrep': []
    }
    
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            headers = next(reader)  # Пропускаем заголовок
            
            for row in reader:
                if len(row) < 7:
                    continue
                
                tool = row[0].strip('"')
                if tool in data:
                    # Экранируем HTML символы
                    escaped_row = [html.escape(cell) for cell in row]
                    data[tool].append(escaped_row)
    
    except Exception as e:
        print(f"Error reading CSV: {e}")
    
    return data

def generate_html(csv_file, output_html):
    """Генерируем HTML отчет"""
    data = read_csv_data(csv_file)
    
    # Подсчитываем статистику
    total_sca = len(data['dependency-check'])
    total_checkov = len(data['checkov'])
    total_semgrep = len(data['semgrep'])
    total_all = total_sca + total_checkov + total_semgrep
    
    # Создаем HTML
    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Unified Security Scan Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 2px solid #4CAF50;
            padding-bottom: 10px;
        }}
        .summary {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }}
        .summary-card {{
            background: white;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .summary-card .count {{
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .tool-section {{
            margin: 25px 0;
            padding: 15px;
            background: #fff;
            border-radius: 5px;
            border: 1px solid #ddd;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
            font-size: 14px;
        }}
        th {{
            background-color: #4CAF50;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .severity {{
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 12px;
            text-align: center;
            display: inline-block;
            min-width: 70px;
        }}
        .severity-CRITICAL {{ background-color: #dc3545; color: white; }}
        .severity-HIGH {{ background-color: #fd7e14; color: white; }}
        .severity-MEDIUM {{ background-color: #ffc107; color: #212529; }}
        .severity-LOW {{ background-color: #28a745; color: white; }}
        .severity-INFO {{ background-color: #17a2b8; color: white; }}
        .cve-id {{
            font-family: monospace;
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 12px;
        }}
        .location {{
            font-size: 12px;
            color: #666;
            font-family: monospace;
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        .timestamp {{
            color: #666;
            font-style: italic;
            margin-bottom: 20px;
        }}
        .export-links {{
            margin: 20px 0;
        }}
        .export-links a {{
            display: inline-block;
            margin-right: 10px;
            padding: 8px 16px;
            background: #4CAF50;
            color: white;
            text-decoration: none;
            border-radius: 4px;
        }}
        .export-links a:hover {{
            background: #45a049;
        }}
        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            table {{
                display: block;
                overflow-x: auto;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Unified Security Scan Report</h1>
        <div class="timestamp">Generated on: {html.escape(str(import datetime; datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))) if 'datetime' in locals() else ''}</div>
        
        <div class="export-links">
            <a href="unified_report.json" download>Download JSON</a>
            <a href="unified_report.csv" download>Download CSV</a>
        </div>
        
        <div class="summary">
            <h2>Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Total Findings</h3>
                    <div class="count">{total_all}</div>
                </div>
                <div class="summary-card">
                    <h3>Dependency Check (SCA)</h3>
                    <div class="count">{total_sca}</div>
                </div>
                <div class="summary-card">
                    <h3>Checkov</h3>
                    <div class="count">{total_checkov}</div>
                </div>
                <div class="summary-card">
                    <h3>Semgrep</h3>
                    <div class="count">{total_semgrep}</div>
                </div>
            </div>
        </div>
'''
    
    # Добавляем SCA данные
    if total_sca > 0:
        html_content += f'''
        <div class="tool-section">
            <h2>Software Composition Analysis (Dependency Check) - {total_sca} findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Component</th>
                        <th>Description</th>
                        <th>Location</th>
                        <th>CVE ID</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for row in data['dependency-check'][:50]:  # Показываем первые 50 записей
            severity = row[2] if len(row) > 2 else ""
            component = row[3] if len(row) > 3 else ""
            description = row[4] if len(row) > 4 else ""
            location = row[5] if len(row) > 5 else ""
            cve_id = row[6] if len(row) > 6 else ""
            
            html_content += f'''
                    <tr>
                        <td><span class="severity severity-{severity}">{severity}</span></td>
                        <td><strong>{component}</strong></td>
                        <td>{description}</td>
                        <td class="location" title="{location}">{location[:80]}{"..." if len(location) > 80 else ""}</td>
                        <td><span class="cve-id">{cve_id}</span></td>
                    </tr>'''
        
        html_content += '''
                </tbody>
            </table>'''
        
        if total_sca > 50:
            html_content += f'<p style="text-align: center; color: #666;">Showing first 50 of {total_sca} SCA findings. Download CSV for complete list.</p>'
        
        html_content += '</div>'
    
    # Добавляем Checkov данные
    if total_checkov > 0:
        html_content += f'''
        <div class="tool-section">
            <h2>Infrastructure as Code Security (Checkov) - {total_checkov} findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Resource</th>
                        <th>Check Name</th>
                        <th>File</th>
                        <th>Check ID</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for row in data['checkov']:
            severity = row[2] if len(row) > 2 else ""
            resource = row[3] if len(row) > 3 else ""
            check_name = row[4] if len(row) > 4 else ""
            file_path = row[5] if len(row) > 5 else ""
            check_id = row[6] if len(row) > 6 else ""
            
            # Определяем класс severity для Checkov
            severity_class = "INFO"
            if "CRITICAL" in severity.upper():
                severity_class = "CRITICAL"
            elif "HIGH" in severity.upper():
                severity_class = "HIGH"
            elif "MEDIUM" in severity.upper():
                severity_class = "MEDIUM"
            elif "LOW" in severity.upper():
                severity_class = "LOW"
            
            html_content += f'''
                    <tr>
                        <td><span class="severity severity-{severity_class}">{severity}</span></td>
                        <td><strong>{resource}</strong></td>
                        <td>{check_name}</td>
                        <td class="location">{file_path}</td>
                        <td><span class="cve-id">{check_id}</span></td>
                    </tr>'''
        
        html_content += '''
                </tbody>
            </table>
        </div>'''
    
    # Добавляем Semgrep данные
    if total_semgrep > 0:
        html_content += f'''
        <div class="tool-section">
            <h2>Static Application Security Testing (Semgrep) - {total_semgrep} findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>File</th>
                        <th>Message</th>
                        <th>Location</th>
                        <th>Rule ID</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for row in data['semgrep']:
            severity = row[2] if len(row) > 2 else ""
            file_path = row[3] if len(row) > 3 else ""
            message = row[4] if len(row) > 4 else ""
            location = row[5] if len(row) > 5 else ""
            rule_id = row[6] if len(row) > 6 else ""
            
            html_content += f'''
                    <tr>
                        <td><span class="severity severity-{severity}">{severity}</span></td>
                        <td><strong>{file_path}</strong></td>
                        <td>{message}</td>
                        <td>{location}</td>
                        <td><span class="cve-id">{rule_id}</span></td>
                    </tr>'''
        
        html_content += '''
                </tbody>
            </table>
        </div>'''
    
    # Закрываем HTML
    html_content += '''
        <div style="text-align: center; margin-top: 30px; color: #666; font-size: 12px;">
            <p>Generated by Unified Security Report Generator | Tools: OWASP Dependency Check, Checkov, Semgrep</p>
        </div>
    </div>
</body>
</html>'''
    
    # Записываем HTML в файл
    with open(output_html, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"HTML report generated: {output_html}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        generate_html(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "unified_report.html")
    else:
        print("Usage: python script.py <csv_file> [output_html]")
EOF
    
    # Запускаем Python скрипт
    python3 "${REPORT_DIR}/generate_html.py" "${csv_file}" "${output_html}"
    
    # Удаляем временный Python файл
    rm -f "${REPORT_DIR}/generate_html.py"
    
    echo "${output_html}"
}

# Альтернативная функция для создания HTML без Python
create_unified_html_simple() {
    local csv_file="$1"
    local output_html="${REPORT_DIR}/unified_report.html"
    
    echo "Creating simple HTML report..."
    
    # Подсчитываем статистику
    local total_all=$(tail -n +2 "${csv_file}" | wc -l)
    local total_sca=$(grep -c '"dependency-check"' "${csv_file}" 2>/dev/null || echo "0")
    local total_checkov=$(grep -c '"checkov"' "${csv_file}" 2>/dev/null || echo "0")
    local total_semgrep=$(grep -c '"semgrep"' "${csv_file}" 2>/dev/null || echo "0")
    
    cat > "${output_html}" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Unified Security Scan Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 2px solid #4CAF50;
            padding-bottom: 10px;
        }
        .summary {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        .summary-card {
            background: white;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            text-align: center;
        }
        .summary-card .count {
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }
        .tool-section {
            margin: 25px 0;
            padding: 15px;
            background: #fff;
            border-radius: 5px;
            border: 1px solid #ddd;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
            font-size: 14px;
        }
        th {
            background-color: #4CAF50;
            color: white;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .severity {
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 12px;
            text-align: center;
            display: inline-block;
            min-width: 70px;
        }
        .severity-CRITICAL { background-color: #dc3545; color: white; }
        .severity-HIGH { background-color: #fd7e14; color: white; }
        .severity-MEDIUM { background-color: #ffc107; color: #212529; }
        .severity-LOW { background-color: #28a745; color: white; }
        .severity-INFO { background-color: #17a2b8; color: white; }
        .cve-id {
            font-family: monospace;
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 12px;
        }
        .location {
            font-size: 12px;
            color: #666;
            font-family: monospace;
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .timestamp {
            color: #666;
            font-style: italic;
            margin-bottom: 20px;
        }
        .export-links {
            margin: 20px 0;
        }
        .export-links a {
            display: inline-block;
            margin-right: 10px;
            padding: 8px 16px;
            background: #4CAF50;
            color: white;
            text-decoration: none;
            border-radius: 4px;
        }
        .export-links a:hover {
            background: #45a049;
        }
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            table {
                display: block;
                overflow-x: auto;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Unified Security Scan Report</h1>
        <div class="timestamp">Generated on: 
EOF
    
    cat >> "${output_html}" << EOF
            $(date "+%Y-%m-%d %H:%M:%S")
        </div>
        
        <div class="export-links">
            <a href="unified_report.json" download>Download JSON</a>
            <a href="unified_report.csv" download>Download CSV</a>
        </div>
        
        <div class="summary">
            <h2>Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Total Findings</h3>
                    <div class="count">${total_all}</div>
                </div>
                <div class="summary-card">
                    <h3>Dependency Check (SCA)</h3>
                    <div class="count">${total_sca}</div>
                </div>
                <div class="summary-card">
                    <h3>Checkov</h3>
                    <div class="count">${total_checkov}</div>
                </div>
                <div class="summary-card">
                    <h3>Semgrep</h3>
                    <div class="count">${total_semgrep}</div>
                </div>
            </div>
        </div>
EOF
    
    # Добавляем данные из CSV
    echo '<div class="tool-section">' >> "${output_html}"
    echo '<h2>Complete Data (from CSV)</h2>' >> "${output_html}"
    echo '<p>For detailed data, please download the CSV file or view the raw data below:</p>' >> "${output_html}"
    
    # Добавляем простую таблицу с первыми 20 строками
    if [ ${total_all} -gt 0 ]; then
        echo '<table>' >> "${output_html}"
        echo '<thead><tr><th>Tool</th><th>Severity</th><th>Component/File</th><th>Description</th><th>ID</th></tr></thead>' >> "${output_html}"
        echo '<tbody>' >> "${output_html}"
        
        # Показываем первые 20 строк для примера
        tail -n +2 "${csv_file}" | head -20 | while IFS= read -r line; do
            # Парсим CSV строку (упрощенная версия)
            IFS=',' read -r -a fields <<< "$line"
            
            # Извлекаем значения (удаляем кавычки)
            tool=$(echo "${fields[0]}" | sed 's/^"//;s/"$//')
            severity=$(echo "${fields[2]}" | sed 's/^"//;s/"$//')
            component=$(echo "${fields[3]}" | sed 's/^"//;s/"$//')
            description=$(echo "${fields[4]}" | sed 's/^"//;s/"$//' | cut -c1-50)
            id=$(echo "${fields[6]}" | sed 's/^"//;s/"$//')
            
            echo "<tr>" >> "${output_html}"
            echo "<td><strong>${tool}</strong></td>" >> "${output_html}"
            echo "<td><span class=\"severity severity-${severity}\">${severity}</span></td>" >> "${output_html}"
            echo "<td>${component}</td>" >> "${output_html}"
            echo "<td>${description}...</td>" >> "${output_html}"
            echo "<td><span class=\"cve-id\">${id}</span></td>" >> "${output_html}"
            echo "</tr>" >> "${output_html}"
        done
        
        echo '</tbody></table>' >> "${output_html}"
        
        if [ ${total_all} -gt 20 ]; then
            echo "<p style='text-align: center; color: #666;'>Showing first 20 of ${total_all} findings. Download CSV for complete list.</p>" >> "${output_html}"
        fi
    else
        echo '<p>No security findings detected.</p>' >> "${output_html}"
    fi
    
    echo '</div>' >> "${output_html}"
    
    # Добавляем раздел с информацией о файлах
    cat >> "${output_html}" << 'EOF'
        <div class="tool-section">
            <h2>Report Files</h2>
            <table>
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Format</th>
                        <th>Size</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
EOF
    
    # Добавляем информацию о файлах
    for file in "${REPORT_DIR}"/*.json "${REPORT_DIR}"/*.csv "${REPORT_DIR}"/*.html; do
        if [ -f "${file}" ]; then
            filename=$(basename "${file}")
            filesize=$(stat -c%s "${file}" 2>/dev/null || stat -f%z "${file}" 2>/dev/null)
            filesize_kb=$((filesize / 1024))
            
            case "${filename}" in
                "unified_report.json")
                    description="Complete JSON data from all scans"
                    ;;
                "unified_report.csv")
                    description="Structured CSV data for analysis"
                    ;;
                "unified_report.html")
                    description="HTML report (this file)"
                    ;;
                "sca_data.json")
                    description="Raw SCA (Dependency Check) data"
                    ;;
                "checkov_data.json")
                    description="Raw Checkov data"
                    ;;
                "semgrep_data.json")
                    description="Raw Semgrep data"
                    ;;
                *)
                    description="Data file"
                    ;;
            esac
            
            echo "<tr>" >> "${output_html}"
            echo "<td><a href=\"${filename}\">${filename}</a></td>" >> "${output_html}"
            echo "<td>${filename##*.}</td>" >> "${output_html}"
            echo "<td>${filesize_kb} KB</td>" >> "${output_html}"
            echo "<td>${description}</td>" >> "${output_html}"
            echo "</tr>" >> "${output_html}"
        fi
    done
    
    cat >> "${output_html}" << 'EOF'
                </tbody>
            </table>
        </div>
        
        <div style="text-align: center; margin-top: 30px; color: #666; font-size: 12px;">
            <p>Generated by Unified Security Report Generator | Tools: OWASP Dependency Check, Checkov, Semgrep</p>
            <p>Report directory: 
EOF
    
    echo "${REPORT_DIR}" >> "${output_html}"
    
    cat >> "${output_html}" << 'EOF'
            </p>
        </div>
    </div>
</body>
</html>
EOF
    
    echo "${output_html}"
}

# Основной скрипт
main() {
    echo "Starting unified report generation..."
    
    # Проверяем наличие jq
    if ! command -v jq &> /dev/null; then
        echo "Warning: jq is not installed. Some features may be limited."
        echo "Install with: sudo apt-get install jq"
    fi
    
    # Парсим отчеты
    echo "Parsing security reports..."
    sca_data=$(parse_sca_reports)
    checkov_data=$(parse_checkov_report)
    semgrep_data=$(parse_semgrep_report)
    
    # Создаем единый JSON
    echo "Creating unified JSON report..."
    unified_json=$(create_unified_json "${sca_data}" "${checkov_data}" "${semgrep_data}")
    
    # Создаем CSV
    echo "Creating CSV report..."
    unified_csv=$(create_unified_csv "${unified_json}")
    
    # Проверяем, установлен ли Python3
    if command -v python3 &> /dev/null; then
        echo "Creating enhanced HTML report with Python..."
        # Сохраняем Python скрипт в файл
        cat > "${REPORT_DIR}/generate_html.py" << 'PYEOF'
import csv
import html
import sys
from datetime import datetime

def read_csv_data(csv_file):
    """Читаем CSV файл и возвращаем данные по категориям"""
    data = {
        'dependency-check': [],
        'checkov': [],
        'semgrep': []
    }
    
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            headers = next(reader)  # Пропускаем заголовок
            
            for row in reader:
                if len(row) < 7:
                    continue
                
                tool = row[0].strip('"')
                if tool in data:
                    # Экранируем HTML символы
                    escaped_row = [html.escape(cell) for cell in row]
                    data[tool].append(escaped_row)
    
    except Exception as e:
        print(f"Error reading CSV: {e}")
    
    return data

def generate_html(csv_file, output_html):
    """Генерируем HTML отчет"""
    data = read_csv_data(csv_file)
    
    # Подсчитываем статистику
    total_sca = len(data['dependency-check'])
    total_checkov = len(data['checkov'])
    total_semgrep = len(data['semgrep'])
    total_all = total_sca + total_checkov + total_semgrep
    
    # Создаем HTML
    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Unified Security Scan Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 2px solid #4CAF50;
            padding-bottom: 10px;
        }}
        .summary {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }}
        .summary-card {{
            background: white;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .summary-card .count {{
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .tool-section {{
            margin: 25px 0;
            padding: 15px;
            background: #fff;
            border-radius: 5px;
            border: 1px solid #ddd;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
            font-size: 14px;
        }}
        th {{
            background-color: #4CAF50;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .severity {{
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 12px;
            text-align: center;
            display: inline-block;
            min-width: 70px;
        }}
        .severity-CRITICAL {{ background-color: #dc3545; color: white; }}
        .severity-HIGH {{ background-color: #fd7e14; color: white; }}
        .severity-MEDIUM {{ background-color: #ffc107; color: #212529; }}
        .severity-LOW {{ background-color: #28a745; color: white; }}
        .severity-INFO {{ background-color: #17a2b8; color: white; }}
        .cve-id {{
            font-family: monospace;
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 12px;
        }}
        .location {{
            font-size: 12px;
            color: #666;
            font-family: monospace;
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        .timestamp {{
            color: #666;
            font-style: italic;
            margin-bottom: 20px;
        }}
        .export-links {{
            margin: 20px 0;
        }}
        .export-links a {{
            display: inline-block;
            margin-right: 10px;
            padding: 8px 16px;
            background: #4CAF50;
            color: white;
            text-decoration: none;
            border-radius: 4px;
        }}
        .export-links a:hover {{
            background: #45a049;
        }}
        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            table {{
                display: block;
                overflow-x: auto;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Unified Security Scan Report</h1>
        <div class="timestamp">Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
        
        <div class="export-links">
            <a href="unified_report.json" download>Download JSON</a>
            <a href="unified_report.csv" download>Download CSV</a>
        </div>
        
        <div class="summary">
            <h2>Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Total Findings</h3>
                    <div class="count">{total_all}</div>
                </div>
                <div class="summary-card">
                    <h3>Dependency Check (SCA)</h3>
                    <div class="count">{total_sca}</div>
                </div>
                <div class="summary-card">
                    <h3>Checkov</h3>
                    <div class="count">{total_checkov}</div>
                </div>
                <div class="summary-card">
                    <h3>Semgrep</h3>
                    <div class="count">{total_semgrep}</div>
                </div>
            </div>
        </div>
'''
    
    # Добавляем SCA данные
    if total_sca > 0:
        html_content += f'''
        <div class="tool-section">
            <h2>Software Composition Analysis (Dependency Check) - {total_sca} findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Component</th>
                        <th>Description</th>
                        <th>Location</th>
                        <th>CVE ID</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for row in data['dependency-check'][:50]:  # Показываем первые 50 записей
            severity = row[2] if len(row) > 2 else ""
            component = row[3] if len(row) > 3 else ""
            description = row[4] if len(row) > 4 else ""
            location = row[5] if len(row) > 5 else ""
            cve_id = row[6] if len(row) > 6 else ""
            
            html_content += f'''
                    <tr>
                        <td><span class="severity severity-{severity}">{severity}</span></td>
                        <td><strong>{component}</strong></td>
                        <td>{description}</td>
                        <td class="location" title="{location}">{location[:80]}{"..." if len(location) > 80 else ""}</td>
                        <td><span class="cve-id">{cve_id}</span></td>
                    </tr>'''
        
        html_content += '''
                </tbody>
            </table>'''
        
        if total_sca > 50:
            html_content += f'<p style="text-align: center; color: #666;">Showing first 50 of {total_sca} SCA findings. Download CSV for complete list.</p>'
        
        html_content += '</div>'
    
    # Добавляем Checkov данные
    if total_checkov > 0:
        html_content += f'''
        <div class="tool-section">
            <h2>Infrastructure as Code Security (Checkov) - {total_checkov} findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Resource</th>
                        <th>Check Name</th>
                        <th>File</th>
                        <th>Check ID</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for row in data['checkov']:
            severity = row[2] if len(row) > 2 else ""
            resource = row[3] if len(row) > 3 else ""
            check_name = row[4] if len(row) > 4 else ""
            file_path = row[5] if len(row) > 5 else ""
            check_id = row[6] if len(row) > 6 else ""
            
            # Определяем класс severity для Checkov
            severity_class = "INFO"
            severity_upper = severity.upper()
            if "CRITICAL" in severity_upper:
                severity_class = "CRITICAL"
            elif "HIGH" in severity_upper:
                severity_class = "HIGH"
            elif "MEDIUM" in severity_upper:
                severity_class = "MEDIUM"
            elif "LOW" in severity_upper:
                severity_class = "LOW"
            
            html_content += f'''
                    <tr>
                        <td><span class="severity severity-{severity_class}">{severity}</span></td>
                        <td><strong>{resource}</strong></td>
                        <td>{check_name}</td>
                        <td class="location">{file_path}</td>
                        <td><span class="cve-id">{check_id}</span></td>
                    </tr>'''
        
        html_content += '''
                </tbody>
            </table>
        </div>'''
    
    # Добавляем Semgrep данные
    if total_semgrep > 0:
        html_content += f'''
        <div class="tool-section">
            <h2>Static Application Security Testing (Semgrep) - {total_semgrep} findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>File</th>
                        <th>Message</th>
                        <th>Location</th>
                        <th>Rule ID</th>
                    </tr>
                </thead>
                <tbody>'''
        
        for row in data['semgrep']:
            severity = row[2] if len(row) > 2 else ""
            file_path = row[3] if len(row) > 3 else ""
            message = row[4] if len(row) > 4 else ""
            location = row[5] if len(row) > 5 else ""
            rule_id = row[6] if len(row) > 6 else ""
            
            html_content += f'''
                    <tr>
                        <td><span class="severity severity-{severity}">{severity}</span></td>
                        <td><strong>{file_path}</strong></td>
                        <td>{message}</td>
                        <td>{location}</td>
                        <td><span class="cve-id">{rule_id}</span></td>
                    </tr>'''
        
        html_content += '''
                </tbody>
            </table>
        </div>'''
    
    # Закрываем HTML
    html_content += '''
        <div style="text-align: center; margin-top: 30px; color: #666; font-size: 12px;">
            <p>Generated by Unified Security Report Generator | Tools: OWASP Dependency Check, Checkov, Semgrep</p>
        </div>
    </div>
</body>
</html>'''
    
    # Записываем HTML в файл
    with open(output_html, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"HTML report generated: {output_html}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        generate_html(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "unified_report.html")
    else:
        print("Usage: python script.py <csv_file> [output_html]")
        sys.exit(1)
PYEOF
        
        # Запускаем Python скрипт
        python3 "${REPORT_DIR}/generate_html.py" "${unified_csv}" "${REPORT_DIR}/unified_report.html"
        
        # Удаляем временный Python файл
        rm -f "${REPORT_DIR}/generate_html.py"
        unified_html="${REPORT_DIR}/unified_report.html"
    else
        echo "Python3 not found, creating simple HTML report..."
        unified_html=$(create_unified_html_simple "${unified_csv}")
    fi
    
    echo ""
    echo "========================================"
    echo "✅ REPORTS GENERATED SUCCESSFULLY!"
    echo "========================================"
    echo ""
    echo "📊 REPORT SUMMARY:"
    echo "-----------------"
    echo "Total Findings: ${total_all}"
    echo "  • SCA (Dependency Check): ${total_sca}"
    echo "  • Checkov: ${total_checkov}"
    echo "  • Semgrep: ${total_semgrep}"
    echo ""
    echo "📁 GENERATED FILES:"
    echo "------------------"
    echo "1. 📈 HTML Dashboard: ${unified_html}"
    echo "2. 📋 CSV Data: ${unified_csv}"
    echo "3. 📊 JSON Complete: ${unified_json}"
    echo ""
    echo "🔍 QUICK VIEW:"
    echo "-------------"
    echo "To view the HTML report:"
    echo "  firefox ${unified_html} 2>/dev/null || echo 'Open in browser: file://${unified_html}'"
    echo ""
    echo "To check CSV data:"
    echo "  head -5 ${unified_csv}"
    echo ""
    echo "========================================"
}

main
