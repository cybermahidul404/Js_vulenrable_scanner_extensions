document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("scanBtn").addEventListener("click", scanCurrentTab);
});

function scanCurrentTab() {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        const activeTab = tabs[0];
        if (!activeTab || !activeTab.url) {
            document.getElementById("outputText").textContent = "❌ Unable to access current tab.";
            return;
        }

        const url = new URL(activeTab.url);
        const domain = url.hostname.replace(/^www\./, "");
        document.getElementById("outputText").innerHTML = `<p>🔍 Scanning domain: <strong>${domain}</strong>...</p>`;

        fetchSubdomains(domain, async function (subdomains) {
            if (subdomains.length === 0) {
                document.getElementById("outputText").innerHTML += "<p>⚠️ No subdomains found.</p>";
                return;
            }

            let totalJS = 0;
            let vulnerableCount = 0;
            let processedSubs = 0;
            const subdomainResults = [];

            for (const sub of subdomains) {
                const fullURL = `https://${sub}`;
                await fetchJSFiles(fullURL, async function (jsFiles) {
                    const jsData = [];
                    for (const js of jsFiles) {
                        const libInfo = await getLibraryInfo(js);
                        const vulns = await checkOsvVulnerabilities(libInfo.library, libInfo.version);
                        if (vulns.length > 0) vulnerableCount++;
                        jsData.push({ js, libInfo, vulns });
                        totalJS++;
                    }
                    subdomainResults.push({ subdomain: sub, jsData });
                    processedSubs++;

                    if (processedSubs === subdomains.length) {
                        generateResultTable(subdomainResults);
                        document.getElementById("outputText").innerHTML += `<p>✅ Scan Complete. Total JS Files Found: ${totalJS}</p>`;
                        document.getElementById("outputText").innerHTML += `<p>⚠️ Vulnerable JS Files: ${vulnerableCount}</p>`;
                        updateVulnerabilityCount(vulnerableCount, totalJS);
                    }
                });
            }
        });
    });
}

function fetchSubdomains(domain, callback) {
    fetch(`https://crt.sh/?q=%25.${domain}&output=json`)
        .then((response) => response.json())
        .then((data) => {
            const names = data.map((entry) => entry.name_value);
            const unique = [...new Set(names.flatMap((name) => name.split("\n")))];
            callback(unique);
        })
        .catch((err) => {
            console.error("Failed to fetch subdomains:", err);
            callback([]);
        });
}

function fetchJSFiles(domainUrl, callback) {
    fetch(domainUrl)
        .then((res) => res.text())
        .then((html) => {
            const scripts = html.match(/<script[^>]+src=["']([^"']+)["']/gi);
            if (scripts) {
                const jsLinks = scripts.map((tag) => {
                    const match = tag.match(/src=["']([^"']+)["']/);
                    return match ? new URL(match[1], domainUrl).href : null;
                }).filter(Boolean);
                callback(jsLinks);
            } else {
                callback([]);
            }
        })
        .catch((err) => {
            console.warn(`⚠️ Cannot fetch JS from ${domainUrl}`, err);
            callback([]);
        });
}

async function getLibraryInfo(jsFile) {
    try {
        const res = await fetch(jsFile);
        const content = await res.text();
        let libraryInfo = { library: "Unknown", version: null };

        const versionMatch = jsFile.match(/[?&]ver=([\d.]+)/i);
        const lower = jsFile.toLowerCase();

        if (lower.includes("jquery/ui")) {
            libraryInfo.library = "jquery-ui";
            libraryInfo.version = versionMatch ? versionMatch[1] : extractVersion(content, "jquery");
        } else if (lower.includes("jquery") || content.includes("jQuery")) {
            libraryInfo.library = "jquery";
            libraryInfo.version = versionMatch ? versionMatch[1] : extractVersion(content, "jquery");
        } else if (lower.includes("react-dom") || content.includes("react-dom")) {
            libraryInfo.library = "react-dom";
            libraryInfo.version = extractVersion(content, "react");
        } else if (lower.includes("react") || content.includes("React")) {
            libraryInfo.library = "react";
            libraryInfo.version = extractVersion(content, "react");
        } else if (content.includes("Vue")) {
            libraryInfo.library = "vue";
            libraryInfo.version = extractVersion(content, "vue");
        } else if (content.includes("angular")) {
            libraryInfo.library = "angular";
            libraryInfo.version = extractVersion(content, "angular");
        } else if (content.includes("underscore")) {
            libraryInfo.library = "underscore";
            libraryInfo.version = extractVersion(content, "underscore");
        }

        return libraryInfo;
    } catch (err) {
        console.warn(`⚠️ Cannot fetch JS file: ${jsFile}`, err);
        return { library: "Unknown", version: null };
    }
}

function extractVersion(content, lib) {
    const patterns = {
        react: /React\.version\s*=\s*["']([^"']+)["']/i,
        jquery: /jQuery\.fn\.jquery\s*=\s*["']([^"']+)["']/i,
        vue: /Vue\.version\s*=\s*["']([^"']+)["']/i,
        angular: /angular\.version\.full\s*=\s*["']([^"']+)["']/i,
        underscore: /_.version\s*=\s*["']([^"']+)["']/i,
    };
    const match = content.match(patterns[lib]);
    return match ? match[1] : null;
}

async function checkOsvVulnerabilities(libName, version) {
    if (!libName || !version) return [];
    try {
        const response = await fetch("https://api.osv.dev/v1/query", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                version: version,
                package: { name: libName.toLowerCase(), ecosystem: "npm" }
            })
        });

        if (!response.ok) throw new Error("OSV API error");
        const data = await response.json();
        return data.vulns || [];
    } catch (err) {
        console.warn(`OSV API Error for ${libName}`, err);
        return [];
    }
}

function updateVulnerabilityCount(vulnerableCount, totalJS) {
    const countElement = document.getElementById("countSummary");
    countElement.innerHTML = `
        <strong>Total JS Files:</strong> ${totalJS}<br>
        <strong style="color: red;">Vulnerable Files:</strong> ${vulnerableCount}
    `;
}

function generateResultTable(subdomainResults) {
    let html = `
    <table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%;">
    <thead style="background-color: #f2f2f2;">
        <tr>
            <th>Subdomain</th>
            <th>JS File</th>
            <th>Library</th>
            <th>Version</th>
            <th>Status</th>
            <th>Vulnerabilities</th>
        </tr>
    </thead>
    <tbody>`;

    subdomainResults.forEach(({ subdomain, jsData }) => {
        if (jsData.length === 0) {
            html += `<tr><td>${subdomain}</td><td colspan="5">⚠️ No JS files found</td></tr>`;
        } else {
            jsData.forEach(({ js, libInfo, vulns }) => {
                const vulnList = vulns.length
                    ? `<ul style="margin: 0; padding-left: 18px;">${vulns.map(v => `
                        <li>
                            <a href="https://osv.dev/vulnerability/${v.id}" target="_blank" style="color:#d73a49; font-weight: bold;">${v.id}</a>: ${v.summary}
                        </li>`).join("")}</ul>`
                    : "✅ No vulnerabilities";

                html += `<tr>
                    <td>${subdomain}</td>
                    <td><a href="${js}" target="_blank" style="color:#0366d6;">${js}</a></td>
                    <td>${libInfo.library}</td>
                    <td>${libInfo.version || "Unknown"}</td>
                    <td style="color: ${vulns.length > 0 ? 'red' : 'green'};">
                        ${vulns.length > 0 ? `🔴 ${vulns.length} Found` : "✅ Safe"}
                    </td>
                    <td>${vulnList}</td>
                </tr>`;
            });
        }
    });

    html += `</tbody></table></div>`;
    document.getElementById("outputText").innerHTML += html;
}