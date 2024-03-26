pipeline {
    agent {
        label 'windows'
    }

    environment {
        SNYK = tool name: 'Snyk-Installation'
        SNYK_API_TOKEN = credentials('Snyk-API-Token')
    }

    parameters {
        booleanParam(name: 'OWASP_DEPENDENCY_CHECK', defaultValue: false, description: 'Enable OWASP Dependency Check')
        booleanParam(name: 'SNYK', defaultValue: false, description: 'Enable Snyk Scan')
        booleanParam(name: 'TRIVY', defaultValue: true, description: 'Enable Trivy Scan')
    }
    
    stages {
        stage('Build') {
            steps {
                echo 'Build'
            }
        }

        stage('Test') {
            steps {
                echo 'Test'
            }
        }

        stage('OWASP Dependency Check') {
            when {
                expression { params.OWASP_DEPENDENCY_CHECK == true }
            }
            steps {
                dependencyCheck additionalArguments: '--scan \"${WORKSPACE}\" --prettyPrint --format JSON --format XML', odcInstallation: 'Dependency-Check-Installation'
                dependencyCheckPublisher pattern: '**/dependency-check-report.xml'

                script {
                    def dependencyCheckReport = "${WORKSPACE}/dependency-check-report.json"
                    def OWASPVulnerabilities = extractOWASPVulnerabilities(dependencyCheckReport)

                    def OWASPTableRows = generateOWASPHTMLTableRows(OWASPVulnerabilities)

                    env.OWASP_TABLE = OWASPTableRows
                }
            }
        }

        stage('Snyk') {
            when {
                expression { params.SNYK == true }
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'SUCCESS') {
                    bat """
                        ${SNYK}/snyk-win.exe auth %SNYK_API_TOKEN%
                        ${SNYK}/snyk-win.exe code test ${WORKSPACE} --json-file-output=${WORKSPACE}/snyk-report.json
                    """
                }

                script {
                    def snykReport = "${WORKSPACE}/snyk-report.json"
                    def snykVulnerabilities = extractSnykVulnerabilities(snykReport)

                    def snykTableRows = generateSnykHTMLTableRows(snykVulnerabilities)

                    env.SNYK_TABLE = snykTableRows
                }
            }
        }

        stage('Trivy') {
            when {
                expression { params.TRIVY == true }
            }
            steps {
                bat """
                    cd C:\\jenkins\\trivy_0.49.0_windows-64bit
                    trivy.exe
                    trivy fs --scanners vuln,secret,misconfig,license ${WORKSPACE} -f json -o ${WORKSPACE}/trivy-report.json
                """

                script {
                    // Extract Trivy vulnerabilities
                    def trivyReport = "${WORKSPACE}/trivy-report.json"
                    def trivyVulnerabilities = extractTrivyVulnerabilities(trivyReport)
                    def trivyMisconfigurations = extractTrivyMisconfigurations(trivyReport)

                    def trivyVulnerabilitiesTableRows = generateTrivyVulnerabilitiesHTMLTableRows(trivyVulnerabilities)
                    def trivyMisconfigurationsTableRows = generateTrivyMisconfigurationsHTMLTableRows(trivyMisconfigurations)

                    env.TRIVY_VULNERABILITIES_TABLE = trivyVulnerabilitiesTableRows
                    env.TRIVY_MISCONFIGURATIONS_TABLE = trivyMisconfigurationsTableRows
                }
            }
        }

        stage('Deploy') {
            steps {
                echo 'Deploy'
            }
        }
    }

    post {
        always {
            script {
                emailext(
                    to: 'ahdoo.ling010519@gmail.com',
                    mimeType: 'text/html',
                    subject: 'Build #${BUILD_NUMBER} - ${JOB_NAME}',
                    body: """
                        <html>
                            <head>
                                <style>
                                    body {
                                        font-family: Arial, sans-serif;
                                        background-color: #f5f5f5;
                                    }
                                    .container {
                                        background-color: #ffffff;
                                        border-radius: 5px;
                                        box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.2);
                                        margin: 20px;
                                        padding: 20px;
                                    }
                                    table {
                                        width: 100%;
                                        border-collapse: collapse;
                                        margin-top: 20px;
                                    }
                                    th, td {
                                        border: 1px solid #ddd;
                                        padding: 8px;
                                        text-align: left;
                                    }
                                    th {
                                        background-color: #f2f2f2;
                                    }
                                    .status {
                                        font-size: 24px;
                                        font-weight: bold;
                                        color: ${getStatusColor()};
                                    }
                                    .footer {
                                        margin-top: 20px;
                                        padding-top: 10px;
                                        border-top: 1px solid #ddd;
                                        text-align: center;
                                        font-size: 12px;
                                        color: #666;
                                    }
                                    .jenkins-icon {
                                        position: absolute;
                                        top: 10px; 
                                        left: 10px; 
                                        width: 150px; 
                                        height: auto;
                                    }
                                </style>
                            </head>
                            <body>
                                <div class="container">
                                    <img src="https://www.jenkins.io/images/logo-title-opengraph.png" alt="Jenkins Icon" class="jenkins-icon">

                                    <p class="status">Build Status: ${currentBuild.currentResult}</p>
                                    
                                    <h2>Build Info</h2>
                                    <table>
                                        <tr>
                                            <th>Job Name</th>
                                            <td>${JOB_NAME}</td>
                                            <th>Build Number</th>
                                            <td>${BUILD_NUMBER}</td>
                                        </tr>
                                        <tr>
                                            <th>Build URL</th>
                                            <td colspan="3"><a href="${BUILD_URL}">${BUILD_URL}</a></td>
                                        </tr>
                                        <tr>
                                            <th>Build Node</th>
                                            <td>${NODE_NAME}</td>
                                            <th>Build Duration</th>
                                            <td>${currentBuild.durationString}</td>
                                        </tr>
                                    </table>
        
                                    <h2>Git Changeset</h2>
                                    <table>
                                        <tr>
                                            <th>Commit ID</th>
                                            <th>Author</th>
                                            <th>Message</th>
                                            <th>Files</th>
                                            <th>Timestamp</th>
                                        </tr>
                                        ${getGitChangeSetTable()}
                                    </table>

                                    <h2>OWASP Dependency Check</h2>
                                    <table>
                                        <tr>
                                            <th>File Name</th>
                                            <th>Vulnerability Name</th>
                                            <th>Severity</th>
                                            <th>Description</th>
                                        </tr>
                                        ${env.OWASP_TABLE ?: "<tr><td colspan=\"4\">No vulnerabilities found</td></tr>"}
                                    </table>

                                    <h2>Snyk</h2>
                                    <table>
                                        <tr>
                                            <th>Rule ID</th>
                                            <th>Level</th>
                                            <th>Message</th>
                                            <th>File</th>
                                            <th>Location</th>
                                        </tr>
                                        ${env.SNYK_TABLE ?: "<tr><td colspan=\"5\">No vulnerabilities found</td></tr>"}
                                    </table>

                                    <h2>Trivy</h2>
                                    <h3>Vulnerabilities</h3>
                                    <table>
                                        <tr>
                                            <th>Target</th>
                                            <th>Vulnerability ID</th>
                                            <th>Severity</th>
                                            <th>Title</th>
                                            <th>Description</th>
                                            <th>Package Name</th>
                                            <th>Installed Version</th>
                                            <th>Fixed Version</th>
                                        </tr>
                                        ${env.TRIVY_VULNERABILITIES_TABLE ?: "<tr><td colspan=\"8\">No vulnerabilities found</td></tr>"}
                                    </table>
                                    <h3>Misconfigurations</h3>  
                                    <table>
                                        <tr>
                                            <th>Target</th>
                                            <th>AVD ID</th>
                                            <th>Title</th>
                                            <th>Description</th>
                                            <th>Resolution</th>
                                        </tr>
                                        ${env.TRIVY_MISCONFIGURATIONS_TABLE ?: "<tr><td colspan=\"5\">No misconfigurations found</td></tr>"}
                                    </table>

                                    <div class="footer">
                                    <p>
                                        This email and any files transmitted with it are confidential and intended solely for the use of the individual or entity to whom they are addressed. If you have received this email in error, please notify the system manager.
                                        <br><br>
                                        This message is sent from the AVAR project.
                                        <br><br>
                                        &copy; 2024 All rights reserved.
                                    </p>
                                </div>
                                </div>
                            </body>
                        </html>
                    """
                )
            }
        }
    }
}

def getGitChangeSetTable() {
    def changelogTable = ""
    def build = currentBuild

    if (build.changeSets.size() > 0) {
        changelogTable += build.changeSets.collect { cs ->
            cs.collect { entry ->
                def formattedTimestamp = new Date(entry.timestamp.toLong()).toString()
                def id = entry.commitId
                def files = entry.affectedFiles.collect { file ->
                    file.path
                }.join(", ")
                def author = entry.author.fullName
                def message = entry.msg
                def commitUrl = "https://github.com/SHAODOO/WebGoat/commit/${id}"
                "<tr><td><a href=\"${commitUrl}\">${id}</a></td><td>${author}</td><td>${message}</td><td>${files}</td><td>${formattedTimestamp}</td></tr>"
            }.join('\n')
        }.join('\n')
    } else {
        def buildsWithChangeset = 0
        while (buildsWithChangeset < 5 && build != null) {
            if (build.changeSets.size() > 0) {
                changelogTable += build.changeSets.collect { cs ->
                    cs.collect { entry ->
                        def formattedTimestamp = new Date(entry.timestamp.toLong()).toString()
                        def id = entry.commitId
                        def files = entry.affectedFiles.collect { file ->
                            file.path
                        }.join(", ")
                        def author = entry.author.fullName
                        def message = entry.msg
                        // Construct GitHub commit URL
                        def commitUrl = "https://github.com/SHAODOO/WebGoat/commit/${id}"
                        "<tr><td><a href=\"${commitUrl}\">${id}</a></td><td>${author}</td><td>${message}</td><td>${files}</td><td>${formattedTimestamp}</td></tr>"
                    }.join('\n')
                }.join('\n')
                buildsWithChangeset++
            }
            build = build.previousBuild
        }
    }

    if (changelogTable.isEmpty()) {
        changelogTable = "<tr><td colspan=\"5\">No changesets found</td></tr>"
    }

    return changelogTable
}

def getStatusColor() {
    switch (currentBuild.currentResult) {
        case 'SUCCESS':
            return 'green';
        case 'FAILURE':
            return 'red';
        case 'ABORTED':
            return 'grey';
        default:
            return 'black'; // default color
    }
}

def extractOWASPVulnerabilities(reportFile) {
    def vulnerabilities = [:]
    node {
        def jsonReport = readFile(file: reportFile)
        def json = readJSON text: jsonReport

        json.dependencies.findAll { dependency ->
            dependency.vulnerabilities
        }.each { dependency ->
            def fileName = dependency.fileName
            def dependencyVulnerabilities = dependency.vulnerabilities

            if (dependencyVulnerabilities) {
                vulnerabilities[fileName] = dependencyVulnerabilities.collect { vuln ->
                    return [name: vuln.name, severity: vuln.severity, description: vuln.description]
                }
            }
        }
    }

    return vulnerabilities
}

def generateOWASPHTMLTableRows(OWASPVulnerabilities) {
    def tableRows = ""
    OWASPVulnerabilities.each { fileName, vulns ->        
        vulns.eachWithIndex { vuln, index ->
            if (index > 0) {
                tableRows += "<tr>"
            }
            tableRows += "<td>${fileName}</td>"
            tableRows += "<td>${vuln.name}</td>"
            tableRows += "<td>${vuln.severity}</td>"
            tableRows += "<td>${vuln.description}</td>"
            tableRows += "</tr>"
        }
    }
    return tableRows
}

def extractSnykVulnerabilities(reportFile) {
    def vulnerabilities = []
    def jsonReport = readFile(file: reportFile)
    def json = readJSON text: jsonReport
    
    json.runs.each { run ->
        run.results.each { result ->
            def vulnerability = [:]
            vulnerability['ruleId'] = result.ruleId
            vulnerability['level'] = result.level
            vulnerability['message'] = result.message.text
            vulnerability['artifactUri'] = result.locations[0].physicalLocation.artifactLocation.uri
            vulnerability['startLine'] = result.locations[0].physicalLocation.region.startLine
            vulnerability['endLine'] = result.locations[0].physicalLocation.region.endLine
            vulnerability['startColumn'] = result.locations[0].physicalLocation.region.startColumn
            vulnerability['endColumn'] = result.locations[0].physicalLocation.region.endColumn
            vulnerabilities.add(vulnerability)
        }
    }
    
    return vulnerabilities
}

def generateSnykHTMLTableRows(snykVulnerabilities) {
    def tableRows = ""
    snykVulnerabilities.each { vulnerability ->
        tableRows += "<tr>"
        tableRows += "<td>${vulnerability.ruleId}</td>"
        tableRows += "<td>${vulnerability.level}</td>"
        tableRows += "<td>${vulnerability.message}</td>"
        tableRows += "<td>${vulnerability.artifactUri}</td>"
        tableRows += "<td>Ln ${vulnerability.startLine}, Col ${vulnerability.startColumn} - Ln ${vulnerability.endLine}, Col ${vulnerability.endColumn}</td>"
        tableRows += "</tr>"
    }
    return tableRows
}

def extractTrivyVulnerabilities(reportFile) {
    def jsonReport = readFile(file: reportFile)
    def json = readJSON text: jsonReport
    def vulnerabilities = []

    json.Results.each { result ->
        if (result.Vulnerabilities) { 
            result.Vulnerabilities.each { vulnerability ->
                def vuln = [
                    Target: result.Target,
                    VulnerabilityID: "<a href=\"${vulnerability.PrimaryURL}\">${vulnerability.VulnerabilityID}</a>",
                    Severity: vulnerability.Severity,
                    Title: vulnerability.Title,
                    Description: vulnerability.Description,
                    PkgName: vulnerability.PkgName,
                    InstalledVersion: vulnerability.InstalledVersion,
                    FixedVersion: vulnerability.FixedVersion
                ]
                vulnerabilities.add(vuln)
            }
        }
    }
    return vulnerabilities
}

def generateTrivyVulnerabilitiesHTMLTableRows(trivyVulnerabilities) {
    def tableRows = ""
    trivyVulnerabilities.each { vulnerability ->
        tableRows += "<tr>"
        tableRows += "<td>${vulnerability.Target}</td>"
        tableRows += "<td>${vulnerability.VulnerabilityID}</td>"
        tableRows += "<td>${vulnerability.Severity}</td>"
        tableRows += "<td>${vulnerability.Title}</td>"
        tableRows += "<td>${vulnerability.Description}</td>"
        tableRows += "<td>${vulnerability.PkgName}</td>"
        tableRows += "<td>${vulnerability.InstalledVersion}</td>"
        tableRows += "<td>${vulnerability.FixedVersion}</td>"
        tableRows += "</tr>"
    }
    return tableRows
}

def extractTrivyMisconfigurations(reportFile) {
    def jsonReport = readFile(file: reportFile)
    def json = readJSON text: jsonReport
    def misconfigurations = []

    json.Results.each { result ->
        if (result.Misconfigurations) { 
            result.Misconfigurations.each { misconfiguration ->
                def misconf = [
                    Target: result.Target,
                    AVDID: "<a href=\"${misconfiguration.PrimaryURL}\">${misconfiguration.AVDID}</a>",
                    Title: misconfiguration.Title,
                    Description: misconfiguration.Description,
                    Resolution: misconfiguration.Resolution,
                ]
                misconfigurations.add(misconf)
            }
        }
    }
    return misconfigurations
}

def generateTrivyMisconfigurationsHTMLTableRows(trivyMisconfigurations) {
    def tableRows = ""
    trivyMisconfigurations.each { misconfiguration ->
        tableRows += "<tr>"
        tableRows += "<td>${misconfiguration.Target}</td>"
        tableRows += "<td>${misconfiguration.AVDID}</td>"
        tableRows += "<td>${misconfiguration.Title}</td>"
        tableRows += "<td>${misconfiguration.Description}</td>"
        tableRows += "<td>${misconfiguration.Resolution}</td>"
        tableRows += "</tr>"
    }
    return tableRows
}
