@Library('AVAR-Shared-Library') _

pipeline {
    agent {
        label 'linux'
    }

    environment {
        SNYK = tool name: 'Snyk-Installation'
        SNYK_API_TOKEN = credentials('Snyk-API-Token')
        GITHUB_URL = scm.getUserRemoteConfigs()[0].getUrl().replaceAll(/\.git$/, '')
    }

    parameters {
        booleanParam(name: 'OWASP_DEPENDENCY_CHECK', defaultValue: true, description: 'Enable OWASP Dependency Check')
        booleanParam(name: 'SNYK', defaultValue: true, description: 'Enable Snyk Scan')
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
                    def trivyReport = "${WORKSPACE}/trivy-report.json"
                    def trivyVulnerabilities = extractTrivyVulnerabilities(trivyReport)
                    def trivyMisconfigurations = extractTrivyMisconfigurations(trivyReport)
                    def trivySecrets = extractTrivySecrets(trivyReport)
                    def trivyLicenses = extractTrivyLicenses(trivyReport)

                    def trivyVulnerabilitiesTableRows = generateTrivyVulnerabilitiesHTMLTableRows(trivyVulnerabilities)
                    def trivyMisconfigurationsTableRows = generateTrivyMisconfigurationsHTMLTableRows(trivyMisconfigurations)
                    def trivySecretsTableRows = generateTrivySecretsHTMLTableRows(trivySecrets)
                    def trivyLicensesTableRows = generateTrivyLicensesHTMLTableRows(trivyLicenses)

                    env.TRIVY_VULNERABILITIES_TABLE = trivyVulnerabilitiesTableRows
                    env.TRIVY_MISCONFIGURATIONS_TABLE = trivyMisconfigurationsTableRows
                    env.TRIVY_SECRETS_TABLE = trivySecretsTableRows
                    env.TRIVY_LICENSES_TABLE = trivyLicensesTableRows
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
                                    <p class="status" style="font-size: 24px; font-weight: bold; color: ${getStatusColor(currentBuild.currentResult)};">
                                        Build Status: ${currentBuild.currentResult}
                                    </p>
                                    
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
                                        ${getGitChangeSetTable(GITHUB_URL)}
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
                                    <h3>Secrets</h3>
                                    <table>
                                        <tr>
                                            <th>Target</th>
                                            <th>Rule ID</th>
                                            <th>Severity</th>
                                            <th>Title</th>
                                            <th>Line</th>
                                            <th>Match</th>
                                        </tr>
                                        ${env.TRIVY_SECRETS_TABLE ?: "<tr><td colspan=\"6\">No secrets found</td></tr>"}
                                    </table>
                                    <h3>Licenses</h3>
                                    <table>
                                        <tr>
                                            <th>Package Name</th>
                                            <th>Severity</th>
                                            <th>Name</th>
                                            <th>Confidence</th>
                                        </tr>
                                        ${env.TRIVY_LICENSES_TABLE ?: "<tr><td colspan=\"4\">No licenses found</td></tr>"}
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
                cleanWs()
            }
        }
    }
}

